// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <utility>

#include <hilti/ast/ast-context.h>
#include <hilti/ast/builder/builder.h>
#include <hilti/ast/declarations/module.h>
#include <hilti/ast/type.h>
#include <hilti/ast/visitor.h>
#include <hilti/base/timing.h>
#include <hilti/compiler/detail/id-assigner.h>
#include <hilti/compiler/detail/optimizer.h>
#include <hilti/compiler/detail/renderer.h>
#include <hilti/compiler/detail/resolver.h>
#include <hilti/compiler/detail/scope-builder.h>
#include <hilti/compiler/detail/type-unifier.h>
#include <hilti/compiler/driver.h>
#include <hilti/compiler/plugin.h>

using namespace hilti;
using namespace hilti::detail;
using namespace hilti::util;

namespace hilti::logging::debug {
inline const DebugStream AstCache("ast-cache");
inline const DebugStream AstCodegen("ast-codegen");
inline const DebugStream AstDeclarations("ast-declarations");
inline const DebugStream AstDumpIterations("ast-dump-iterations");
inline const DebugStream AstFinal("ast-final");
inline const DebugStream AstOrig("ast-orig");
inline const DebugStream AstPrintTransformed("ast-print-transformed");
inline const DebugStream AstResolved("ast-resolved");
inline const DebugStream AstTransformed("ast-transformed");
inline const DebugStream Compiler("compiler");
} // namespace hilti::logging::debug

ASTRoot::~ASTRoot() = default;

std::string ASTRoot::_render() const { return ""; }

ASTContext::ASTContext(Context* context) : _context(context) {
    _root = ASTRoot::create(this);
    _root->getOrCreateScope(); // create the global scope
}

Result<module::UID> ASTContext::parseSource(const hilti::rt::filesystem::path& path,
                                            std::optional<hilti::rt::filesystem::path> process_extension) {
    return _parseSource(path, {}, std::move(process_extension));
}

Result<module::UID> ASTContext::importModule(const ID& id, const std::optional<ID>& scope,
                                             const hilti::rt::filesystem::path& parse_extension,
                                             const std::optional<hilti::rt::filesystem::path>& process_extension,
                                             std::vector<hilti::rt::filesystem::path> search_dirs) {
    auto parse_plugin = plugin::registry().pluginForExtension(parse_extension);

    if ( ! (parse_plugin && parse_plugin->get().parse) )
        return result::Error(fmt("no plugin provides support for importing *%s files", parse_extension.native()));

    auto filename = fmt("%s%s", util::tolower(id), parse_extension.native());

    if ( scope )
        filename = fmt("%s/%s", util::replace(scope->str(), ".", "/"), filename);

    std::vector<hilti::rt::filesystem::path> library_paths = std::move(search_dirs);

    if ( parse_plugin->get().library_paths )
        library_paths = util::concat(std::move(library_paths), (*parse_plugin->get().library_paths)(_context));

    library_paths = util::concat(_context->options().library_paths, library_paths);

    auto path = util::findInPaths(filename, library_paths);
    if ( ! path ) {
        HILTI_DEBUG(logging::debug::Compiler, fmt("Failed to find module '%s' in search paths:", filename));
        for ( const auto& p : library_paths )
            HILTI_DEBUG(logging::debug::Compiler, fmt("  %s", p));

        return result::Error(fmt("cannot find file"));
    }

    if ( auto m = _modules_by_path.find(util::normalizePath(*path).native()); m != _modules_by_path.end() )
        return m->second->uid();

    auto uid = _parseSource(*path, scope, process_extension);
    if ( ! uid )
        return uid;

    if ( uid->id != id )
        return result::Error(
            util::fmt("file %s does not contain expected module %s (but %s)", path->native(), id, uid->id));

    return uid;
}

Result<module::UID> ASTContext::_parseSource(const hilti::rt::filesystem::path& path, const std::optional<ID>& scope,
                                             std::optional<hilti::rt::filesystem::path> process_extension) {
    util::timing::Collector _("hilti/compiler/parser");

    std::ifstream in;
    in.open(path);

    if ( ! in )
        return result::Error(fmt("cannot open source file %s", path));

    auto plugin = plugin::registry().pluginForExtension(path.extension());

    if ( ! (plugin && plugin->get().parse) )
        return result::Error(fmt("no plugin provides support for importing *%s files", path.extension().native()));

    auto dbg_message = fmt("parsing file %s as %s code", path, plugin->get().component);

    if ( plugin->get().component != "HILTI" )
        dbg_message += fmt(" (%s)", plugin->get().component);

    HILTI_DEBUG(logging::debug::Compiler, dbg_message);

    auto builder = Builder(this);
    auto module = (*plugin->get().parse)(&builder, in, path);
    if ( ! module )
        return module.error();

    if ( module && ! (*module)->id() )
        return result::Error(fmt("module in %s does not have an ID", path.native()));

    if ( scope )
        (*module)->setScopePath(*scope);

    if ( process_extension )
        (*module)->setProcessExtension(*process_extension);

    return _addModuleToAST(std::move(*module));
}

module::UID ASTContext::_addModuleToAST(ModulePtr module) {
    assert(_modules_by_uid.find(module->uid()) == _modules_by_uid.end());
    assert(! module->hasParent()); // don't want to end up copying the whole AST
    auto uid = module->uid();

    _modules_by_uid[uid] = module;
    _modules_by_path[uid.path.native()] = module;
    _modules_by_id_and_scope[std::make_pair(uid.id, module->scopePath())] = module;

    _root->addChild(this, std::move(module));
    return uid;
}

template<typename PluginMember, typename... Args>
Result<Nothing> _runHook(bool* modified, const Plugin& plugin, PluginMember hook, const std::string& description,
                         const Args&... args) {
    if ( ! (plugin.*hook) )
        return Nothing();

    auto msg = fmt("[%s] %s", plugin.component, description);

    HILTI_DEBUG(logging::debug::Compiler, msg);
    if ( (*(plugin.*hook))(args...) ) {
        *modified = true;
        HILTI_DEBUG(logging::debug::Compiler, "  -> modified");
    }

    if ( logger().errors() )
        return result::Error("aborting due to errors during " + description);

    return Nothing();
}

Result<Nothing> ASTContext::processAST(Driver* driver) {
    if ( _resolved )
        return Nothing();

    // Automatically import the `hilti` library module.
    // TODO: Do we want to hide its content from user code unless imported
    // explicitly? That used to be the old semantics, but not clear its worth
    // retaining.
    importModule("hilti", {}, ".hlt", {}, {});

    _driver = driver;
    _rebuild_scopes = true;

    auto builder = Builder(this);

    for ( const auto& plugin : plugin::registry().plugins() ) {
        if ( auto rc = _validate(plugin, true); ! rc )
            return rc;

        type_unifier::unify(&builder, root());

        if ( auto rc = _resolve(plugin); ! rc )
            return rc;

        if ( auto rc = _validate(plugin, false); ! rc )
            return rc;

        if ( auto rc = driver->hookCompilationFinished(plugin); ! rc )
            return rc;

        if ( auto rc = _transform(plugin); ! rc )
            return rc;
    }

    if ( _context->options().global_optimizations ) {
        if ( auto rc = _optimize(); ! rc )
            return rc;

        if ( auto rc = _validate(plugin::registry().hiltiPlugin(), false); ! rc )
            return rc;
    }

    _driver = nullptr;
    return Nothing();
}

void ASTContext::_checkAST() const {
    // Check parent pointering.
    for ( const auto& n : visitor::PreOrder().walk(_root) ) {
        for ( const auto& c : n->children() ) {
            if ( c && c->parent() != n.get() )
                logger().internalError("broken parent pointer!");
        }
    }

    // Detect cycles, we shouldn't have them.
    std::set<Node*> seen = {};
    for ( const auto& n : visitor::PreOrder().walk(_root) ) {
        if ( seen.find(n.get()) != seen.end() )
            logger().internalError("cycle in AST detected");

        seen.insert(n.get());
    }
}

Result<Nothing> ASTContext::_resolve(const Plugin& plugin) {
    HILTI_DEBUG(logging::debug::Compiler, fmt("resolving units with plugin %s", plugin.component))

    logging::DebugPushIndent _(logging::debug::Compiler);

    _dumpAST(logging::debug::AstOrig, plugin, "Original AST", 0);
    _saveIterationAST(plugin, "AST before first iteration", 0);

    int round = 1;
    bool modified = true;

    auto builder = Builder(this);

    while ( modified ) {
        HILTI_DEBUG(logging::debug::Compiler, fmt("processing ASTs, round %d", round));
        logging::DebugPushIndent _(logging::debug::Compiler);

#ifndef NDEBUG
        _checkAST();
#endif

        operator_::registry().initPending(this);

        for ( const auto& i : hilti::visitor::PreOrder().walk(_root) ) {
            assert(i); // walk() should not give us null pointer children.
            i->clearErrors();
        }

        if ( _rebuild_scopes ) {
            HILTI_DEBUG(logging::debug::Compiler, "building scopes");

            for ( const auto& i : hilti::visitor::PreOrder().walk(_root) )
                i->clearScope();

            if ( auto rc = _runHook(&modified, plugin, &Plugin::ast_build_scopes, "building scopes", &builder, _root);
                 ! rc )
                return rc.error();
        }

        modified = false;

        HILTI_DEBUG(logging::debug::Compiler, "computing canonical IDs");
        if ( id_assigner::assign(&builder, _root) ) {
            HILTI_DEBUG(logging::debug::Compiler, "  -> modified");
            modified = true;
        }

        if ( auto rc = _runHook(&modified, plugin, &Plugin::ast_resolve, "resolving", &builder, _root); ! rc )
            return rc.error();

        HILTI_DEBUG(logging::debug::Compiler, "unifying types");
        if ( type_unifier::unify(&builder, root()) ) {
            HILTI_DEBUG(logging::debug::Compiler, "  -> modified");
            modified = true;
        }

        _dumpAST(logging::debug::AstResolved, plugin, "AST after resolving", round);
        _saveIterationAST(plugin, "AST after resolving", round);

        if ( ++round >= 50 )
            logger().internalError("hilti::Unit::compile() didn't terminate, AST keeps changing");
    }

    _dumpAST(logging::debug::AstFinal, plugin, "Final AST", round);
    _dumpDeclarations(plugin);
    _saveIterationAST(plugin, "Final AST", round);

    // All declarations should have canonical IDs at this point. This will
    // abort if not.
    id_assigner::debugEnforceCanonicalIDs(&builder, _root);

    // At this point, all built-in operators should be fully resolved. If not,
    // there's an internal problem somewhere. This will abort then.
    operator_::registry().debugEnforceBuiltInsAreResolved();

    HILTI_DEBUG(logging::debug::Compiler, "finalized AST");
    _resolved = true;

    return Nothing();
}

Result<Nothing> ASTContext::_transform(const Plugin& plugin) {
    if ( ! plugin.ast_transform )
        return Nothing();

    HILTI_DEBUG(logging::debug::Compiler, "transforming AST");

    auto builder = Builder(this);
    bool modified = false;
    if ( auto rc = _runHook(&modified, plugin, &Plugin::ast_transform, "transforming", &builder, _root); ! rc )
        return rc;

    _dumpAST(logging::debug::AstTransformed, plugin, "AST after transforming", 0);
    _saveIterationAST(plugin, "AST after transforming");

    return Nothing();
}

Result<Nothing> ASTContext::_optimize() {
    HILTI_DEBUG(logging::debug::Compiler, "performing global transformations");

    auto builder = Builder(this);
    optimizer::optimize(&builder, _root);

    return Nothing();
}

Result<Nothing> ASTContext::_validate(const Plugin& plugin, bool pre_resolve) {
    if ( _context->options().skip_validation )
        return Nothing();

    auto builder = Builder(this);
    bool modified = false; // not used

    if ( pre_resolve )
        _runHook(&modified, plugin, &Plugin::ast_validate_pre, "validating (pre)", &builder, _root);
    else
        _runHook(&modified, plugin, &Plugin::ast_validate_post, "validating (post)", &builder, _root);

    return _collectErrors();
}

void ASTContext::_dumpAST(const logging::DebugStream& stream, const Plugin& plugin, const std::string& prefix,
                          int round) {
    if ( ! logger().isEnabled(stream) )
        return;

    std::string r;

    if ( round > 0 )
        r = fmt(" (round %d)", round);

    HILTI_DEBUG(stream, fmt("# [%s] %s%s", plugin.component, prefix, r));
    renderer::render(stream, root(), true);
}

void ASTContext::_dumpAST(std::ostream& stream, const Plugin& plugin, const std::string& prefix, int round) {
    std::string r;

    if ( round > 0 )
        r = fmt(" (round %d)", round);

    stream << fmt("# [%s] %s%s\n", plugin.component, prefix, r);
    renderer::render(stream, root(), true);
}

void ASTContext::dumpAST(const logging::DebugStream& stream, const std::string& prefix) {
    if ( ! logger().isEnabled(stream) )
        return;

    HILTI_DEBUG(stream, fmt("# %s\n", prefix));
    renderer::render(stream, root(), true);
}

void ASTContext::_dumpDeclarations(const Plugin& plugin) {
    if ( ! logger().isEnabled(logging::debug::AstDeclarations) )
        return;

    logger().debugSetIndent(logging::debug::AstDeclarations, 0);
    HILTI_DEBUG(logging::debug::AstDeclarations, fmt("# [%s]", plugin.component));

    auto nodes = visitor::RangePreOrder(root());
    for ( auto i = nodes.begin(); i != nodes.end(); ++i ) {
        auto decl = (*i)->tryAs<Declaration>();
        if ( ! decl )
            continue;

        logger().debugSetIndent(logging::debug::AstDeclarations, i.depth() - 1);
        HILTI_DEBUG(logging::debug::AstDeclarations,
                    fmt("- %s \"%s\" (%s)", ID((*i)->typename_()).local(), decl->id(), decl->canonicalID()));
    }
}

void ASTContext::_saveIterationAST(const Plugin& plugin, const std::string& prefix, int round) {
    if ( ! logger().isEnabled(logging::debug::AstDumpIterations) )
        return;

    std::ofstream out(fmt("ast-%s-%d.tmp", plugin.component, round));
    _dumpAST(out, plugin, prefix, round);
}

void ASTContext::_saveIterationAST(const Plugin& plugin, const std::string& prefix, const std::string& tag) {
    if ( ! logger().isEnabled(logging::debug::AstDumpIterations) )
        return;

    std::ofstream out(fmt("ast-%s-%s.tmp", plugin.component, tag));
    _dumpAST(out, plugin, prefix, 0);
}

static void _recursiveDependencies(const ASTContext* ctx, const ModulePtr& module, std::vector<module::UID>* seen) {
    if ( std::find(seen->begin(), seen->end(), module->uid()) != seen->end() )
        return;

    for ( const auto& uid : module->dependencies() ) {
        seen->push_back(uid);
        auto dep = ctx->getModule(uid);
        assert(dep);
        _recursiveDependencies(ctx, dep, seen);
    }
}

std::vector<module::UID> ASTContext::dependencies(const module::UID& uid, bool recursive) const {
    auto module = getModule(uid);
    assert(module);

    if ( recursive ) {
        std::vector<module::UID> seen;
        _recursiveDependencies(this, module, &seen);
        return seen;
    }
    else
        return module->dependencies();
}

static node::ErrorPriority _recursiveValidateAST(const NodePtr& n, Location closest_location, node::ErrorPriority prio,
                                                 int level, std::vector<node::Error>* errors) {
    if ( n->location() )
        closest_location = n->location();

    auto oprio = prio;
    for ( const auto& c : n->children() ) {
        if ( c )
            prio = std::max(prio, _recursiveValidateAST(c, closest_location, oprio, level + 1, errors));
    }

    auto errs = n->errors();
    auto nprio = prio;
    for ( auto& err : errs ) {
        if ( ! err.location && closest_location )
            err.location = closest_location;

        if ( err.priority > prio )
            errors->push_back(err);

        nprio = std::max(nprio, err.priority);
    }

    return nprio;
}

static void _reportErrors(const std::vector<node::Error>& errors) {
    // We only report the highest priority error category.
    std::set<node::Error> reported;

    auto prios = {node::ErrorPriority::High, node::ErrorPriority::Normal, node::ErrorPriority::Low};

    for ( auto p : prios ) {
        for ( const auto& e : errors ) {
            if ( e.priority != p )
                continue;

            if ( reported.find(e) == reported.end() ) {
                logger().error(e.message, e.context, e.location);
                reported.insert(e);
            }
        }

        if ( reported.size() )
            break;
    }
}

Result<Nothing> ASTContext::_collectErrors() {
    std::vector<node::Error> errors;
    _recursiveValidateAST(_root, Location(), node::ErrorPriority::NoError, 0, &errors);

    if ( errors.size() ) {
        _reportErrors(errors);
        return result::Error("validation failed");
    }

    return Nothing();
}
