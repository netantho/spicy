// Copyright (c) 2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <map>
#include <memory>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include <hilti/ast/declarations/module.h>
#include <hilti/ast/forward.h>
#include <hilti/ast/node.h>
#include <hilti/base/logger.h>

namespace hilti {

class ASTContext;
class Context;
class Driver;
struct Plugin;

/**
 * Parses a HILTI source file into an AST.
 *
 * @param in stream to read from
 * @param filename path associated with the input
 *
 * Returns: The parsed AST, or a corresponding error if parsing failed.
 */
Result<ModulePtr> parseSource(Builder* builder, std::istream& in, const std::string& filename);

/**
 * Root node for the AST inside an AST context. This will always be present
 * exactly once.
 */
class ASTRoot : public Node {
public:
    ~ASTRoot() override;

    static auto create(ASTContext* ctx) { return NodeDerivedPtr<ASTRoot>(new ASTRoot(ctx)); }

protected:
    ASTRoot(ASTContext* ctx) : Node(ctx, {}, Meta(Location("<root>"))) {}

    std::string _render() const final;

    HILTI_NODE(ASTRoot);
};

/**
 * Environment for AST-wide state. The environment stores the AST root node and
 * owns all nodes added to it or, recursively, any of if children. Each node
 * can be part of just one AST context.
 */
class ASTContext : public std::enable_shared_from_this<ASTContext> {
public:
    /**
     * Constructor.
     *
     * @param context compiler context to use for logging and error reporting
     */
    ASTContext(Context* context);

    /** Returns the AST's root node. This always exists. */
    auto root() const { return _root; }

    /**
     * Parses a source file and adds it to the AST as a new module. If a module
     * for this file is already part of the AST, returns the existing module
     * without any further AST changes.
     *
     * @param path path to source file to parse
     * @param process_extension if given, file extension indicating which
     * plugin to use later for processing the resulting AST for the module; if
     * not given, the same plugin will be used as for parsing (which is
     * determined by the path's extension)
     * @return UID of the parsed module (which is now a part of the AST), or an
     * error if parsing failed
     */
    Result<module::UID> parseSource(const hilti::rt::filesystem::path& path,
                                    std::optional<hilti::rt::filesystem::path> process_extension = {});

    /**
     * Imports a module from an external source file and adds it to the AST as
     * a new module. This implements HILTI's `import` statement. If a module
     * for the requested `import` is already part of the AST, returns the
     * existing module without any further AST changes.
     *
     * @param id name of the module to import (as in: ``import <id>``)
     * @param scope search scope for the import (as in: ``import ... from <scope>``)
     * @param parse_extension file extension indicating which plugin to use for
     * parsing the module's source code
     * @param process_extension if given, file extension indicating which
     * plugin to use later for processing the resulting AST; if not given, the
     * same plugin will be used as for parsing
     * @param search_dirs list of directories to search for the module's source
     * (in addition to any globally configured search directories)
     * @return UID of the parsed module (which is now a part of the AST), or an
     * error if parsing failed
     */
    Result<module::UID> importModule(const ID& id, const std::optional<ID>& scope,
                                     const hilti::rt::filesystem::path& parse_extension,
                                     const std::optional<hilti::rt::filesystem::path>& process_extension,
                                     std::vector<hilti::rt::filesystem::path> search_dirs);

    /**
     * Retrieves a module node from the AST given its UID. Returns null if no
     * such module exists.
     *
     * @param uid UID of module to return
     */
    ModulePtr getModule(const module::UID& uid) const {
        if ( auto m = _modules_by_uid.find(uid); m != _modules_by_uid.end() )
            return m->second;
        else
            return nullptr;
    }

    /**
     * Processes the whole AST with all of the compiler's visitor passes. This
     * is the top-level entry point for all resolving/validating/optimizing. If
     * successful, the will be fully resolved and validated; and ready for code
     * generation.
     *
     * @param driver current compiler driver, which AST processing may access
     */
    Result<Nothing> processAST(Driver* driver);

    /**
     * During AST processing, returns the current compiler driver. If called
     * outside of `processAST() executing, it will return null.
     */
    Driver* driver() const { return _driver; }

    /**
     * Returns direct & indirect dependencies that a module imports. This
     * information will be available only once the AST has been processed
     * successfully through `processAST()`.
     *
     * @param uid UID of module to return dependencies for; the module must be
     * known, otherwise an internal error is reported
     * @param recursive if true, return the transitive closure of all
     * dependent units, vs just direct dependencies of the specified unit
     * @return set of dependencies
     */
    std::vector<module::UID> dependencies(const module::UID& uid, bool recursive = false) const;

    /**
     * Dumps the current total AST of all modules to a debug stream.
     *
     * @param stream debug stream to write to
     * @param prefix prefix line to start output with
     */
    void dumpAST(const hilti::logging::DebugStream& stream, const std::string& prefix);

private:
    // The following methods implement the corresponding phases of AST processing.

    Result<module::UID> _parseSource(const hilti::rt::filesystem::path& path, const std::optional<ID>& scope,
                                     std::optional<hilti::rt::filesystem::path> process_extension = {});
    Result<Nothing> _buildScopes(const Plugin& plugin);
    Result<Nothing> _resolve(const Plugin& plugin);
    Result<Nothing> _validate(const Plugin& plugin, bool pre_resolver);
    Result<Nothing> _transform(const Plugin& plugin);
    Result<Nothing> _collectErrors();
    Result<Nothing> _optimize();

    // Adds a module to the AST. The module must not be part of any AST yet
    // (including the current one).
    module::UID _addModuleToAST(ModulePtr module);

    // Performs internal consistency checks on the AST.
    void _checkAST() const;

    // Dumps the AST to disk during AST processing, for debugging..
    void _saveIterationAST(const Plugin& plugin, const std::string& prefix, int round = 0);

    // Dumps the AST to disk during AST processing, for debugging..
    void _saveIterationAST(const Plugin& plugin, const std::string& prefix, const std::string& tag);

    // Dumps the AST to a debugging stream.
    void _dumpAST(const hilti::logging::DebugStream& stream, const Plugin& plugin, const std::string& prefix,
                  int round);

    // Dumps the AST to a debugging stream.
    void _dumpAST(std::ostream& stream, const Plugin& plugin, const std::string& prefix, int round);

    // Dumps all declarations nodes to the `declarations' debug stream.
    void _dumpDeclarations(const Plugin& plugin);

    Context* _context;             // compier context.
    NodeDerivedPtr<ASTRoot> _root; // root node of the AST.
    bool _rebuild_scopes = true;   // true if next iteration round needs to rebuild all AST scopes
    bool _resolved = false;        // true if `processAST()` has finished successfully
    Driver* _driver = nullptr;     // pointer to compiler drive during `processAST()`, null outside of that

    std::unordered_map<module::UID, ModulePtr> _modules_by_uid;  // all known modules indexed by UID
    std::unordered_map<std::string, ModulePtr> _modules_by_path; // all known modules indexed by path
    std::map<std::pair<ID, ID>, ModulePtr>
        _modules_by_id_and_scope; // all known modules indexed by their ID and search scope
};

} // namespace hilti
