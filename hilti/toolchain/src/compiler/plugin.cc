// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/autogen/config.h>
#include <hilti/compiler/context.h>
#include <hilti/compiler/detail/parser/driver.h>
#include <hilti/compiler/detail/resolver.h>
#include <hilti/compiler/detail/scope-builder.h>
#include <hilti/compiler/detail/validator.h>
#include <hilti/compiler/plugin.h>
#include <hilti/global.h>

using namespace hilti;
using namespace hilti::detail;

PluginRegistry::PluginRegistry() = default; // Needed here to allow PluginRegistry to be forward declared.

Result<std::reference_wrapper<const Plugin>> PluginRegistry::pluginForExtension(hilti::rt::filesystem::path ext) const {
    auto p = std::find_if(_plugins.begin(), _plugins.end(), [&](auto& p) { return p.extension == ext; });
    if ( p != _plugins.end() )
        return {*p};

    return result::Error(util::fmt("no plugin registered for extension %s", ext));
}

const Plugin& PluginRegistry::hiltiPlugin() const {
    static const Plugin* hilti_plugin = nullptr;

    if ( ! hilti_plugin ) {
        auto p = std::find_if(_plugins.begin(), _plugins.end(), [&](auto& p) { return p.component == "HILTI"; });
        if ( p == _plugins.end() )
            logger().fatalError("cannot retrieve HILTI plugin");

        hilti_plugin = &*p;
    }

    return *hilti_plugin;
}

PluginRegistry& plugin::registry() {
    static PluginRegistry singleton;
    return singleton;
}

void PluginRegistry::register_(const Plugin& p) {
    _plugins.push_back(p);
    std::sort(_plugins.begin(), _plugins.end(), [](const auto& x, const auto& y) { return x.order < y.order; });
}

// Always-on default plugin with HILTI functionality.
Plugin hilti::detail::create_hilti_plugin() {
    return Plugin{
        .component = "HILTI",
        .order = 10,
        .extension = ".hlt",
        .cxx_includes = {"hilti/rt/libhilti.h"},

        .library_paths = [](hilti::Context* ctx) { return hilti::configuration().hilti_library_paths; },

        .parse = [](Builder* builder, std::istream& in,
                    const hilti::rt::filesystem::path& path) { return parser::parseSource(builder, in, path); },

        .coerce_ctor = [](Builder* builder, const CtorPtr& c, const QualifiedTypePtr& dst,
                          bitmask<CoercionStyle> style) { return coercer::coerceCtor(builder, c, dst, style); },

        .coerce_type = [](Builder* builder, const QualifiedTypePtr& t, const QualifiedTypePtr& dst,
                          bitmask<CoercionStyle> style) { return coercer::coerceType(builder, t, dst, style); },

        .ast_build_scopes =
            [](Builder* ctx, const ASTRootPtr& root) {
                scope_builder::build(ctx, root);
                return false;
            },

        .ast_resolve = [](Builder* ctx, const ASTRootPtr& root) { return resolver::resolve(ctx, root); },

        .ast_validate_pre =
            [](Builder* builder, const ASTRootPtr& m) {
                validator::validate_pre(builder, m);
                return false;
            },

        .ast_validate_post =
            [](Builder* builder, const ASTRootPtr& root) {
                validator::validate_post(builder, root);
                return false;
            },

        .ast_transform = {},
    };
}
