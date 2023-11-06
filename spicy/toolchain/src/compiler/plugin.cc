// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <spicy/ast/builder/builder.h>
#include <spicy/autogen/config.h>
#include <spicy/compiler/detail/codegen/codegen.h>
#include <spicy/compiler/detail/coercer.h>
#include <spicy/compiler/detail/parser/driver.h>
#include <spicy/compiler/detail/printer.h>
#include <spicy/compiler/detail/resolver.h>
#include <spicy/compiler/detail/scope-builder.h>
#include <spicy/compiler/detail/validator.h>
#include <spicy/compiler/plugin.h>

using namespace spicy;
using namespace spicy::detail;

hilti::Plugin spicy::detail::create_spicy_plugin() {
    return hilti::Plugin{
        .component = "Spicy",
        .order = 5, // before HILTI
        .extension = ".spicy",
        .cxx_includes = {"spicy/rt/libspicy.h"},

        .library_paths = [](const hilti::Context* /* ctx */) { return spicy::configuration().spicy_library_paths; },

        .parse =
            [](ASTContext* ctx, std::istream& in, const hilti::rt::filesystem::path& path) {
                Builder builder(ctx);
                return parser::parseSource(&builder, in, path);
            },

        .coerce_ctor =
            [](ASTContext* ctx, const CtorPtr& c, const QualifiedTypePtr& dst, bitmask<hilti::CoercionStyle> style) {
                Builder builder(ctx);
                return coercer::coerceCtor(&builder, c, dst, style);
            },

        .coerce_type =
            [](ASTContext* ctx, const QualifiedTypePtr& t, const QualifiedTypePtr& dst,
               bitmask<hilti::CoercionStyle> style) {
                Builder builder(ctx);
                return coercer::coerceType(&builder, t, dst, style);
            },

        .ast_build_scopes =
            [](ASTContext* ctx, const ASTRootPtr& root) {
                Builder builder(ctx);
                scope_builder::build(&builder, root);
                return false;
            },

        .ast_resolve =
            [](ASTContext* ctx, const ASTRootPtr& root) {
                Builder builder(ctx);
                return resolver::resolve(&builder, root);
            },

        .ast_validate_pre =
            [](ASTContext* ctx, const ASTRootPtr& m) {
                Builder builder(ctx);
                validator::validate_pre(&builder, m);
                return false;
            },

        .ast_validate_post =
            [](ASTContext* ctx, const ASTRootPtr& root) {
                Builder builder(ctx);
                validator::validate_post(&builder, root);
                return false;
            },

        .ast_print = [](const NodePtr& node, hilti::detail::printer::Stream& out) { return printer::print(out, node); },

        .ast_transform = [](ASTContext* ctx, const ASTRootPtr& m) -> bool {
            Builder builder(ctx);
            return CodeGen(&builder).compileAST(m);
        },
    };
}
