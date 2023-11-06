// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/ast-context.h>
#include <hilti/base/logger.h>
#include <hilti/base/timing.h>
#include <hilti/compiler/plugin.h>

#include <spicy/ast/builder/builder.h>
#include <spicy/ast/forward.h>
#include <spicy/ast/visitor.h>
#include <spicy/compiler/detail/scope-builder.h>

using namespace spicy;

namespace {

struct Visitor : visitor::PostOrder {
    explicit Visitor(Builder* builder, const ASTRootPtr& root) : root(root), builder(builder) {}

    const ASTRootPtr& root;
    Builder* builder;

    void operator()(type::Unit* n) final {
        if ( auto d = n->self() )
            n->scope()->insert(std::move(d));

        for ( auto&& x : n->parameters() )
            n->scope()->insert(std::move(x));
    }

    void operator()(type::unit::item::Field* n) final {
        if ( auto d = n->dd() )
            n->scope()->insert(std::move(d));
    }

    void operator()(declaration::UnitHook* n) final {
        if ( auto d = n->hook()->dd() )
            n->scope()->insert(std::move(d));

        if ( auto u = n->hook()->unitType() ) {
            if ( u->self() )
                n->scope()->insert(u->self());

            for ( auto&& x : u->parameters() )
                n->scope()->insert(std::move(x));
        }
    }

    void operator()(Hook* n) final {
        if ( auto d = n->dd() )
            n->scope()->insert(std::move(d));
        else
            // Force the scope lookup to stop here so that we don't find any
            // higher-level `$$`, which may have a different type.
            n->scope()->insertNotFound(ID("__dd"));

        for ( auto&& x : n->ftype()->parameters() )
            n->scope()->insert(std::move(x));

        if ( auto u = n->unitType() ) {
            if ( u->self() )
                n->scope()->insert(u->self());

            for ( auto&& x : u->parameters() )
                n->scope()->insert(std::move(x));
        }
    }

    void operator()(hilti::Attribute* n) final {
        if ( n->tag() == "&until" || n->tag() == "&until-including" || n->tag() == "&while" ) {
            auto f = n->parent<type::unit::item::Field>();
            if ( ! (f && f->isContainer()) )
                return;

            const auto& pt = f->parseType();
            if ( ! pt->isResolved() )
                return;

            auto dd = hilti::expression::Keyword::createDollarDollarDeclaration(builder->context(),
                                                                                pt->type()->elementType());
            n->scope()->insert(std::move(dd));
        }
    }
};

} // anonymous namespace

void detail::scope_builder::build(Builder* builder, const ASTRootPtr& root) {
    hilti::util::timing::Collector _("spicy/compiler/ast/scope-builder");

    (*hilti::plugin::registry().hiltiPlugin().ast_build_scopes)(builder->context(), root);
    hilti::visitor::visit(Visitor(builder, root), root);
}
