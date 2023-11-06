// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/attribute.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/types/void.h>

#include <spicy/ast/types/unit-item.h>

namespace spicy::type::unit::item {

/**
 * AST node for a unit sink.
 */
class Property : public unit::Item {
public:
    const auto& id() const { return _id; }
    auto expression() const { return child<Expression>(0); }
    auto attributes() const { return child<AttributeSet>(1); }
    auto inherited() const { return _inherited; }

    QualifiedTypePtr itemType() const final { return child<QualifiedType>(2); }

    bool isResolved() const final { return true; }

    node::Properties properties() const final {
        auto p = node::Properties{{"id", _id}, {"inherited", _inherited}};
        return unit::Item::properties() + p;
    }

    static auto create(ASTContext* ctx, ID id, AttributeSetPtr attrs, bool inherited = false, const Meta& meta = {}) {
        if ( ! attrs )
            attrs = AttributeSet::create(ctx);

        return NodeDerivedPtr<Property>(new Property(ctx, node::flatten(nullptr, attrs, hilti::type::Void::create(ctx)),
                                                     std::move(id), false, meta));
    }

    static auto create(ASTContext* ctx, ID id, ExpressionPtr expr, AttributeSetPtr attrs, bool inherited = false,
                       const Meta& meta = {}) {
        if ( ! attrs )
            attrs = AttributeSet::create(ctx);

        return NodeDerivedPtr<Property>(
            new Property(ctx, node::flatten(std::move(expr), attrs, hilti::type::Void::create(ctx)), std::move(id),
                         inherited, meta));
    }

protected:
    Property(ASTContext* ctx, Nodes children, ID id, bool inherited, const Meta& meta)
        : unit::Item(ctx, std::move(children), meta), _id(std::move(id)), _inherited(inherited) {}

    HILTI_NODE(spicy, Property)

private:
    ID _id;
    bool _inherited;
};

} // namespace spicy::type::unit::item
