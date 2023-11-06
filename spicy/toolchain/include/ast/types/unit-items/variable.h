// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/attribute.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/type.h>

#include <spicy/ast/types/unit-item.h>

namespace spicy::type::unit::item {

/**
 * AST node for a unit variable.
 *
 * @note We don't support hooks for variables because we can't reliably
 * identify assignments in the generated code. To do that, we'd need to trap
 * struct field assignments at the C++ level.
 */
class Variable : public unit::Item {
public:
    const auto& id() const { return _id; }
    auto default_() const { return child<AttributeSet>(1); }
    auto attributes() const { return child<AttributeSet>(2); }

    bool isOptional() const { return attributes()->has("&optional"); }

    QualifiedTypePtr itemType() const final { return child<QualifiedType>(0); }

    bool isResolved() const final { return itemType()->isResolved(); }

    node::Properties properties() const final {
        auto p = node::Properties{{"id", _id}};
        return unit::Item::properties() + p;
    }

    static auto create(ASTContext* ctx, ID id, QualifiedTypePtr type, ExpressionPtr default_, AttributeSetPtr attrs,
                       const Meta& meta = {}) {
        if ( ! attrs )
            attrs = AttributeSet::create(ctx);

        return NodeDerivedPtr<Variable>(
            new Variable(ctx, {std::move(type), std::move(default_), attrs}, std::move(id), meta));
    }

protected:
    Variable(ASTContext* ctx, Nodes children, ID id, const Meta& meta)
        : unit::Item(ctx, std::move(children), meta), _id(std::move(id)) {}

    HILTI_NODE(spicy, Variable)

private:
    ID _id;
};

} // namespace spicy::type::unit::item
