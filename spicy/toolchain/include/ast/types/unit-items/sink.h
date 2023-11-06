// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/attribute.h>
#include <hilti/ast/type.h>

#include <spicy/ast/types/sink.h>
#include <spicy/ast/types/unit-item.h>

namespace spicy::type::unit::item {

/**
 * AST node for a unit sink.
 */
class Sink : public unit::Item {
public:
    const auto& id() const { return _id; }
    auto attributes() const { return child<AttributeSet>(0); }

    QualifiedTypePtr itemType() const final { return child<QualifiedType>(1); }

    bool isResolved() const final { return itemType()->isResolved(); }

    node::Properties properties() const final {
        auto p = node::Properties{{"id", _id}};
        return unit::Item::properties() + p;
    }

    static auto create(ASTContext* ctx, ID id, AttributeSetPtr attrs, const Meta& meta = {}) {
        if ( ! attrs )
            attrs = AttributeSet::create(ctx);

        return NodeDerivedPtr<Sink>(new Sink(ctx, {attrs, type::Sink::create(ctx)}, std::move(id), meta));
    }

protected:
    Sink(ASTContext* ctx, Nodes children, ID id, const Meta& meta)
        : unit::Item(ctx, std::move(children), meta), _id(std::move(id)) {}

    HILTI_NODE(spicy, Sink)

private:
    ID _id;
};

} // namespace spicy::type::unit::item
