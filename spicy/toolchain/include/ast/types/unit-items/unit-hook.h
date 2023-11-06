// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/attribute.h>
#include <hilti/ast/type.h>

#include <spicy/ast/hook.h>
#include <spicy/ast/types/unit-item.h>

namespace spicy::type::unit::item {

/**
 * AST node for a unit hook.
 */
class UnitHook : public unit::Item {
public:
    const auto& id() const { return _id; }
    auto hook() const { return child<spicy::Hook>(0); }
    auto location() const { return hook()->location(); }

    QualifiedTypePtr itemType() const final { return hook()->function()->type(); }

    bool isResolved() const final { return itemType()->isResolved(); }

    node::Properties properties() const final {
        auto p = node::Properties{{"id", _id}};
        return unit::Item::properties() + p;
    }

    static auto create(ASTContext* ctx, ID id, spicy::HookPtr hook, const Meta& meta = {}) {
        auto h = NodeDerivedPtr<UnitHook>(new UnitHook(ctx, {std::move(hook)}, std::move(id), meta));
        h->hook()->setID(id);
        return h;
    }

protected:
    UnitHook(ASTContext* ctx, Nodes children, ID id, const Meta& meta)
        : unit::Item(ctx, std::move(children), meta), _id(std::move(id)) {}

    HILTI_NODE(spicy, UnitHook)

private:
    ID _id;
};

} // namespace spicy::type::unit::item
