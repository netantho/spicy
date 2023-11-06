// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>
#include <vector>

#include <hilti/ast/node.h>

#include <spicy/ast/forward.h>

namespace spicy::type::unit {

/** Base class for all unit items. */
class Item : public Node {
public:
    ~Item() override;

    /** Returns the type of the parsed unit item. */
    virtual QualifiedTypePtr itemType() const = 0;

    /** Returns true if the item's type has been resolved. */
    virtual bool isResolved() const = 0;

protected:
    Item(ASTContext* ctx, Nodes children, Meta meta) : Node::Node(ctx, std::move(children), std::move(meta)) {}

    HILTI_NODE_BASE(hilti, Item);
};


} // namespace spicy::type::unit
