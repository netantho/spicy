// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/type.h>

namespace hilti::type {

/** AST node for a `void` type. */
class Void : public UnqualifiedType {
public:
    std::string_view typeClass() const final { return "void"; }

    bool isAllocable() const final { return false; }
    bool isSortable() const final { return true; }

    static auto create(ASTContext* ctx, Meta meta = {}) { return NodeDerivedPtr<Void>(new Void(ctx, std::move(meta))); }

protected:
    Void(ASTContext* ctx, Meta meta) : UnqualifiedType(ctx, {"void"}, std::move(meta)) {}

    HILTI_NODE(hilti, Void)
};

} // namespace hilti::type
