// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/type.h>

namespace hilti::type {

/** AST node for a `real` type. */
class Real : public UnqualifiedType {
public:
    std::string_view typeClass() const final { return "real"; }

    bool isAllocable() const final { return true; }
    bool isSortable() const final { return true; }

    static auto create(ASTContext* ctx, Meta meta = {}) { return NodeDerivedPtr<Real>(new Real(ctx, std::move(meta))); }

protected:
    Real(ASTContext* ctx, Meta meta) : UnqualifiedType(ctx, {"real"}, std::move(meta)) {}

    HILTI_NODE(Real)
};

} // namespace hilti::type
