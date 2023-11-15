// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/type.h>

namespace hilti::type {

/** * AST node for a null type. */
class Null : public UnqualifiedType {
public:
    std::string_view typeClass() const final { return "null"; }

    static auto create(ASTContext* ctx, Meta meta = {}) { return NodeDerivedPtr<Null>(new Null(ctx, std::move(meta))); }

protected:
    Null(ASTContext* ctx, Meta meta) : UnqualifiedType(ctx, {"null"}, std::move(meta)) {}

    HILTI_NODE(hilti, Null)
};

} // namespace hilti::type
