// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/type.h>

namespace hilti::type {

/** AST node for a error type. */
class Error : public UnqualifiedType {
public:
    static auto create(ASTContext* ctx, Meta meta = {}) {
        return NodeDerivedPtr<Error>(new Error(ctx, std::move(meta)));
    }

    std::string_view typeClass() const final { return "error"; }

    bool isAllocable() const final { return true; }

protected:
    Error(ASTContext* ctx, Meta meta) : UnqualifiedType(ctx, {"error"}, std::move(meta)) {}

    HILTI_NODE(hilti, Error)
};

} // namespace hilti::type
