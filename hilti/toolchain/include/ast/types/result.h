// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>
#include <vector>

#include <hilti/ast/type.h>
#include <hilti/ast/types/unknown.h>

namespace hilti::type {

/** AST node for an `result<T>` type. */
class Result : public UnqualifiedType {
public:
    std::string_view typeClass() const final { return "result"; }

    QualifiedTypePtr dereferencedType() const final { return child(0)->as<QualifiedType>(); }

    bool isAllocable() const final { return true; }
    bool isResolved() const final { return dereferencedType()->isResolved(); }

    static auto create(ASTContext* ctx, const QualifiedTypePtr& t, Meta m = Meta()) {
        return NodeDerivedPtr<Result>(new Result(ctx, {t}, std::move(m)));
    }

    static auto create(ASTContext* ctx, Wildcard _, const Meta& m = Meta()) {
        return NodeDerivedPtr<Result>(
            new Result(ctx, Wildcard(), {QualifiedType::create(ctx, type::Unknown::create(ctx, m), true)}, m));
    }

protected:
    Result(ASTContext* ctx, Nodes children, Meta meta)
        : UnqualifiedType(ctx, {}, std::move(children), std::move(meta)) {}
    Result(ASTContext* ctx, Wildcard _, Nodes children, Meta meta)
        : UnqualifiedType(ctx, Wildcard(), {"result(*)"}, std::move(children), std::move(meta)) {}


    HILTI_NODE(Result)
};

} // namespace hilti::type
