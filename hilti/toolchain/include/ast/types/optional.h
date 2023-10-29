// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>
#include <vector>

#include <hilti/ast/type.h>
#include <hilti/ast/types/unknown.h>

namespace hilti::type {

/** AST node for an `optional<T>` type. */
class Optional : public UnqualifiedType {
public:
    QualifiedTypePtr dereferencedType() const final { return child(0)->as<QualifiedType>(); }

    std::string_view typeClass() const final { return "optional"; }

    bool isAllocable() const final { return true; }
    bool isResolved() const final { return dereferencedType()->isResolved(); }

    static auto create(ASTContext* ctx, const QualifiedTypePtr& t, Meta m = Meta()) {
        return NodeDerivedPtr<Optional>(new Optional(ctx, {t}, std::move(m)));
    }

    static auto create(ASTContext* ctx, Wildcard _, const Meta& m = Meta()) {
        return NodeDerivedPtr<Optional>(
            new Optional(ctx, Wildcard(), {QualifiedType::create(ctx, type::Unknown::create(ctx, m), true)}, m));
    }

protected:
    Optional(ASTContext* ctx, Nodes children, Meta meta)
        : UnqualifiedType(ctx, {}, std::move(children), std::move(meta)) {}
    Optional(ASTContext* ctx, Wildcard _, Nodes children, Meta meta)
        : UnqualifiedType(ctx, Wildcard(), {"optional(*)"}, std::move(children), std::move(meta)) {}


    HILTI_NODE(Optional)
};


} // namespace hilti::type
