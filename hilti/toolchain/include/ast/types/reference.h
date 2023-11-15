// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/forward.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/null.h>
#include <hilti/ast/types/unknown.h>

namespace hilti::type {

/** AST node for a `strong_ref<T>` type. */
class StrongReference : public UnqualifiedType {
public:
    std::string_view typeClass() const final { return "strong_ref"; }

    QualifiedTypePtr dereferencedType() const final { return child(0)->as<QualifiedType>(); }

    bool isAllocable() const final { return true; }
    bool isReferenceType() const final { return true; }
    bool isResolved() const final { return dereferencedType()->isResolved(); }

    static auto create(ASTContext* ctx, const QualifiedTypePtr& type, Meta meta = {}) {
        return NodeDerivedPtr<StrongReference>(new StrongReference(ctx, {type}, std::move(meta)));
    }

    static auto create(ASTContext* ctx, Wildcard _, const Meta& m = Meta()) {
        return NodeDerivedPtr<StrongReference>(
            new StrongReference(ctx, Wildcard(), {QualifiedType::create(ctx, type::Null::create(ctx, m), true)}, m));
    }

protected:
    StrongReference(ASTContext* ctx, Nodes children, Meta meta)
        : UnqualifiedType(ctx, {}, std::move(children), std::move(meta)) {}
    StrongReference(ASTContext* ctx, Wildcard _, Nodes children, Meta meta)
        : UnqualifiedType(ctx, Wildcard(), {"strong_ref(*)"}, std::move(children), std::move(meta)) {}

    HILTI_NODE(hilti, StrongReference)
};

/** AST node for a `weak_ref<T>` type. */
class WeakReference : public UnqualifiedType {
public:
    std::string_view typeClass() const final { return "weak_ref"; }

    QualifiedTypePtr dereferencedType() const final { return child(0)->as<QualifiedType>(); }

    bool isAllocable() const final { return true; }
    bool isReferenceType() const final { return true; }

    static auto create(ASTContext* ctx, const QualifiedTypePtr& type, Meta meta = {}) {
        return NodeDerivedPtr<WeakReference>(new WeakReference(ctx, {type}, std::move(meta)));
    }

    static auto create(ASTContext* ctx, Wildcard _, const Meta& m = Meta()) {
        return NodeDerivedPtr<WeakReference>(
            new WeakReference(ctx, Wildcard(), {QualifiedType::create(ctx, type::Null::create(ctx, m), true)}, m));
    }

protected:
    WeakReference(ASTContext* ctx, Nodes children, Meta meta)
        : UnqualifiedType(ctx, {}, std::move(children), std::move(meta)) {}
    WeakReference(ASTContext* ctx, Wildcard _, Nodes children, Meta meta)
        : UnqualifiedType(ctx, Wildcard(), {"weak_ref(*)"}, std::move(children), std::move(meta)) {}

    bool isResolved() const final { return dereferencedType()->isResolved(); }

    HILTI_NODE(hilti, WeakReference)
};

/** AST node for a `value_ref<T>` type. */
class ValueReference : public UnqualifiedType {
public:
    std::string_view typeClass() const final { return "value_ref"; }

    QualifiedTypePtr dereferencedType() const final { return child(0)->as<QualifiedType>(); }

    bool isAllocable() const final { return true; }
    bool isReferenceType() const final { return true; }

    static auto create(ASTContext* ctx, const QualifiedTypePtr& type, Meta meta = {}) {
        return NodeDerivedPtr<ValueReference>(new ValueReference(ctx, {type}, std::move(meta)));
    }

    static auto create(ASTContext* ctx, Wildcard _, const Meta& m = Meta()) {
        return NodeDerivedPtr<ValueReference>(
            new ValueReference(ctx, Wildcard(), {QualifiedType::create(ctx, type::Null::create(ctx, m), true)}, m));
    }

protected:
    ValueReference(ASTContext* ctx, Nodes children, Meta meta)
        : UnqualifiedType(ctx, {}, std::move(children), std::move(meta)) {}
    ValueReference(ASTContext* ctx, Wildcard _, Nodes children, Meta meta)
        : UnqualifiedType(ctx, Wildcard(), {"value_ref(*)"}, std::move(children), std::move(meta)) {}

    bool isResolved() const final { return dereferencedType()->isResolved(); }

    HILTI_NODE(hilti, ValueReference)
};

} // namespace hilti::type
