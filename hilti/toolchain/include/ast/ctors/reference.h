// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/ctor.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/types/auto.h>
#include <hilti/ast/types/reference.h>

namespace hilti::ctor {

/** AST node for a `strong_ref<T>` constructor value (which can only be null). */
class StrongReference : public Ctor {
public:
    QualifiedTypePtr dereferencedType() const {
        return type()->type()->as<type::StrongReference>()->dereferencedType();
    }

    QualifiedTypePtr type() const final { return child<QualifiedType>(0); }

    static auto create(ASTContext* ctx, const QualifiedTypePtr& t, const Meta& meta = {}) {
        return CtorPtr(
            new StrongReference(ctx, {QualifiedType::create(ctx, type::StrongReference::create(ctx, t, meta), true)},
                                meta));
    }

protected:
    StrongReference(ASTContext* ctx, Nodes children, Meta meta) : Ctor(ctx, std::move(children), std::move(meta)) {}

    HILTI_NODE(StrongReference)
};

/** AST node for a `weak_ref<T>` constructor value (which can only be null). */
class WeakReference : public Ctor {
public:
    QualifiedTypePtr dereferencedType() const { return type()->type()->as<type::WeakReference>()->dereferencedType(); }

    QualifiedTypePtr type() const final { return child<QualifiedType>(0); }

    static auto create(ASTContext* ctx, const QualifiedTypePtr& t, const Meta& meta = {}) {
        return CtorPtr(new WeakReference(ctx,
                                         {QualifiedType::create(ctx, type::WeakReference::create(ctx, t, meta), true)},
                                         meta));
    }

protected:
    WeakReference(ASTContext* ctx, Nodes children, Meta meta) : Ctor(ctx, std::move(children), std::move(meta)) {}

    HILTI_NODE(WeakReference)
};

/** AST node for a `value_ref<T>` constructor value. */
class ValueReference : public Ctor {
public:
    ExpressionPtr expression() const { return child<Expression>(0); }
    QualifiedTypePtr dereferencedType() const { return type()->type()->as<type::ValueReference>()->dereferencedType(); }

    QualifiedTypePtr type() const final { return expression()->type(); }

    static auto create(ASTContext* ctx, const ExpressionPtr& expr, const Meta& meta = {}) {
        return NodeDerivedPtr<ValueReference>(new ValueReference(ctx, {expr}, meta));
    }

protected:
    ValueReference(ASTContext* ctx, Nodes children, Meta meta) : Ctor(ctx, std::move(children), std::move(meta)) {}

    HILTI_NODE(ValueReference)
};

} // namespace hilti::ctor
