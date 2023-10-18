// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/expression.h>
#include <hilti/ast/type.h>

namespace hilti::expression {

/** AST node for a `typeinfo` expression. */
class TypeInfo : public Expression {
public:
    auto expression() const { return child<Expression>(0); }

    QualifiedTypePtr type() const final { return expression()->type(); }

    static auto create(ASTContext* ctx, const ExpressionPtr& expr, const Meta& meta = {}) {
        return NodeDerivedPtr<TypeInfo>(new TypeInfo(ctx, {expr}, meta));
    }

protected:
    TypeInfo(ASTContext* ctx, Nodes children, Meta meta) : Expression(ctx, std::move(children), std::move(meta)) {}

    HILTI_NODE(TypeInfo)
};

} // namespace hilti::expression
