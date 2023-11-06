// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>
#include <utility>

#include <hilti/ast/attribute.h>
#include <hilti/ast/declaration.h>
#include <hilti/ast/expression.h>

namespace hilti::declaration {

/** AST node for a expression declaration. */
class Expression : public Declaration {
public:
    auto expression() const { return child<hilti::Expression>(0); }
    auto attributes() const { return child<AttributeSet>(1); }

    std::string displayName() const final { return "expression"; }

    static auto create(ASTContext* ctx, ID id, const ExpressionPtr& expr, const AttributeSetPtr& attrs,
                       declaration::Linkage linkage, Meta meta = {}) {
        return NodeDerivedPtr<Expression>(new Expression(ctx, {expr, attrs}, std::move(id), linkage, std::move(meta)));
    }
    static auto create(ASTContext* ctx, ID id, const ExpressionPtr& expr, declaration::Linkage linkage,
                       Meta meta = {}) {
        return create(ctx, std::move(id), expr, nullptr, linkage, std::move(meta));
    }


protected:
    Expression(ASTContext* ctx, Nodes children, ID id, declaration::Linkage linkage, Meta meta)
        : Declaration(ctx, std::move(children), std::move(id), linkage, std::move(meta)) {}

    HILTI_NODE(hilti, Expression)
};

} // namespace hilti::declaration
