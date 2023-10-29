// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <hilti/ast/attribute.h>
#include <hilti/ast/declaration.h>
#include <hilti/ast/declarations/type.h>
#include <hilti/ast/detail/operator-registry.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/function.h>
#include <hilti/ast/id.h>
#include <hilti/ast/operators/struct.h>
#include <hilti/ast/types/auto.h>

namespace hilti::declaration {

/** AST node for a struct/union field declaration. */
class Field : public Declaration {
public:
    auto callingConvention() const { return _cc; }
    auto attributes() const { return child<AttributeSet>(1); }
    auto inlineFunction() const { return child<hilti::Function>(2); }

    /** Returns an operator corresponding to a call to the member function that the declaration corresponds to, if any.
     */
    const auto& operator_() const { return _operator; }

    QualifiedTypePtr type() const {
        if ( const auto& func = inlineFunction() )
            return func->type();
        else
            return child<QualifiedType>(0);
    }

    bool isResolved() const {
        if ( auto func = inlineFunction() )
            return func->type()->isResolved();

        if ( auto type = child<QualifiedType>(0); type->type()->isA<type::Function>() )
            return true;
        else
            return type->isResolved();
    }

    ExpressionPtr default_() const {
        if ( auto a = attributes()->find("&default") )
            return *a->valueAsExpression();
        else
            return {};
    }

    auto isAnonymous() const { return attributes()->find("&anonymous") != nullptr; }
    auto isInternal() const { return attributes()->find("&internal") != nullptr; }
    auto isOptional() const { return attributes()->find("&optional") != nullptr; }
    auto isStatic() const { return attributes()->find("&static") != nullptr; }
    auto isNoEmit() const { return attributes()->find("&no-emit") != nullptr; }

    auto linkedType() const { return _linked_type.lock(); }

    void setAttributes(ASTContext* ctx, const AttributeSetPtr& attrs) { setChild(ctx, 1, attrs); }
    void setOperator(const Operator* op) { _operator = op; }
    void setType(ASTContext* ctx, const QualifiedTypePtr& t) { setChild(ctx, 0, t); }
    void setLinkedType(const NodeDerivedPtr<UnqualifiedType>& decl) { _linked_type = decl; }

    std::string displayName() const final { return "struct field"; }

    node::Properties properties() const final;

    static auto create(ASTContext* ctx, ID id, const QualifiedTypePtr& type, const AttributeSetPtr& attrs,
                       Meta meta = {}) {
        return NodeDerivedPtr<Field>(new Field(ctx, {type, attrs, nullptr}, std::move(id), {}, std::move(meta)));
    }

    static auto create(ASTContext* ctx, ID id, ::hilti::function::CallingConvention cc, const type::FunctionPtr& ftype,
                       const AttributeSetPtr& attrs, Meta meta = {}) {
        return NodeDerivedPtr<Field>(new Field(ctx, {QualifiedType::create(ctx, ftype, true), attrs, nullptr},
                                               std::move(id), cc, std::move(meta)));
    }

    static auto create(ASTContext* ctx, const ID& id, const FunctionPtr& inline_func, const AttributeSetPtr& attrs,
                       Meta meta = {}) {
        return NodeDerivedPtr<Field>(new Field(ctx, {nullptr, attrs, inline_func}, id, {}, std::move(meta)));
    }

protected:
    Field(ASTContext* ctx, Nodes children, ID id, std::optional<::hilti::function::CallingConvention> cc, Meta meta)
        : Declaration(ctx, std::move(children), std::move(id), declaration::Linkage::Struct, std::move(meta)) {}

    std::string _render() const override;

    HILTI_NODE(Field)

private:
    std::optional<::hilti::function::CallingConvention> _cc;
    const Operator* _operator = nullptr;
    std::weak_ptr<UnqualifiedType> _linked_type;
};

using FieldPtr = std::shared_ptr<Field>;
using FieldList = std::vector<FieldPtr>;

} // namespace hilti::declaration
