// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <hilti/ast/declaration.h>
#include <hilti/ast/declarations/type.h>
#include <hilti/ast/detail/operator-registry.h>
#include <hilti/ast/node-range.h>
#include <hilti/ast/operator.h>
#include <hilti/ast/types/struct.h>
#include <hilti/ast/types/type.h>

namespace hilti::declaration {

/** AST node for a function declaration. */
class Function : public Declaration {
public:
    ~Function() override {}

    auto function() const { return child<::hilti::Function>(0); }

    /** Returns an operator corresponding to a call to the function that the declaration corresponds to. */
    const auto& operator_() const { return _operator; }

    auto linkedType() const { return _linked_type.lock(); }
    auto linkedPrototype() const { return _linked_prototype.lock(); }

    void setOperator(const Operator* op) { _operator = op; }

    void setLinkedType(const NodeDerivedPtr<declaration::Type>& decl) {
        assert(decl->type()->type()->isA<type::Struct>());
        _linked_type = decl;
    }

    void setLinkedPrototype(const DeclarationPtr& decl) {
        assert(decl->isA<declaration::Field>() || decl->isA<declaration::Function>());
        _linked_prototype = decl;
    }

    std::string displayName() const final { return "function"; }

    node::Properties properties() const final;

    static NodeDerivedPtr<Function> create(ASTContext* ctx, const FunctionPtr& function,
                                           declaration::Linkage linkage = Linkage::Private, const Meta& meta = {}) {
        return NodeDerivedPtr<Function>(new Function(ctx, {function}, function->id(), linkage, meta));
    }

protected:
    Function(ASTContext* ctx, Nodes children, ID id, declaration::Linkage linkage, Meta meta)
        : Declaration(ctx, std::move(children), std::move(id), linkage, std::move(meta)) {}

    HILTI_NODE(Function)

private:
    const Operator* _operator = nullptr;

    std::weak_ptr<declaration::Type> _linked_type;
    std::weak_ptr<Declaration> _linked_prototype;
};

} // namespace hilti::declaration
