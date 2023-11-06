// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>
#include <utility>

#include <hilti/ast/declaration.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/id.h>
#include <hilti/ast/type.h>

namespace hilti::expression {

/** AST node for an expression referencing an ID. */
class Name : public Expression {
public:
    const auto& id() const { return _id; }
    auto resolvedDeclaration() const { return _declaration; }

    QualifiedTypePtr type() const final;

    void setID(ID id) { _id = std::move(id); }
    void setResolvedDeclaration(ASTContext* ctx, const DeclarationPtr& d) {
        _declaration = d;
        setChild(ctx, 0, nullptr);
    }

    node::Properties properties() const final;

    static auto create(ASTContext* ctx, const hilti::ID& id, const Meta& meta = {}) {
        return NodeDerivedPtr<Name>(new Name(ctx, {QualifiedType::createAuto(ctx, meta)}, id, meta));
    }

protected:
    Name(ASTContext* ctx, Nodes children, hilti::ID id, Meta meta)
        : Expression(ctx, std::move(children), std::move(meta)), _id(std::move(id)) {}

    HILTI_NODE(hilti, Name)

private:
    hilti::ID _id;

    // TODO: Changing this to weak_ptr leads to some nullptr trouble (e.g.,
    // hilti.expressions.list-comprehension). Not sure if I'd expect that ...
    DeclarationPtr _declaration;
};

} // namespace hilti::expression
