// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <hilti/ast/declarations/parameter.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/type.h>

namespace hilti::type {

namespace operand_list {

/** Base class for operand nodes. */
class Operand final : public Node {
public:
    const auto& id() const { return _id; }
    auto type__() const { return child<UnqualifiedType>(0); }
    auto kind() const { return _kind; }
    auto isOptional() const { return _optional; }
    auto default_() const { return child<Expression>(1); }

    node::Properties properties() const final {
        auto p = node::Properties{{"id", _id}, {"optional", _optional}, {"kind", to_string(_kind)}};
        return Node::properties() + p;
    }

    static auto create(ASTContext* ctx, parameter::Kind kind, const UnqualifiedTypePtr& type, bool optional = false,
                       Meta meta = {}) {
        return NodeDerivedPtr<Operand>(new Operand(ctx, {type, nullptr}, {}, kind, optional, std::move(meta)));
    }

    static auto create(ASTContext* ctx, ID id, parameter::Kind kind, const UnqualifiedTypePtr& type,
                       bool optional = false, Meta meta = {}) {
        return NodeDerivedPtr<Operand>(
            new Operand(ctx, {type, nullptr}, std::move(id), kind, optional, std::move(meta)));
    }

    static auto create(ASTContext* ctx, ID id, parameter::Kind kind, const UnqualifiedTypePtr& type,
                       const ExpressionPtr& default_, const Meta& meta = {}) {
        return NodeDerivedPtr<Operand>(
            new Operand(ctx, {type, default_}, std::move(id), kind, (default_ != nullptr), meta));
    }

    static auto create(ASTContext* ctx, ID id, parameter::Kind kind, const UnqualifiedTypePtr& type,
                       const ExpressionPtr& default_, bool optional, const Meta& meta = {}) {
        return NodeDerivedPtr<Operand>(new Operand(ctx, {type, default_}, std::move(id), kind, optional, meta));
    }

protected:
    Operand(ASTContext* ctx, Nodes children, ID id, parameter::Kind kind, bool optional, Meta meta = {})
        : Node(ctx, std::move(children), std::move(meta)), _id(std::move(id)), _kind(kind), _optional(optional) {}

    HILTI_NODE(Operand);

private:
    ID _id;
    parameter::Kind _kind = parameter::Kind::Unknown;
    bool _optional = false;
};

using OperandPtr = NodeDerivedPtr<Operand>;
using Operands = std::vector<OperandPtr>;
} // namespace operand_list

/**
 * AST node for a type representing a list of function/method operands. This
 * is an internal type used for overload resolution, it's nothing actually
 * instantiated by a HILTI program. That's also why we don't use any child
 * nodes, but store the operands directly.
 */
class OperandList final : public UnqualifiedType {
public:
    auto operands() const { return children<operand_list::Operand>(0, {}); }
    auto op0() const {
        assert(children().size() >= 1);
        return child<operand_list::Operand>(0);
    }
    auto op1() const {
        assert(children().size() >= 2);
        return child<operand_list::Operand>(1);
    }
    auto op2() const {
        assert(children().size() >= 3);
        return child<operand_list::Operand>(2);
    }

    std::string_view typeClass() const final { return "operand-list"; }

    static auto create(ASTContext* ctx, operand_list::Operands operands, Meta meta = {}) {
        return NodeDerivedPtr<OperandList>(new OperandList(ctx, node::flatten(std::move(operands)), std::move(meta)));
    }

    static auto create(ASTContext* ctx, Wildcard _, const Meta& m = Meta()) {
        return NodeDerivedPtr<OperandList>(new OperandList(ctx, Wildcard(), m));
    }

    template<typename Container>
    static UnqualifiedTypePtr fromParameters(ASTContext* ctx, const Container& params) {
        operand_list::Operands ops;

        for ( const auto& p : params )
            ops.push_back(operand_list::Operand::create(ctx, p->id(), p->kind(), p->type()->type(), p->default_()));

        return type::OperandList::create(ctx, std::move(ops));
    }

protected:
    OperandList(ASTContext* ctx, Nodes children, Meta meta)
        : UnqualifiedType(ctx, {}, std::move(children), std::move(meta)) {}
    OperandList(ASTContext* ctx, Wildcard _, const Meta& meta)
        : UnqualifiedType(ctx, Wildcard(), {"operand-list(*)"}, meta) {}

    HILTI_NODE(OperandList)
};

} // namespace hilti::type
