// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <hilti/ast/function.h>
#include <hilti/ast/node.h>
#include <hilti/ast/types/function.h>
#include <hilti/ast/types/void.h>

#include <spicy/ast/engine.h>
#include <spicy/ast/forward.h>

namespace spicy {

namespace type {

class Unit;

namespace unit::item {
class Field;
}

} // namespace type

/** AST node representing a Spicy unit hook. */
class Hook : public Node {
public:
    ~Hook() override;

    auto function() const { return child<Function>(0); }
    auto attributes() const { return function()->attributes(); }
    auto dd() const { return child(1)->tryAs<Declaration>(); }

    auto body() const { return function()->body(); }
    auto ftype() const { return function()->ftype(); }
    auto id() const { return function()->id(); }
    auto type() const { return function()->type(); }

    Engine engine() const { return _engine; }
    auto unitType() { return _unit_type.lock(); }
    auto unitField() { return _unit_field.lock(); }

    ExpressionPtr priority() const {
        if ( auto attr = attributes()->find("priority") )
            return *attr->valueAsExpression();
        else
            return nullptr;
    }

    auto isForEach() const { return attributes()->has("foreach"); }
    auto isDebug() const { return attributes()->has("%debug"); }

    void setID(const ID& id) { function()->setID(id); }
    void setUnitType(const NodeDerivedPtr<type::Unit>& unit) { _unit_type = unit; }
    void setField(const NodeDerivedPtr<type::unit::item::Field>& field) { _unit_field = field; }

    void setDD(ASTContext* ctx, const QualifiedTypePtr& t) { setChild(ctx, 1, t); }
    void setParameters(ASTContext* ctx, const hilti::declaration::Parameters& params) {
        ftype()->setParameters(ctx, params);
    }
    void setResult(ASTContext* ctx, const QualifiedTypePtr& t) { function()->setResultType(ctx, t); }

    node::Properties properties() const final;

    static auto create(ASTContext* ctx, const hilti::declaration::Parameters& parameters, const StatementPtr& body,
                       Engine engine, const AttributeSetPtr& attrs, const Meta& m = Meta()) {
        auto ftype = hilti::type::Function::create(ctx,
                                                   QualifiedType::create(ctx, hilti::type::Void::create(ctx, m),
                                                                         hilti::Constness::Const),
                                                   parameters, hilti::type::function::Flavor::Hook, m);
        auto func = hilti::Function::create(ctx, hilti::ID(), ftype, body, hilti::function::CallingConvention::Standard,
                                            attrs, m);
        return NodeDerivedPtr<Hook>(new Hook(ctx, node::flatten(func, nullptr), engine, m));
    }

protected:
    Hook(ASTContext* ctx, Nodes children, Engine engine, Meta m = Meta())
        : Node(ctx, std::move(children), std::move(m)), _engine(engine) {}

    HILTI_NODE(spicy, Hook);

private:
    Engine _engine = {};
    std::weak_ptr<type::Unit> _unit_type;
    std::weak_ptr<type::unit::item::Field> _unit_field;
};

using HookPtr = NodeDerivedPtr<Hook>;
using Hooks = std::vector<HookPtr>;

} // namespace spicy
