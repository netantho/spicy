// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>
#include <utility>

#include <hilti/ast/declarations/function.h>
#include <hilti/ast/operators/common.h>

namespace hilti {

namespace operator_ {
HILTI_NODE_OPERATOR(function, Call); // AST node for instantiated call operator
}

namespace function {

class Call final : public Operator {
public:
    Call(std::weak_ptr<declaration::Function> f) : Operator(f.lock()->meta(), false), _fdecl(std::move(f)) {}
    ~Call() final;

    operator_::Signature signature(Builder* builder) const final;

    Result<ResolvedOperatorPtr> instantiate(Builder* builder, Expressions operands, const Meta& meta) const final;

    std::string name() const final { return "function::Call"; }

    private:
    friend class declaration::Function;

    std::weak_ptr<declaration::Function> _fdecl;
};

} // namespace function

} // namespace hilti
