// Copyright (c) 2021-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>
#include <utility>

#include <hilti/ast/builder/node-factory.h>

namespace hilti {

class Builder : public builder::NodeFactory {
public:
    Builder(ASTContext* ctx) : NodeFactory(ctx) {}

    // TODO: This class is WIP. We'll expand it with the other old `builder::*` functions.

    ExpressionPtr namedCtor(const std::string& name, const Expressions& args, const Meta& m = Meta()) {
        return expressionUnresolvedOperator(operator_::Kind::Call,
                                            {expressionMember(ID(name)), expressionCtor(ctorTuple(args))}, m);
    }

    auto integer(unsigned int i, const Meta& m = Meta()) { return expressionCtor(ctorUnsignedInteger(i, 64, m), m); }
    auto bool_(bool b, const Meta& m = Meta()) { return expressionCtor(ctorBool(b, m), m); }
    auto string(std::string s, const Meta& m = Meta()) { return expressionCtor(ctorString(std::move(s), m), m); }
    auto tuple(const Expressions& v, const Meta& m = Meta()) { return expressionCtor(ctorTuple(v, m), m); }
};

using BuilderPtr = std::shared_ptr<Builder>;

} // namespace hilti
