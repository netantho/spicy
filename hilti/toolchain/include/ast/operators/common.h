// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <utility>
#include <vector>

#include <hilti/ast/expressions/resolved-operator.h>
#include <hilti/ast/forward.h>

#define HILTI_NODE_OPERATOR(scope, ns, cls)                                                                            \
    namespace ns {                                                                                                     \
    class cls : public hilti::expression::ResolvedOperator {                                                           \
    public:                                                                                                            \
        static NodeDerivedPtr<cls> create(ASTContext* ctx, const hilti::Operator* op, const QualifiedTypePtr& result,  \
                                          const Expressions& operands, const hilti::Meta& meta) {                      \
            return NodeDerivedPtr<cls>(new cls(ctx, op, result, operands, meta));                                      \
        }                                                                                                              \
                                                                                                                       \
        HILTI_NODE(scope, cls)                                                                                         \
                                                                                                                       \
    private:                                                                                                           \
        using hilti::expression::ResolvedOperator::ResolvedOperator;                                                   \
    };                                                                                                                 \
    } // namespace ns
