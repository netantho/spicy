// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/statement.h>

#include <spicy/ast/forward.h>

namespace spicy::statement {

/** AST node for a `break` statement. */
class Stop : public Statement {
public:
    static auto create(ASTContext* ctx, Meta meta = {}) {
        return NodeDerivedPtr<Stop>(new Stop(ctx, {}, std::move(meta)));
    }

protected:
    Stop(ASTContext* ctx, Nodes children, Meta meta) : Statement(ctx, std::move(children), std::move(meta)) {}

    HILTI_NODE(spicy, Stop)
};

} // namespace spicy::statement
