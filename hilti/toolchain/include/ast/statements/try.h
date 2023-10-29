// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <hilti/ast/declarations/parameter.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/statement.h>
#include <hilti/base/logger.h>

namespace hilti::statement {

namespace try_ {

/** AST node for a `catch` block. */
class Catch final : public Node {
public:
    ~Catch() final;

    auto parameter() const { return child<declaration::Parameter>(0); }
    auto body() const { return child<hilti::Statement>(1); }

    static auto create(ASTContext* ctx, const DeclarationPtr& param, const StatementPtr& body, Meta meta = {}) {
        return NodeDerivedPtr<Catch>(new Catch(ctx, {param, body}, std::move(meta)));
    }

    static auto create(ASTContext* ctx, const StatementPtr& body, Meta meta = {}) {
        return NodeDerivedPtr<Catch>(new Catch(ctx, {nullptr, body}, std::move(meta)));
    }

protected:
    Catch(ASTContext* ctx, Nodes children, Meta meta = {}) : Node(ctx, std::move(children), std::move(meta)) {
        if ( child(0) && ! child(0)->isA<declaration::Parameter>() )
            logger().internalError("'catch' first child must be parameter");
    }

    std::string _render() const final;

    HILTI_NODE(Catch);
};

using CatchPtr = std::shared_ptr<Catch>;
using Catches = std::vector<CatchPtr>;

} // namespace try_

/** AST node for a `try` statement. */
class Try : public Statement {
public:
    auto body() const { return child<hilti::Statement>(0); }
    auto catches() const { return children<try_::Catch>(1, {}); }

    static auto create(ASTContext* ctx, StatementPtr body, const try_::Catches& catches, Meta meta = {}) {
        return NodeDerivedPtr<Try>(new Try(ctx, node::flatten(std::move(body), catches), std::move(meta)));
    }

protected:
    Try(ASTContext* ctx, Nodes children, Meta meta) : Statement(ctx, std::move(children), std::move(meta)) {}

    HILTI_NODE(Try)
};

} // namespace hilti::statement
