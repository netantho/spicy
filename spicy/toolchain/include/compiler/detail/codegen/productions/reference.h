// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <spicy/compiler/detail/codegen/production.h>
#include <spicy/compiler/detail/codegen/productions/visitor.h>

namespace spicy::detail::codegen::production {

/**
 * Wrapper production that forwards to an already existing one, without owning
 * it.
 */
class Reference : public Production {
public:
    Reference(ASTContext* /* ctx */, Production* prod)
        : Production(prod->symbol(), prod->location()), _production(prod) {}

    auto* production() const { return _production; }

    bool isAtomic() const final { return _production->isAtomic(); };
    bool isEodOk() const final { return _production->isNullable(); };
    bool isLiteral() const final { return _production->isLiteral(); };
    bool isNullable() const final { return _production->isNullable(); };
    bool isTerminal() const final { return _production->isTerminal(); };

    std::vector<std::vector<Production*>> rhss() const final { return _production->rhss(); }
    ExpressionPtr expression() const final { return _production->expression(); }
    QualifiedTypePtr type() const final { return _production->type(); }
    int64_t tokenID() const final { return _production->tokenID(); };

    std::string render() const final { return hilti::util::fmt("ref(%s)", _production->render()); }

    SPICY_PRODUCTION

private:
    Production* _production;
};

} // namespace spicy::detail::codegen::production
