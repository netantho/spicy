// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>

#include <spicy/compiler/detail/codegen/production.h>
#include <spicy/compiler/detail/codegen/productions/visitor.h>

namespace spicy::detail::codegen {
class Grammar;
} // namespace spicy::detail::codegen

namespace spicy::detail::codegen::production {

/*
 * Place-holder production that's resolved through a `Grammar` later. This
 * can used to be create to self-recursive grammars.
 *
 * @note This option doesn't actually implement most of the `Production` API
 * (meaningfully).
 */
class Resolved : public Production {
public:
    Resolved(ASTContext* /* ctx */, const Location& l = location::None)
        : Production("", l),
          _symbol(std::make_shared<std::string>("<unresolved>")),
          _rsymbol(hilti::util::fmt("ref:%d", ++_cnt)) {}

    const auto& symbol() const { return *_symbol; }
    const auto& referencedSymbol() const { return _rsymbol; }

    void resolve(Production* p) {
        *_symbol = p->symbol();
        _resolved = p;
    }

    auto resolved() const { return _resolved; }

    bool isAtomic() const final { return true; };
    bool isEodOk() const final { return false; };
    bool isLiteral() const final { return false; };
    bool isNullable() const final { return false; };
    bool isTerminal() const final { return false; };

    std::string render() const final { return symbol(); }

    SPICY_PRODUCTION

private:
    Production* _resolved = nullptr;
    std::shared_ptr<std::string> _symbol;
    std::string _rsymbol;

    inline static int _cnt = 0;
};

} // namespace spicy::detail::codegen::production
