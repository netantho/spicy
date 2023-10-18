// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <algorithm>
#include <exception>

#include <hilti/ast/ctors/integer.h>
#include <hilti/ast/types/integer.h>

using namespace hilti;
using namespace hilti::type;

NodeDerivedPtr<SignedInteger> type::SignedInteger::create(ASTContext* ctx, unsigned int width, const Meta& m) {
    return NodeDerivedPtr<SignedInteger>(new SignedInteger(ctx, {}, width, m));
}

NodeDerivedPtr<UnsignedInteger> type::UnsignedInteger::create(ASTContext* ctx, unsigned int width, const Meta& m) {
    return NodeDerivedPtr<UnsignedInteger>(new UnsignedInteger(ctx, {}, width, m));
}
