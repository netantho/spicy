// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/types/reference.h>

#include <spicy/ast/types/unit-items/field.h>
#include <spicy/ast/types/unit.h>

using namespace spicy;
using namespace spicy::detail;

std::optional<std::pair<ExpressionPtr, QualifiedTypePtr>> type::unit::item::Field::convertExpression() const {
    if ( auto convert = attributes()->find("&convert") )
        return std::make_pair(*convert->valueAsExpression(), nullptr);

    auto t = parseType();

    if ( auto x = t->type()->tryAs<hilti::type::ValueReference>() )
        t = x->dereferencedType();

    if ( auto x = t->type()->tryAs<type::Unit>() ) {
        if ( auto convert = x->attributes()->find("&convert") )
            return std::make_pair(*convert->valueAsExpression(), std::move(t));
    }

    return {};
}
