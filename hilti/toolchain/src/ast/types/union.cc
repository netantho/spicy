// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/types/union.h>

using namespace hilti;

bool type::Union::isResolved() const {
    const auto& cs = children();

    return std::all_of(cs.begin(), cs.end(), [&](const auto& c) {
        if ( auto f = c->template tryAs<declaration::Field>() )
            return f->isResolved();

        else if ( auto p = c->template tryAs<type::function::Parameter>() )
            return p->isResolved();

        return true;
    });
}
