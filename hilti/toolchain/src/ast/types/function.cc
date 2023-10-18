// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/types/function.h>

using namespace hilti;

bool type::Function::isResolved() const {
    if ( result()->type()->isA<type::Auto>() )
        // We treat this as resolved because (1) it doesn't need to hold up
        // other resolving, and (2) can lead to resolver dead-locks if we
        // let it.
        return true;

    if ( ! result()->type()->isResolved() )
        return false;

    // TODO: Should this move to the beginning before auto check?
    for ( auto p = children().begin() + 1; p != children().end(); p++ ) {
        if ( ! (*p)->as<declaration::Parameter>()->isResolved() )
            return false;
    }

    return true;
}
