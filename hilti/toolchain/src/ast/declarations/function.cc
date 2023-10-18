// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/declarations/function.h>
#include <hilti/ast/expressions/name.h>
#include <hilti/ast/operators/function.h>
#include <hilti/ast/types/operand-list.h>
#include <hilti/ast/types/struct.h>

using namespace hilti;
using namespace hilti::declaration;

node::Properties declaration::Function::properties() const {
    ID type = "<unset>";
    if ( linkedType() ) {
        if ( linkedType()->typeID() )
            type = *linkedType()->typeID();
        else
            type = "<no-type-id>";
    }

    ID prototype = "<unset>";
    if ( linkedPrototype() )
        prototype = linkedPrototype()->canonicalID();

    auto p =
        node::Properties{{"operator", (_operator ? "<set>" : "<unset>")}, {"type", type}, {"prototype", prototype}};

    return Declaration::properties() + p;
}
