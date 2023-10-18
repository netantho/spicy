// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/declarations/field.h>
#include <hilti/ast/declarations/type.h>

using namespace hilti;
using namespace hilti::declaration;

node::Properties declaration::Field::properties() const {
    ID id = "<unset>";
    if ( linkedType() ) {
        if ( linkedType()->typeID() )
            id = *linkedType()->typeID();
        else
            id = "<no-type-id>";
    }

    auto p = node::Properties{{"cc", _cc ? to_string(*_cc) : "<unset>"}, {"type", id}};

    return Declaration::properties() + p;
}

std::string declaration::Field::_render() const {
    std::vector<std::string> x;

    if ( isResolved() )
        x.emplace_back("(resolved)");
    else
        x.emplace_back("(not resolved)");

    return util::join(x);
}
