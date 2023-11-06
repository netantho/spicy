// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <spicy/ast/hook.h>
#include <spicy/ast/types/unit-items/field.h>
#include <spicy/ast/types/unit.h>

using namespace spicy;

Hook::~Hook() {}

node::Properties Hook::properties() const {
    auto p = node::Properties{{"engine", to_string(_engine)}};

    if ( auto t = _unit_type.lock() )
        p.emplace("unit", t->typeID());
    else
        p.emplace("unit", "<unset>");

    if ( auto f = _unit_field.lock() )
        p.emplace("field", f->id());
    else
        p.emplace("field", "<unset>");

    return Node::properties() + p;
}
