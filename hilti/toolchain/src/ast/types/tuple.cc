// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <algorithm>
#include <exception>
#include <functional>

#include <hilti/ast/types/tuple.h>

using namespace hilti;

type::tuple::Element::~Element() = default;

std::optional<std::pair<int, std::shared_ptr<type::tuple::Element>>> type::Tuple::elementByID(const ID& id) const {
    int i = 0;
    for ( const auto& e : elements() ) {
        if ( e->id() == id )
            return std::make_optional(std::make_pair(i, e));

        i++;
    }

    return {};
}

bool type::Tuple::isResolved() const {
    const auto& cs = children();

    return std::all_of(cs.begin(), cs.end(), [&](const auto& c) {
        auto t = c->template tryAs<QualifiedType>();
        return ! t || t->isResolved();
    });
}
