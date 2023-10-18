// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/types/struct.h>

using namespace hilti;
using namespace hilti::type;

int64_t Struct::_anon_struct_counter = 0;

bool Struct::isResolved() const {
    for ( const auto& c : children<Declaration>(1, {}) ) {
        if ( auto f = c->template tryAs<declaration::Field>(); f && ! f->isResolved() )
            return false;

        if ( auto p = c->template tryAs<type::function::Parameter>(); p && ! p->isResolved() )
            return false;

        return true;
    }

    return true;
}

void Struct::_setSelf(ASTContext* ctx) {
    auto qtype = QualifiedType::createExternal(ctx, as<UnqualifiedType>(), false);
    auto self =
        expression::Keyword::create(ctx, expression::keyword::Kind::Self,
                                    QualifiedType::create(ctx, type::ValueReference::create(ctx, qtype), false));

    auto decl = declaration::Expression::create(ctx, ID("self"), self, {}, meta());
    decl->setFullyQualifiedID(ID("self"));

    setChild(ctx, 0, std::move(decl));
}
