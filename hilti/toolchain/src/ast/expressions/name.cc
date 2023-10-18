// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <functional>

#include <hilti/ast/declarations/all.h>
#include <hilti/ast/expressions/name.h>
#include <hilti/ast/types/type.h>
#include <hilti/base/logger.h>

using namespace hilti;

QualifiedTypePtr expression::Name::type() const {
    struct Visitor : hilti::visitor::PreOrder {
        QualifiedTypePtr result = nullptr;

        void operator()(declaration::Constant* c) final { result = c->type(); }
        void operator()(declaration::Expression* e) final { result = e->expression()->type(); }
        void operator()(declaration::Field* f) final { result = f->type(); }
        void operator()(declaration::Function* f) final { result = f->function()->type(); }
        void operator()(declaration::GlobalVariable* v) final { result = v->type(); }
        void operator()(declaration::LocalVariable* v) final { result = v->type(); }
        void operator()(declaration::Parameter* p) final { result = p->type(); }
        void operator()(declaration::Type* t) final { result = t->type(); }
    };

    if ( auto decl = resolvedDeclaration() ) {
        if ( auto type = visitor::dispatch(Visitor(), decl, [](const auto& x) { return x.result; }) )
            return type;
        else
            logger().internalError(util::fmt("unsupported declaration type %s", resolvedDeclaration()->typename_()),
                                   this);
    }
    else
        return child<QualifiedType>(0);
}

node::Properties expression::Name::properties() const {
    auto p = node::Properties{{"id", _id},
                              {"resolved", (resolvedDeclaration() ? resolvedDeclaration()->canonicalID().str() : std::string("-"))}};
    return Expression::properties() + p;
}
