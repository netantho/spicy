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

        void operator()(declaration::Constant* n) final { result = n->type(); }
        void operator()(declaration::Expression* n) final { result = n->expression()->type(); }
        void operator()(declaration::Field* n) final { result = n->type(); }
        void operator()(declaration::Function* n) final { result = n->function()->type(); }
        void operator()(declaration::GlobalVariable* n) final { result = n->type(); }
        void operator()(declaration::LocalVariable* n) final { result = n->type(); }
        void operator()(declaration::Parameter* n) final { result = n->type(); }
        void operator()(declaration::Type* n) final { result = n->type(); }
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
                              {"resolved", (resolvedDeclaration() ? resolvedDeclaration()->canonicalID().str() :
                                                                    std::string("-"))}};
    return Expression::properties() + p;
}
