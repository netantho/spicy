// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/forward.h>
#include <hilti/ast/scope-lookup.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/all.h>
#include <hilti/compiler/detail/type-unifier.h>

using namespace hilti;
using namespace hilti::detail;
using util::fmt;

UnqualifiedType::~UnqualifiedType() {}

std::optional<ID> UnqualifiedType::typeID() const {
    if ( auto decl = _declaration.lock(); decl && decl->fullyQualifiedID() )
        return decl->fullyQualifiedID();
    else
        return std::nullopt;
}

std::optional<ID> UnqualifiedType::cxxID() const {
    if ( auto decl = _declaration.lock() ) {
        if ( auto a = decl->attributes()->find("&cxxname") )
            return ID{*a->valueAsString()};
    }

    return std::nullopt;
}

hilti::node::Properties UnqualifiedType::properties() const {
    auto p = node::Properties{{{"unified", _unification.str()},
                               {"declaration", declaration() ? declaration()->canonicalID().str() : std::string("-")},
                               {"wildcard", _is_wildcard}}};
    return Node::properties() + p;
}

std::string UnqualifiedType::_render() const {
    std::vector<std::string> x;

    x.emplace_back(this->isResolved() ? "(resolved)" : "(not resolved)");

    return util::join(x);
}

bool QualifiedType::isAuto() const { return type()->isA<type::Auto>(); }

hilti::node::Properties QualifiedType::properties() const {
    auto side = (_side == Side::LHS ? "lhs" : "rhs");
    auto constness = (_constness == Constness::Const ? "true" : "false");
    return {{"const", constness}, {"side", side}};
}

std::string QualifiedType::_render() const {
    std::vector<std::string> x;

    if ( _external_type ) {
        if ( ! _external_type->expired() )
            x.emplace_back(fmt("(weak external: %s [@t:%s])", _external_type->lock()->print(),
                               _external_type->lock()->identity()));
        else
            x.emplace_back("(weak external: EXPIRED)");
    }

    return util::join(x, " ");
}

UnqualifiedTypePtr type::follow(const UnqualifiedTypePtr& t) {
    if ( auto x = t->tryAs<type::Name>(); x && x->resolvedType() )
        return follow(x->resolvedType()->type()->type());

    return t;
}

UnqualifiedType* type::follow(UnqualifiedType* t) {
    if ( auto x = t->tryAs<type::Name>(); x && x->resolvedType() )
        return follow(x->resolvedType()->type()->type()).get();

    return t;
}

QualifiedTypePtr QualifiedType::createExternal(ASTContext* ctx, const std::weak_ptr<UnqualifiedType>& t,
                                               Constness const_, const Meta& m) {
    return NodeDerivedPtr<QualifiedType>(new QualifiedType(ctx, {type::Unknown::create(ctx)}, t, const_, Side::RHS, m));
}

QualifiedTypePtr QualifiedType::createAuto(ASTContext* ctx, const Meta& m) {
    return QualifiedTypePtr(new QualifiedType(ctx, {type::Auto::create(ctx, m)}, NonConst, Side::RHS, m));
}

QualifiedTypePtr QualifiedType::createAuto(ASTContext* ctx, Side side, const Meta& m) {
    return QualifiedTypePtr(new QualifiedType(ctx, {type::Auto::create(ctx, m)}, NonConst, side, m));
}

bool UnqualifiedType::unify(ASTContext* ctx, const NodePtr& scope_root) {
    return type_unifier::unify(ctx, as<UnqualifiedType>());
}
