// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/ctor.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/types/tuple.h>

namespace hilti::ctor {

/** AST node for a tuple ctor. */
class Tuple : public Ctor {
public:
    auto value() const { return children<Expression>(1, {}); }

    QualifiedTypePtr type() const final { return child<QualifiedType>(0); }

    void setType(ASTContext* ctx, QualifiedTypePtr t) { setChild(ctx, 0, std::move(t)); }

    static auto create(ASTContext* ctx, const Expressions& exprs, const Meta& meta = {}) {
        auto type = _inferType(ctx, exprs, meta);
        return NodeDerivedPtr<Tuple>(new Tuple(ctx, node::flatten(type, exprs), meta));
    }

protected:
    Tuple(ASTContext* ctx, Nodes children, Meta meta) : Ctor(ctx, std::move(children), std::move(meta)) {}

    HILTI_NODE(hilti, Tuple)

private:
    static QualifiedTypePtr _inferType(ASTContext* ctx, const Expressions& exprs, const Meta& meta) {
        for ( const auto& e : exprs ) {
            if ( ! e->isResolved() )
                return QualifiedType::createAuto(ctx, meta);
        }

        QualifiedTypes types;
        types.reserve(exprs.size());
        for ( const auto& e : exprs )
            types.emplace_back(e->type());

        return QualifiedType::create(ctx, type::Tuple::create(ctx, types, meta), true, meta);
    }
};
} // namespace hilti::ctor
