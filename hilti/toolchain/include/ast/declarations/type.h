// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>
#include <utility>

#include <hilti/ast/attribute.h>
#include <hilti/ast/declaration.h>
#include <hilti/ast/type.h>

namespace hilti::declaration {

/** AST node for a type declaration. */
class Type : public Declaration {
public:
    auto type() const { return child<QualifiedType>(0); }
    auto attributes() const { return child<AttributeSet>(1); }

    bool isOnHeap() const {
        if ( auto x = attributes() )
            return x->find("&on-heap") != nullptr;
        else
            return false;
    }

    /** Shortcut to `type::typeID()` for the declared type. */
    auto typeID() const { return child<QualifiedType>(0)->type()->typeID(); }

    /** Shortcut to `type::cxxID()` for the declared type. */
    auto cxxID() const { return child<QualifiedType>(0)->type()->cxxID(); }

    /*
     * #<{(|* Shortcut to `type::resolvedID()` for the declared type. |)}>#
     * auto resolvedID() const { return child<QualifiedType>(0)->type()->resolvedID(); }
     */

    void setType(ASTContext* ctx, const QualifiedTypePtr& t) { setChild(ctx, 0, t); }

    std::string displayName() const final { return "type"; }

    static auto create(ASTContext* ctx, ID id, const QualifiedTypePtr& type, AttributeSetPtr attrs,
                       declaration::Linkage linkage = Linkage::Private, Meta meta = {}) {
        if ( ! attrs )
            attrs = AttributeSet::create(ctx);

        return NodeDerivedPtr<Type>(new Type(ctx, {type, attrs}, std::move(id), linkage, std::move(meta)));
    }

    static auto create(ASTContext* ctx, ID id, const QualifiedTypePtr& type,
                       declaration::Linkage linkage = Linkage::Private, Meta meta = {}) {
        return create(ctx, std::move(id), type, AttributeSet::create(ctx), linkage, std::move(meta));
    }

protected:
    Type(ASTContext* ctx, Nodes children, ID id, declaration::Linkage linkage, Meta meta)
        : Declaration(ctx, std::move(children), std::move(id), linkage, std::move(meta)) {}

    HILTI_NODE(Type)
};

} // namespace hilti::declaration
