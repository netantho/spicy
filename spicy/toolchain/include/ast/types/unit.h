// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>
#include <utility>

#include <hilti/ast/attribute.h>
#include <hilti/ast/declarations/parameter.h>
#include <hilti/ast/type.h>

#include <spicy/ast/forward.h>
#include <spicy/ast/types/unit-item.h>

#include "ast/type.h"

namespace spicy {

namespace detail::codegen {
class Grammar;
} // namespace detail::codegen

namespace type {

/** AST node for a unit type. */
class Unit : public UnqualifiedType {
public:
    auto items() const { return childrenOfType<unit::Item>(); }
    auto attributes() const { return child<AttributeSet>(1); }

    auto self() const { return child<Declaration>(0); }
    void clearSelf(ASTContext* ctx) { setChild(ctx, 0, nullptr); }

    /** Returns the type set through ``%context`, if available. */
    UnqualifiedTypePtr contextType() const;

    /**
     * Returns the item of a given name if it exists. This descends
     * recursively into children as well.
     */
    unit::ItemPtr itemByName(const ID& id) const;

    /**
     * Returns all of the unit's items of a particular subtype T.
     **/
    template<typename T>
    auto items() const {
        return childrenOfType<T>();
    }

    /**
     * Returns the property of a given name if it exists. If it exists more
     * than once, it's undefined which one is returned.
     */
    type::unit::item::PropertyPtr propertyItem(const std::string& name) const;

    /** Returns all properties of a given name. */
    unit::item::Properties propertyItems(const std::string& name) const;

    /**
     * Returns true if the unit has been declared as publically/externally
     * accessible.
     */
    auto isPublic() const { return _public; };

    /** * Returns true if this unit type can act as a filter. */
    bool isFilter() const { return propertyItem("%filter") != nullptr; }

    /** Returns the grammar associated with the type. It must have been set
     * before through `setGrammar()`. */
    const spicy::detail::codegen::Grammar& grammar() const {
        assert(_grammar);
        return *_grammar;
    }

    /** Adds a number of new items to the unit. */
    void addItems(ASTContext* ctx, unit::Items items) {
        addChildren(ctx, std::move(items));
        _assignItemIndices();
    }

    void setAttributes(ASTContext* ctx, const AttributeSetPtr& attrs) { setChild(ctx, 1, attrs); }
    void setGrammar(std::shared_ptr<spicy::detail::codegen::Grammar> g) { _grammar = std::move(g); }
    void setPublic(bool p) { _public = p; }

    std::string_view typeClass() const final { return "unit"; }

    hilti::declaration::Parameters parameters() const final { return childrenOfType<hilti::declaration::Parameter>(); }

    bool isAllocable() const final { return true; }
    bool isMutable() const final { return true; }
    bool isNameType() const final { return true; }
    bool isResolved() const final;

    node::Properties properties() const final {
        auto p = node::Properties{{"public", _public}};
        return hilti::UnqualifiedType::properties() + p;
    }

    static auto create(ASTContext* ctx, const hilti::declaration::Parameters& params, type::unit::Items items,
                       AttributeSetPtr attrs, const Meta& meta = {}) {
        if ( ! attrs )
            attrs = hilti::AttributeSet::create(ctx);

        for ( auto&& p : params )
            p->setIsTypeParameter();

        auto t = NodeDerivedPtr<Unit>(new Unit(ctx, node::flatten(nullptr, attrs, params, std::move(items)), meta));
        t->_setSelf(ctx);
        return t;
    }

    static auto create(ASTContext* ctx, hilti::type::Wildcard _, const Meta& meta = {}) {
        auto t =
            NodeDerivedPtr<Unit>(new Unit(ctx, hilti::type::Wildcard(), {nullptr, AttributeSet::create(ctx)}, meta));
        t->_setSelf(ctx);
        return t;
    }

protected:
    Unit(ASTContext* ctx, const Nodes& children, const Meta& meta) : UnqualifiedType(ctx, {}, children, meta) {}

    Unit(ASTContext* ctx, hilti::type::Wildcard _, const Nodes& children, Meta meta)
        : UnqualifiedType(ctx, hilti::type::Wildcard(), {"unit(*)"}, children, std::move(meta)) {
        _assignItemIndices();
    }

    HILTI_NODE(spicy, Unit)

private:
    void _setSelf(ASTContext* ctx);
    void _assignItemIndices();

    bool _public = false;
    std::shared_ptr<spicy::detail::codegen::Grammar> _grammar;
};

} // namespace type
} // namespace spicy
