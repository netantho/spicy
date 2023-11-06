// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <unistd.h>

#include <memory>
#include <string>
#include <type_traits>
#include <typeinfo>
#include <unordered_set>
#include <utility>
#include <vector>

#include <hilti/ast/id.h>
#include <hilti/ast/node.h>
#include <hilti/ast/visitor.h>

namespace hilti {

namespace builder {
class NodeBuilder;
}

namespace declaration {
class Parameter;
class Type;
} // namespace declaration

namespace type::function {
using Parameter = declaration::Parameter;
} // namespace type::function

namespace type {

/** Strong type argument for type constructors. */
struct Wildcard {
    explicit Wildcard() = default;
};

/** Strong type argument to `Unification` constructor. */
struct NeverMatch {
    explicit NeverMatch() = default;
};

namespace detail {
using ResolvedState = std::unordered_set<uintptr_t>;
}

} // namespace type

namespace type {

/**
 * Represent a type's unification string. Two types with the same unification
 * string are considered equivalent during AST processing.
 */
struct Unification {
    /** Creates a unset unification string, which will never match any other. */
    Unification() = default;

    /**
     * Create a unification from pre-computed serialization string.
     *
     * @param serialization string representation of the unification; must not be empty
     */
    Unification(std::string serialization) : _serialization(std::move(serialization)) {
        assert(! _serialization->empty());
    }

    /**
     * Create a unification that's guaranteed to never match any other unification.
     *
     * @param never_match unused
     */
    Unification(NeverMatch _) : _serialization("") {}

    Unification(const Unification& other) = default;
    Unification(Unification&& other) = default;
    ~Unification() = default;

    Unification& operator=(const Unification& other) = default;
    Unification& operator=(Unification&& other) = default;

    /**
     * Returns a string representation of the unification string. This is
     * human-readable for display purposes.
     */
    std::string str() const {
        if ( ! _serialization.has_value() )
            return "<unset>";

        if ( _serialization->empty() )
            return "<never-match>";

        return *_serialization;
    }

    /** Forwards to `str()`. */
    operator std::string() const { return str(); }

    /** Returns true if unification string has been set. */
    operator bool() const { return _serialization.has_value(); }

    /**
     * Returns true if two unifications are  equivalent. Will always return
     * false if any of the is set to never-match, or not set at all.
     */
    bool operator==(const Unification& other) const {
        if ( ! (_serialization.has_value() && other._serialization.has_value()) )
            return false;

        if ( _serialization->empty() || other._serialization->empty() )
            return false;

        return *_serialization == *other._serialization;
    }

    bool operator!=(const Unification& other) const { return ! (*this == other); }

private:
    std::optional<std::string> _serialization; // set but empty means never-match
};
} // namespace type

/** * Base class for classes implementing unqualified types. */
class UnqualifiedType : public Node {
public:
    ~UnqualifiedType() override;

    /**
     * Returns the declaration associated with the type, if any. This will be
     * set during AST resolving.
     */
    auto declaration() const { return _declaration.lock(); }

    /**
     * Sets the declaration associated with the type. Should normally be called
     * only by the AST resolver.
     *
     * @param d declaration to set
     */
    void setDeclaration(const NodeDerivedPtr<declaration::Type>& d) { _declaration = d; }

    /**
     * Returns the C++ ID associated with this type, if any. This is a shortcut
     * to retrieving the associated declaration's C++ ID, which is set through
     * a `&cxxname` attribute.
     */
    std::optional<ID> cxxID() const;

    /**
     * Returns the ID associated with this type, if any. This is a shortcut to
     * retrieving the associated declaration's fully-qualified ID, which is
     * computed during AST resolving.
     */
    std::optional<ID> typeID() const;

    /**
     * Returns true if the type is a wildcard type. That means that all other
     * instances of the same type class coerce into this type, independent of
     * any further parameters or other AST child nodes. In HILTI source code,
     * this typically corresponds to a type `T<*>`.
     */
    bool isWildcard() const { return _is_wildcard; }

    /** Returns the type's current unification string. */
    const auto& unification() const { return _unification; }

    /**
     * Attempts to set the type unification string for this type. If it can't
     * be set (yet), returns false. If it's already set, return true without
     * changing anything.
     */
    bool unify(ASTContext* ctx, const NodePtr& scope_root = nullptr);

    /**
     * Sets the type's unification string explicitly. Should normally be called
     * only by the type unifier.
     *
     * @param u unification string to set
     */
    void setUnification(type::Unification u) { _unification = std::move(u); }

    /**
     * Returns a static string that's descriptive and unique for all instances
     * of this type class. This is used to determine whether two types are of
     * the same class when comparing them for equality.
     */
    virtual std::string_view typeClass() const = 0;

    /**
     * For deferenceable types, returns the type of dereferenced elements.
     * Returns null for all other types.
     */
    virtual QualifiedTypePtr dereferencedType() const { return {}; }

    /**
     * For container types, returns the type of elements. Returns null for all
     * other types.
     */
    virtual QualifiedTypePtr elementType() const { return {}; }

    /**
     * For iterable types, returns the type of an iterator. Returns null for
     * all other types.
     */
    virtual QualifiedTypePtr iteratorType() const { return {}; }

    /** Returns any parameters the type expects on construction. */
    virtual hilti::node::Set<type::function::Parameter> parameters() const { return {}; }

    /**
     * For viewable types, returns the type of a view. Returns null for all
     * other types.
     */
    virtual QualifiedTypePtr viewType() const { return {}; }

    /** Returns true for types that can be used to instantiate variables. */
    virtual bool isAllocable() const { return false; }

    /** Returns true for types for which values can be modified after creation. */
    virtual bool isMutable() const { return false; }

    /** Returns true for types that are compared by name, not structurally. */
    virtual bool isNameType() const { return false; }

    /** Returns true for HILTI types that implement a reference to another type. */
    virtual bool isReferenceType() const { return false; }

    /** * Returns true if a type is fully resolved. */
    virtual bool isResolved() const { return true; }

    /** Returns true for HILTI types that can be compared for ordering at runtime. */
    virtual bool isSortable() const { return false; }

    /**
     * For internal use. Called when an unqualified type has been embedded into
     * a qualified type, allowing the former to adjust for constness if
     * necessary.
     *
     * @param qtype the qualified type now embedding this type
     */
    virtual void newlyQualified(const QualifiedType* qtype) const {}

    hilti::node::Properties properties() const override;

protected:
    UnqualifiedType(ASTContext* ctx, type::Unification&& u, Meta meta)
        : Node::Node(ctx, std::move(meta)), _unification(std::move(u)) {}
    UnqualifiedType(ASTContext* ctx, type::Unification&& u, Nodes children, Meta meta)
        : Node::Node(ctx, std::move(children), std::move(meta)), _unification(std::move(u)) {}
    UnqualifiedType(ASTContext* ctx, type::Wildcard _, type::Unification&& u, const Meta& meta)
        : Node::Node(ctx, {}, meta), _unification(std::move(u)), _is_wildcard(true) {}
    UnqualifiedType(ASTContext* ctx, type::Wildcard _, type::Unification&& u, Nodes children, Meta meta)
        : Node::Node(ctx, std::move(children), std::move(meta)), _unification(std::move(u)), _is_wildcard(true) {}

    /** Implements `Node` interface. */
    std::string _render() const override;

    HILTI_NODE_BASE(hilti, Type);

private:
    type::Unification _unification;                // types unification string if known yet
    bool _is_wildcard = false;                     // true if types is presenting a wildcard type
    std::weak_ptr<declaration::Type> _declaration; // type declaration associated with the type, if any
};

namespace type {

/**
 * Follows any `type::Name` reference chains to the actual, eventual type.
 *
 * Note that you will rarely need to call this function manually because
 * `QualifiedType::type()` follows type chains automatically by default. Doing
 * it that way is always preferred to calling `follow()` manually.
 *
 * @returns The eventual type found at the end of the chain. If there's not
 * `type::Name` encountered,  that's `t` itself. If a `type::Name` is
 * encountered that has not been resolved yet, returns that `type::Name` itself.
 */
extern UnqualifiedTypePtr follow(const UnqualifiedTypePtr& t);

/**
 * Follows any `type::Name` reference chains to the actual, eventual type.
 *
 * Note that you will rarely need to call this function manually because
 * `QualifiedType::type()` follows type chains automatically by default. Doing
 * it that way is always preferred to calling `follow()` manually.
 *
 * @returns The eventual type found at the end of the chain. If there's not
 * `type::Name` encountered,  that's `t` itself. If a `type::Name` is
 * encountered that has not been resolved yet, returns that `type::Name` itself.
 */
extern UnqualifiedType* follow(UnqualifiedType* t);

} // namespace type

/** Selects left-hand-side or right-hand-side semantics for an expression. */
enum class Side { LHS, RHS };

/** Selects constant or non-constant semantics for an expression. */
enum Constness { Const, NonConst };

/** AST node presenting a type along with associated constness and RHS/LHS semantics. */
class QualifiedType : public Node {
public:
    /**
     * Returns the underlying type. By default, this follows any `type::Name` references.
     *
     * @param follow if true, follows any `type::Name` references to the actual type
     */
    UnqualifiedTypePtr type(bool follow = true) const { return follow ? type::follow(_type()) : _type(); }

    /** Returns true if the qualified type is constant. */
    bool isConstant() const { return _constness == Const; }

    /** Returns the type's constness. */
    auto constness() const { return _constness; }

    /** Returns true if the underlying unqualified type is fully resolved. */
    bool isResolved() const { return type()->isResolved(); }

    /** Returns true if the type is a wildcard type. */
    bool isWildcard() const { return _type()->isWildcard(); }

    /** Returns true if the type is `auto`. */
    bool isAuto() const;

    /** Returns the type's "sideness". */
    auto side() const { return _side; }

    /**
     * Sets the constness of the type.
     *
     * @param is_const true if the type is constant
     */
    void setConst(Constness constness) { _constness = constness; }

    /** Implements `Node` interface. */
    hilti::node::Properties properties() const override;

    /**
     * Factory method.
     *
     * @param ctx context to use
     * @param t underlying type to wrap
     * @param is_constant true if the type is constant
     * @param m meta data to attach
     */
    static auto create(ASTContext* ctx, const UnqualifiedTypePtr& t, Constness const_, Meta m = Meta()) {
        auto qt = NodeDerivedPtr<QualifiedType>(new QualifiedType(ctx, Nodes{t}, const_, Side::RHS, std::move(m)));
        qt->type()->unify(ctx);
        qt->_type()->newlyQualified(qt.get());
        return qt;
    }

    /**
     * Factory method.
     *
     * @param ctx context to use
     * @param t underlying type to wrap
     * @param is_constant true if the type is constant
     * @param side the type's "sideness"
     * @param m meta data to attach
     */
    static auto create(ASTContext* ctx, const UnqualifiedTypePtr& t, Constness const_, Side side,
                       const Meta& m = Meta()) {
        auto qt = NodeDerivedPtr<QualifiedType>(new QualifiedType(ctx, Nodes{t}, const_, side, m));
        qt->type()->unify(ctx);
        qt->_type()->newlyQualified(qt.get());
        return qt;
    }

    /**
     * Factory method creating a qualified type linking directly to an already
     * existing unqualified type.
     *
     * This avoid copying the existing type over into a child, and can help to
     * breaks reference cycles.
     *
     * @param ctx context to use
     * @param t underlying type to wrap
     * @param is_constant true if the type is constant
     * @param m meta data to attach
     */
    static QualifiedTypePtr createExternal(ASTContext* ctx, const std::weak_ptr<UnqualifiedType>& t, Constness const_,
                                           const Meta& m = Meta());

    // TODO: Remove.
    static auto create(ASTContext* ctx, const UnqualifiedTypePtr& t, bool is_constant, Meta m = Meta()) {
        return create(ctx, t, is_constant ? Constness::Const : Constness::NonConst, std::move(m));
    }

    // TODO: Remove.
    static auto create(ASTContext* ctx, const UnqualifiedTypePtr& t, bool is_constant, Side side,
                       const Meta& m = Meta()) {
        return create(ctx, t, is_constant ? Constness::Const : Constness::NonConst, side, m);
    }

    // TODO: Remove.
    static auto createExternal(ASTContext* ctx, const std::weak_ptr<UnqualifiedType>& t, bool is_constant,
                               const Meta& m = Meta()) {
        return createExternal(ctx, t, is_constant ? Constness::Const : Constness::NonConst, m);
    }

    /**
     * Shortcut to create a qualified type wrapping a `type::Auto` instance.
     *
     * This sets constness to false, and sideness to RHS; both, however, should
     * normally be ignored.
     */
    static QualifiedTypePtr createAuto(ASTContext* ctx, const Meta& m = Meta());

    /**
     * Shortcut to create a qualified type wrapping a `type::Auto` instance.
     *
     * This sets constness to false, and sideness to RHS; both, however, should
     * normally be ignored.
     */
    static QualifiedTypePtr createAuto(ASTContext* ctx, Side side, const Meta& m = Meta());

    /** Factory method creating a copy of the type with "sideness" changed to LHS. */
    auto recreateAsLhs(ASTContext* ctx) const { return QualifiedType::create(ctx, _type(), false, Side::LHS); }

    /** Factory method creating a copy of the type with constness changed to constant. */
    auto recreateAsConst(ASTContext* ctx) const { return QualifiedType::create(ctx, _type(), true, Side::RHS); }

    /** Factory method creating a copy of the type with constness changed to non-constant. */
    auto recreateAsNonConst(ASTContext* ctx) const { return QualifiedType::create(ctx, _type(), false, Side::RHS); }

protected:
    friend class ASTContext;

    QualifiedType(ASTContext* ctx, Nodes children, Constness constness, Side side, Meta meta)
        : Node(ctx, std::move(children), std::move(meta)), _constness(constness), _side(side) {}

    QualifiedType(ASTContext* ctx, Nodes children, std::weak_ptr<UnqualifiedType> t, Constness constness, Side side,
                  Meta meta)
        : Node(ctx, std::move(children), std::move(meta)),
          _external_type(std::move(t)),
          _constness(constness),
          _side(side) {}


    /** Implements `Node` interface. */
    std::string _render() const final;

    HILTI_NODE(hilti, QualifiedType);

private:
    // Internal version of _type() that doesn't follow name references.
    UnqualifiedTypePtr _type() const {
        if ( _external_type && ! _external_type->expired() )
            return _external_type->lock();

        return child<UnqualifiedType>(0); // type::Unknown for external but expired type
    }

    std::optional<std::weak_ptr<UnqualifiedType>> _external_type; // for external types, the referenced type
    Constness _constness;                                         // constness
    Side _side = Side::RHS;                                       // sideness
};

namespace type {

/**
 * Returns true if a type is fully resolved. This asks the type's `isResolved`
 * handler whether it considers itself resolved.
 */
inline bool isResolved(const UnqualifiedTypePtr& t) { return t->isResolved(); }

/**
 * Returns true if a type is fully resolved. This asks the type's `isResolved`
 * handler whether it considers itself resolved.
 */
inline bool isResolved(const UnqualifiedType* t) { return t->isResolved(); }

/**
 * Returns true if a qualified type's wrapped type is fully resolved. This asks
 * the type's `isResolved` handler whether it considers itself resolved.
 */
inline bool isResolved(const QualifiedTypePtr& t) { return isResolved(t->type()); }

/**
 * Returns true if two types are semantically equal. This returns true only if
 * both types have been fully resolved already.
 */
inline bool same(const UnqualifiedTypePtr& t1, const UnqualifiedTypePtr& t2) {
    if ( ! isResolved(t1) || ! isResolved(t2) )
        return false;

    auto t1_ = follow(t1);
    auto t2_ = follow(t2);

    if ( t1_->unification() == t2_->unification() )
        return true;

    if ( (t1_->isWildcard() || t2_->isWildcard()) && t1_->typeClass() == t2_->typeClass() )
        return true;

    return false;
}

/**
 * Returns true if two types are semantically equal. This returns true only if
 * both types have been fully resolved already.
 */
inline bool same(const QualifiedTypePtr& t1, const QualifiedTypePtr& t2) {
    if ( ! isResolved(t1) || ! isResolved(t2) )
        return false;

    if ( t1->isConstant() != t2->isConstant() )
        return false;

    auto t1_ = t1->type(); // performs follow
    auto t2_ = t2->type(); // performs follow

    if ( t1_->unification() == t2_->unification() )
        return true;

    if ( (t1_->isWildcard() || t2_->isWildcard()) && t1_->typeClass() == t2_->typeClass() )
        return true;

    return false;
}

/**
 * Returns true if two types are semantically equal ignoring their constness.
 * This returns true only if both types have been fully resolved already.
 */
inline bool sameExceptForConstness(const QualifiedTypePtr& t1, const QualifiedTypePtr& t2) {
    if ( ! isResolved(t1) || ! isResolved(t2) )
        return false;

    auto t1_ = t1->type(); // performs follow
    auto t2_ = t2->type(); // performs follow

    if ( t1_->unification() == t2_->unification() )
        return true;

    if ( (t1_->isWildcard() || t2_->isWildcard()) && t1_->typeClass() == t2_->typeClass() )
        return true;

    return false;
}

} // namespace type
} // namespace hilti
