// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <cassert>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <spicy/ast/forward.h>
#include <spicy/ast/types/unit-items/field.h>

#define SPICY_PRODUCTION                                                                                               \
    std::string typename_() const final { return hilti::util::typename_(*this); }                                      \
    void dispatch(production::Visitor& v) const final { v(this); }

#if 0
    bool isAtomic() const final { return X; };
    bool isEodOk() const final { return X; };
    bool isLiteral() const final { return X; };
    bool isNullable() const final { return X; };
    bool isTerminal() const final { return X; };

    // std::vector<std::vector<Production*>> rhss() const final { return {}; };
    // ExpressionPtr expression() const final { return nullptr; }
    // QualifiedTypePtr type() const final { return nullptr; };
    // int64_t tokenID() const  final{ return -1; };

    std::string render() const final { return X; };

#endif


namespace spicy::detail::codegen {

class Production;
using ProductionPtr = std::shared_ptr<Production>;

using Location = hilti::Location;
namespace location {
inline const auto& None = hilti::location::None;
}

/**
 * Returns a readable representation of a production for diagnostics.
 */
extern std::string to_string(const Production& p);

namespace production {

class Visitor;
class Reference;

/* Meta data that the parser builder associates with a production. */
class Meta {
public:
    /** Returns a unit field associated with the production, if set. */
    auto field() const { return _field; }

    /**
     * Returns true if there's a field associated with this production, and
     * the production is the top-level entry point for parsing that field
     * (vs. being a nested production further down in the parse tree).
     */
    bool isFieldProduction() const { return _field && _is_field_production; }

    /**
     * If this production corresponds to a container's item field, this
     * returns the container (once set).
     */
    auto container() const { return _container; }

    /*
     * #<{(|*
     *  * If the production corresponds to a for-each hook, this returns the
     *  * corresponding field (once set).
     *  |)}>#
     * auto forEach() const { return _for_each; }
     */

    void setField(const type::unit::item::FieldPtr& n, bool is_field_production) {
        assert(n);
        _is_field_production = is_field_production;
        _field = n;
    }

    void setContainer(const type::unit::item::FieldPtr& n) {
        assert(n);
        _container = n;
    }

    /*
     * void setForEach(const NodeRef& n) {
     *     assert(n);
     *     _for_each = n;
     * }
     */

    bool _is_field_production = false;
    type::unit::item::FieldPtr _field;
    type::unit::item::FieldPtr _container;
    // NodeRef _for_each;
};

} // namespace production

/** * Base class for a single production inside a grammar. */
class Production {
public:
    /**
     * Constructor.
     *
     * @param symbol symbol associated with the production; the symbol must
     *               be unique within the grammar the production is (or will
     *               be) part of (unless it's empty).
     * @param m meta data associated with the
     * @param l location associated with the production
     */
    Production(std::string symbol, hilti::Location l = hilti::location::None)
        : _symbol(std::move(symbol)), _location(std::move(l)), _meta(new production::Meta()) {}

    /** Destructor. */
    virtual ~Production() {}

    /**
     * Returns the location associated with the production, or Location::None
     * if none.
     */
    const auto& location() const { return _location; }

    /**
     * Returns access to the production meta data. The meta data is filled as
     * grammar and parser are being built.
     */
    const auto& meta() const { return *_meta; }

    /** For terminals, returns the filter function associated with it, if any. */
    auto filter() const { return _filter; }

    /** * For terminals, returns the sink associated with it, if any. */
    auto sink() const { return _sink; }

    /** Returns the symbol associated with the production. */
    const auto& symbol() const { return _symbol; }

    /**
     * For terminals, associates a filter function with it. The filter function
     * will be called when a value has been parsed for the terminal. It must
     * return a value to use instead of the parsed value.
     */
    void setFilter(ExpressionPtr filter) { _filter = std::move(filter); }

    /**
     * Sets the production meta data. The meta data is filled as
     * grammar and parser are being built.
     */
    void setMeta(production::Meta m) { *_meta = std::move(m); }

    /**
     * For terminals, associates a sink with it. Any parsed data will be
     * forwarded to the sink.
     */
    void setSink(ExpressionPtr sink) { _sink = std::move(sink); }

    /** Renames the production. */
    void setSymbol(std::string s) { _symbol = std::move(s); }

    /**
     * Returns a readable representation of the production for diagnostics.
     */
    explicit operator std::string() const { return to_string(*this); }

    // TODO: Can we get rid of the following two internal methods?

    /**
     * Returns the internal meta instance the production is using. For
     * internal infrastructure use only.
     */
    std::shared_ptr<production::Meta> _metaInstance() const { return _meta; }

    /**
     * Sets the internal meta instance the production is using. For internal
     * infrastructure use only.
     */
    void _setMetaInstance(std::shared_ptr<production::Meta> m) { _meta = std::move(m); }

    /**
     * Returns true if this production does not recursively contain other
     * productions.
     */
    virtual bool isAtomic() const = 0;

    /**
     * Returns true if running out of data while parsing this production
     * should not be considered an error.
     */
    virtual bool isEodOk() const = 0;

    /** Returns true if the production represents a literal. */
    virtual bool isLiteral() const = 0;

    /**
     * Returns true if it's possible to derive the production to an Epsilon
     * production. Note that it doesn't *always* need to do so, just one
     * possible derivation is sufficient.
     */
    virtual bool isNullable() const = 0;

    /** Returns true if the production represents a terminal. */
    virtual bool isTerminal() const = 0;

    /**
     * Returns a list of RHS alternatives for this production. Each RHS is
     * itself a list of Production instances.
     */
    virtual std::vector<std::vector<Production*>> rhss() const { return {}; };

    /**
     * For literals, returns the expression associated with it.
     */
    virtual ExpressionPtr expression() const { return nullptr; }

    /** Returns any type associated with this production. */
    virtual QualifiedTypePtr type() const { return nullptr; };

    /**
     * Returns a ID for this literal that's guaranteed to be globally unique
     * for the literal's value, including across grammars. Returns a negative
     * if called for a non-literal.
     */
    virtual int64_t tokenID() const { return -1; };

    virtual std::string typename_() const = 0;

    /** Returns true if a particular is of a particular type (class). */
    template<typename T>
    bool isA() const {
        return dynamic_cast<const T*>(this) != nullptr;
    }

    /**
     * Attempts to casts a production not a particular class. Returns a nullptr
     * if the cast failed.
     */
    template<typename T>
    const auto* tryAs() const {
        return dynamic_cast<const T*>(this);
    }

    /**
     * Attempts to casts a production not a particular class. Returns a nullptr
     * if the cast failed.
     */
    template<typename T>
    auto* tryAs() {
        return dynamic_cast<T*>(this);
    }

    /**
     * Casts a production into a particular class. The cast must be a valid C++
     * dynamic pointer cast, otherwise execution will abort with an internal error.
     */
    template<typename T>
    const auto* as() const {
        if ( auto p = dynamic_cast<const T*>(this) )
            return p;

        std::cerr << hilti::util::fmt("internal error: unexpected production, want %s but have %s",
                                      hilti::util::typename_<T>(), hilti::util::typename_((this)))
                  << std::endl;

        hilti::util::abort_with_backtrace();
    }

    /**
     * Casts a production into a particular class. The cast must be a valid C++
     * dynamic pointer cast, otherwise execution will abort with an internal error.
     */
    template<typename T>
    auto* as() {
        if ( auto p = dynamic_cast<T*>(this) )
            return p;

        std::cerr << hilti::util::fmt("internal error: unexpected production, want %s but have %s",
                                      hilti::util::typename_<T>(), hilti::util::typename_((this)))
                  << std::endl;

        hilti::util::abort_with_backtrace();
    }

protected:
    friend class production::Visitor;
    friend class production::Reference;
    friend std::string to_string(const Production& p);

    /**
     * Helper returning a unique (and stable) token ID for a given string
     * representation of a production. Can be used by implementations of the
     * main, virtual `tokenID()` method.
     */
    static uint64_t tokenID(const std::string& p);

    /**
     * Returns a readable representation of the production, suitable to include
     * in error message and debugging output. This should usually not be called
     * directly; convert the production into a string instead, which will
     * incorporate the output of this method, but may augment it further.
     */
    virtual std::string render() const = 0;

    virtual void dispatch(production::Visitor& v) const = 0;

private:
    std::string _symbol;
    Location _location;
    ExpressionPtr _filter;
    ExpressionPtr _sink;
    std::shared_ptr<production::Meta> _meta;
};

namespace production {
/**
 * Returns if inside a list of production list, at least one is nullable.
 * Also returns true if the list of lists is empty to begin with.
 */
extern bool isNullable(const std::vector<std::vector<Production*>>& rhss);
} // namespace production

/** Renders a production for diagnostics. */
inline std::ostream& operator<<(std::ostream& out, const Production& p) {
    out << to_string(p);
    return out;
}

/** Returns true if the two production's symbols match. */
inline bool operator==(const Production& p1, const Production& p2) {
    if ( &p1 == &p2 )
        return true;

    return p1.symbol() == p2.symbol();
}

/** Sorts by the productions' symbols. */
inline bool operator<(const Production& p1, const Production& p2) { return p1.symbol() < p2.symbol(); }

} // namespace spicy::detail::codegen
