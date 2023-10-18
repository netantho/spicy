// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <utility>
#include <vector>

#include <hilti/ast/node.h>
#include <hilti/ast/visitor-dispatcher.h>
#include <hilti/base/logger.h>

namespace hilti {

namespace detail::visitor {

enum class Order { Pre, Post };

/** Iterator traversing all nodes of an AST. */
template<Order order>
class Iterator {
public:
    using value_type = NodePtr;

    Iterator() = default;
    Iterator(const NodePtr& root, bool include_empty = false) : _include_empty(include_empty) {
        if ( root )
            _path.emplace_back(root, -1);
    }

    Iterator(const Iterator& other) = default;
    Iterator(Iterator&& other) noexcept = default;

    ~Iterator() = default;

    auto depth() const { return _path.size(); }

    Iterator& operator++() {
        next();
        return *this;
    }

    NodePtr operator*() const { return current(); }

    Iterator& operator=(const Iterator& other) = default;
    Iterator& operator=(Iterator&& other) noexcept = default;
    bool operator==(const Iterator& other) const { return _path == other._path; }
    bool operator!=(const Iterator& other) const { return ! (*this == other); }

private:
    struct Location {
        NodePtr node;
        int child = -2;

        Location(NodePtr n, int c) : node(std::move(n)), child(c) {}
        auto operator==(const Location& other) const {
            return std::pair(node, child) == std::pair(other.node, other.child);
        }
    };

    NodePtr current() const {
        if ( _path.empty() )
            throw std::runtime_error("invalid reference of visitor's iterator");

        auto& p = _path.back();

        if ( ! p.node )
            return nullptr;

        if ( p.child < 0 ) {
            assert(order == Order::Pre);
            return p.node;
        }

        if ( p.child == static_cast<int>(p.node->children().size()) ) {
            assert(order == Order::Post);
            return p.node;
        }

        assert(p.child < static_cast<int>(p.node->children().size()));
        return p.node->children()[p.child];
    }

    void next() {
        if ( _path.empty() )
            return;

        auto& p = _path.back();
        p.child += 1;

        if ( p.child == -1 ) {
            if ( order == Order::Pre )
                return;

            next();
            return;
        }

        if ( ! p.node ) {
            _path.pop_back();
            next();
            return;
        }

        assert(p.child >= 0);

        if ( p.child < static_cast<int>(p.node->children().size()) ) {
            if ( auto child = p.node->children()[p.child]; child || _include_empty ) // don't visit null children
                _path.emplace_back(child, -2);

            next();
            return;
        }

        if ( p.child == static_cast<int>(p.node->children().size()) ) {
            if constexpr ( order == Order::Post )
                return;

            p.child += 1;
        }

        if ( p.child > static_cast<int>(p.node->children().size()) ) {
            _path.pop_back();
            next();
            return;
        }
    }

    std::vector<Location> _path;
    bool _include_empty = false;
};

/** Range of AST nodes for traversal. */
template<Order order>
class Range {
public:
    using iterator_t = Iterator<order>;
    using value_type = typename Iterator<order>::value_type;
    Range(NodePtr root) : _root(std::move(root)) {}

    auto begin(bool include_empty = false) {
        if constexpr ( order == Order::Pre )
            return iterator_t(_root, include_empty);

        return ++iterator_t(_root, include_empty);
    }

    auto end() { return iterator_t(); }

private:
    NodePtr _root;
};

/**
 * Generic AST visitor.
 *
 * @tparam order order of iteration
 */
template<Order order>
class Visitor : public ::hilti::visitor::Dispatcher {
public:
    using base_t = Visitor<order>;
    using iterator_t = Iterator<order>;
    static const Order order_ = order;

    Visitor() = default;
    virtual ~Visitor() = default;

    /** Execute matching dispatch methods for a single node.  */
    void dispatch(const NodePtr& n) {
        if ( n )
            n->dispatch(*this);
    }

    /** Return a range that iterates over AST, returning each node successively. */
    auto walk(const NodePtr& root) { return Range<order>(root); }
};

/**
 * Mix-in for an AST visitor that modifies the AST. This brings in some
 * additional helpers for modifying the AST.
 *
 * @param builder builder to use for modifications
 * @param dbg debug stream to log modifications to
 * @tparam order order of iteration
 */
class MutatingVisitorBase {
public:
    /**
     * Constructor.
     *
     * @param ctx AST context the nodes are part of.
     * @param dbg debug stream to log modifications to
     */
    MutatingVisitorBase(ASTContext* ctx, logging::DebugStream dbg);

    /**
     * Constructor.
     *
     * @param builder builder to use for modifications
     * @param dbg debug stream to log modifications to
     */
    MutatingVisitorBase(Builder* builder, logging::DebugStream dbg);

    /** Returns the AST context the nodes are part of. */
    auto context() const { return _context; }

    /**
     * Returns a builder for modifications. This will be valid only if the
     * corresponding constructor was used; and return null otherwise.
     */
    auto builder() const {
        assert(_builder);
        return _builder;
    }

    /**
     * Returns true, if any modifications of the AST have been performed, or
     * registered, by this visitor.
     */
    auto isModified() const { return _modified; }

    /** Clears the flag recording that modifications have taken place. */
    auto clearModified() { _modified = false; }

    /**
     * Replace a child node with a new node. This also logs a corresponding
     * debug message to the stream passed to the constructor.
     *
     * @param old child node to replace
     * @param new_ new node to replace it with
     * @param msg optional, additional debug message to add to log message
     */
    void replaceNode(const Node* old, const NodePtr& new_, const std::string& msg = "");

    /**
     * Records that an AST change has been performed.
     *
     * @param old node that was modified.
     * @param msg debug message describing the change
     */
    void recordChange(const Node* old, const std::string& msg);

    /**
     * Records that an AST change has been performed.
     *
     * @param old node that was modified.
     * @param changed node reflecting the change; it'll be rendered into the debug message, but not otherwise used
     * @param msg message being added to debug log message
     */
    void recordChange(const Node* old, const NodePtr& changed, const std::string& msg = "");

private:
    ASTContext* _context;
    Builder* _builder; // may be null if not passed to constructor
    logging::DebugStream _dbg;

    bool _modified = false;
};

template<Order order>
class MutatingVisitor : public Visitor<order>, public MutatingVisitorBase {
    using detail::visitor::MutatingVisitorBase::MutatingVisitorBase;
};

} // namespace detail::visitor

/**
 * Visitor performing a pre-order iteration over an AST.
 */
namespace visitor {
using PreOrder = detail::visitor::Visitor<detail::visitor::Order::Pre>;

/**
 * Mutating visitor performing a pre-order iteration over an AST.
 */
using MutatingPreOrder = detail::visitor::MutatingVisitor<detail::visitor::Order::Pre>;

/**
 * Iterator range traversing an AST in pre-order.
 */
using RangePreOrder = detail::visitor::Range<detail::visitor::Order::Pre>;

/**
 * Visitor performing a post-order iteration over an AST.
 */
using PostOrder = detail::visitor::Visitor<detail::visitor::Order::Post>;

/**
 * Mutating visitor performing a post-order iteration over an AST.
 */
using MutatingPostOrder = detail::visitor::MutatingVisitor<detail::visitor::Order::Post>;

/**
 * Iterator range traversing an AST in post-order.
 */
using RangePostOrder = detail::visitor::Range<detail::visitor::Order::Post>;

/** Walk the AST recursively and call dispatch for each node. */
template<typename Visitor, typename NodePtr>
auto visit(Visitor&& visitor, NodePtr& root) {
    for ( auto i : visitor.walk(root) )
        visitor.dispatch(i);
}

/** Walks the AST recursively and calls dispatch for each node, then runs callback and returns its result. */
template<typename Visitor, typename NodePtr, typename ResultFunc>
auto visit(Visitor&& visitor, NodePtr& root, ResultFunc result) {
    for ( auto i : visitor.walk(root) )
        visitor.dispatch(i);

    return result(visitor);
}

/** Dispatches a visitor for a single node. */
template<typename Visitor>
void dispatch(Visitor&& visitor, const NodePtr& n) {
    n->dispatch(visitor);
}

/** Dispatches a visitor for a single node, then runs a callback and returns its result. */
template<typename Visitor, typename ResultFunc>
auto dispatch(Visitor&& visitor, const NodePtr& node, ResultFunc result) {
    node->dispatch(visitor);
    return result(visitor);
}

} // namespace visitor
} // namespace hilti
