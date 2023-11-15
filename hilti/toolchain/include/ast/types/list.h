// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/type.h>
#include <hilti/ast/types/unknown.h>

namespace hilti::type {

namespace list {

/** AST node for a list iterator type. */
class Iterator : public UnqualifiedType {
public:
    std::string_view typeClass() const final { return "iterator<list>"; }

    QualifiedTypePtr dereferencedType() const final { return child<QualifiedType>(0); }

    bool isAllocable() const final { return true; }
    bool isMutable() const final { return true; }
    bool isResolved() const final { return dereferencedType()->isResolved(); }

    static auto create(ASTContext* ctx, const QualifiedTypePtr& etype, Meta meta = {}) {
        return NodeDerivedPtr<Iterator>(new Iterator(ctx, {etype}, std::move(meta)));
    }

    static auto create(ASTContext* ctx, Wildcard _, const Meta& m = Meta()) {
        return NodeDerivedPtr<Iterator>(
            new Iterator(ctx, Wildcard(), {QualifiedType::create(ctx, type::Unknown::create(ctx, m), true)}, m));
    }

protected:
    Iterator(ASTContext* ctx, Nodes children, Meta meta)
        : UnqualifiedType(ctx, {}, std::move(children), std::move(meta)) {}
    Iterator(ASTContext* ctx, Wildcard _, const Nodes& children, const Meta& meta)
        : UnqualifiedType(ctx, Wildcard(), {"iterator(list(*))"}, children, meta) {}


    HILTI_NODE(hilti, Iterator)
};

} // namespace list

/** AST node for a `list` type. */
class List : public UnqualifiedType {
public:
    std::string_view typeClass() const final { return "list"; }

    QualifiedTypePtr elementType() const final { return iteratorType()->type()->dereferencedType(); }
    QualifiedTypePtr iteratorType() const final { return child<QualifiedType>(0); }

    bool isAllocable() const final { return true; }
    bool isMutable() const final { return true; }
    bool isResolved() const final { return iteratorType()->isResolved(); }

    static auto create(ASTContext* ctx, const QualifiedTypePtr& t, const Meta& meta = {}) {
        return NodeDerivedPtr<List>(
            new List(ctx, {QualifiedType::create(ctx, list::Iterator::create(ctx, t, meta), false)}, meta));
    }

    static auto create(ASTContext* ctx, Wildcard _, const Meta& m = Meta()) {
        return NodeDerivedPtr<List>(
            new List(ctx, Wildcard(), {QualifiedType::create(ctx, list::Iterator::create(ctx, Wildcard(), m), false)},
                     m));
    }

protected:
    List(ASTContext* ctx, Nodes children, Meta meta) : UnqualifiedType(ctx, {}, std::move(children), std::move(meta)) {}
    List(ASTContext* ctx, Wildcard _, const Nodes& children, const Meta& meta)
        : UnqualifiedType(ctx, Wildcard(), {"list(*)"}, children, meta) {}

    void newlyQualified(const QualifiedType* qtype) const final { elementType()->setConst(qtype->constness()); }

    HILTI_NODE(hilti, List)
};

} // namespace hilti::type
