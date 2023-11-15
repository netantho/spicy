// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/forward.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/integer.h>

namespace hilti::type {

namespace stream {

/** AST node for a stream iterator type. */
class Iterator : public UnqualifiedType {
public:
    std::string_view typeClass() const final { return "iterator<stream>"; }
    QualifiedTypePtr dereferencedType() const final { return child<QualifiedType>(0); }

    bool isAllocable() const final { return true; }
    bool isMutable() const final { return true; }

    static auto create(ASTContext* ctx, const Meta& meta = {}) {
        auto etype = QualifiedType::create(ctx, type::UnsignedInteger::create(ctx, 8, meta), true, meta);
        return NodeDerivedPtr<Iterator>(new Iterator(ctx, {etype}, meta));
    }

protected:
    Iterator(ASTContext* ctx, Nodes children, Meta meta)
        : UnqualifiedType(ctx, {"iterator(stream)"}, std::move(children), std::move(meta)) {}

    HILTI_NODE(hilti, Iterator)
};

/** AST node for a stream view type. */
class View : public UnqualifiedType {
public:
    std::string_view typeClass() const final { return "view::stream"; }

    bool isAllocable() const final { return true; }
    bool isMutable() const final { return true; }

    QualifiedTypePtr elementType() const final { return iteratorType()->type()->dereferencedType(); }
    QualifiedTypePtr iteratorType() const final { return child<QualifiedType>(0); }

    static auto create(ASTContext* ctx, const Meta& meta = {}) {
        return NodeDerivedPtr<View>(
            new View(ctx, {QualifiedType::create(ctx, Iterator::create(ctx, meta), true)}, meta));
    }

protected:
    View(ASTContext* ctx, Nodes children, Meta meta)
        : UnqualifiedType(ctx, {"view::stream"}, std::move(children), std::move(meta)) {}

    HILTI_NODE(hilti, View)
};

} // namespace stream

/** AST node for a `stream` type. */
class Stream : public UnqualifiedType {
public:
    std::string_view typeClass() const final { return "stream"; }

    bool isAllocable() const final { return true; }
    bool isMutable() const final { return true; }
    bool isSortable() const final { return true; }

    QualifiedTypePtr elementType() const final { return iteratorType()->type()->dereferencedType(); }
    QualifiedTypePtr iteratorType() const final { return viewType()->type()->iteratorType(); }
    QualifiedTypePtr viewType() const final { return child<QualifiedType>(0); }

    static auto create(ASTContext* ctx, const Meta& meta = {}) {
        return NodeDerivedPtr<Stream>(
            new Stream(ctx, {QualifiedType::create(ctx, stream::View::create(ctx, meta), false)}, meta));
    }

protected:
    Stream(ASTContext* ctx, Nodes children, Meta meta)
        : UnqualifiedType(ctx, {"stream"}, std::move(children), std::move(meta)) {}

    void newlyQualified(const QualifiedType* qtype) const final { elementType()->setConst(qtype->constness()); }

    HILTI_NODE(hilti, Stream)
};

} // namespace hilti::type
