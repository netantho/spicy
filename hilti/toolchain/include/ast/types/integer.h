// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>
#include <vector>

#include <hilti/ast/type.h>

namespace hilti::type {

namespace detail {

/** Common base class for an AST node representing an integer type. */
class IntegerBase : public UnqualifiedType {
public:
    auto width() const { return _width; }

    bool isAllocable() const final { return true; }
    bool isSortable() const final { return true; }

    node::Properties properties() const final {
        auto p = node::Properties{{"width", _width}};
        return UnqualifiedType::properties() + p;
    }

protected:
    IntegerBase(ASTContext* ctx, type::Unification u, Nodes children, unsigned int width, const Meta& m = Meta())
        : UnqualifiedType(ctx, std::move(u), std::move(children), m), _width(width) {}
    IntegerBase(ASTContext* ctx, Wildcard _, type::Unification u, const Meta& m = Meta())
        : UnqualifiedType(ctx, Wildcard(), std::move(u), m) {}

private:
    unsigned int _width = 0;
};

} // namespace detail

/** AST node for a signed integer type. */
class SignedInteger : public detail::IntegerBase {
public:
    std::string_view typeClass() const final { return "int"; }

    static NodeDerivedPtr<SignedInteger> create(ASTContext* ctx, unsigned int width, const Meta& m = Meta());

    static auto create(ASTContext* ctx, Wildcard _, const Meta& m = Meta()) {
        return NodeDerivedPtr<SignedInteger>(new SignedInteger(ctx, Wildcard(), m));
    }

protected:
    SignedInteger(ASTContext* ctx, const Nodes& children, unsigned int width, const Meta& m = Meta())
        : IntegerBase(ctx, {util::fmt("int%" PRIu64, width)}, children, width, m) {}
    SignedInteger(ASTContext* ctx, Wildcard _, const Meta& m = Meta()) : IntegerBase(ctx, Wildcard(), {"int<*>"}, m) {}

    HILTI_NODE(SignedInteger)
};

/** AST node for an unsigned integer type. */
class UnsignedInteger : public detail::IntegerBase {
public:
    std::string_view typeClass() const final { return "uint"; }

    static NodeDerivedPtr<UnsignedInteger> create(ASTContext* ctx, unsigned int width, const Meta& m = Meta());

    static auto create(ASTContext* ctx, Wildcard _, const Meta& m = Meta()) {
        return NodeDerivedPtr<UnsignedInteger>(new UnsignedInteger(ctx, Wildcard(), m));
    }

protected:
    UnsignedInteger(ASTContext* ctx, const Nodes& children, unsigned int width, const Meta& m = Meta())
        : IntegerBase(ctx, {util::fmt("uint%" PRIu64, width)}, children, width, m) {}
    UnsignedInteger(ASTContext* ctx, Wildcard _, const Meta& m = Meta())
        : IntegerBase(ctx, Wildcard(), {"uint<*>"}, m) {}

    HILTI_NODE(UnsignedInteger);
};

} // namespace hilti::type
