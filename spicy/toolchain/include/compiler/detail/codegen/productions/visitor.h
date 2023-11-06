// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <utility>
#include <vector>

#include <spicy/compiler/detail/codegen/production.h>
#include <spicy/compiler/detail/codegen/productions/visitor.h>

namespace spicy::detail::codegen::production {

class Boolean;
class ByteBlock;
class Counter;
class Ctor;
class Enclosure;
class Epsilon;
class ForEach;
class LookAhead;
class Reference;
class Resolved;
class Sequence;
class Skip;
class Switch;
class TypeLiteral;
class Unit;
class Variable;
class While;

/** * Generic production visitor. */
class Visitor {
public:
    Visitor() = default;
    virtual ~Visitor() = default;

    /** Execute matching dispatch methods for a single production.  */
    void dispatch(const Production* n) {
        if ( n )
            n->dispatch(*this);
    }

    void dispatch(const Production& n) { n.dispatch(*this); }

    virtual void operator()(const Boolean*) {}
    virtual void operator()(const ByteBlock*) {}
    virtual void operator()(const Counter*) {}
    virtual void operator()(const Ctor*) {}
    virtual void operator()(const Enclosure*) {}
    virtual void operator()(const Epsilon*) {}
    virtual void operator()(const ForEach*) {}
    virtual void operator()(const LookAhead*) {}
    virtual void operator()(const Reference*) {}
    virtual void operator()(const Resolved*) {}
    virtual void operator()(const Sequence*) {}
    virtual void operator()(const Skip*) {}
    virtual void operator()(const Switch*) {}
    virtual void operator()(const TypeLiteral*) {}
    virtual void operator()(const Unit*) {}
    virtual void operator()(const Variable*) {}
    virtual void operator()(const While*) {}
};
} // namespace spicy::detail::codegen::production
