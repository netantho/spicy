// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>

#include <hilti/ast/forward.h>

// TODO: This should move out of detail/.
namespace hilti::type_unifier {

/**
 * Unifies all the unqualified types in the AST to the degree possible.
 *
 * @returns true if at least one type was unified that wasn't before.
 */
bool unify(Builder* builder, const ASTRootPtr& root);

/**
 * Unifies all the unqualified type, if possible. If it's already unified, no
 * change will be made.
 *
 * @returns true if either the type is now unified, either because it was
 * already or because it could be unified now.
 */
bool unify(ASTContext* ctx, const UnqualifiedTypePtr& type);

/** API class for implementing type unification for custom types by plugins. */
class Unifier {
public:
    void add(UnqualifiedType* t);
    void add(const QualifiedTypePtr& t);
    void add(const std::string& s);

    void abort() { _abort = true; }
    auto isAborted() const { return _abort; }

    const auto& serialization() const { return _serial; }

    void reset() {
        _serial.clear();
        _abort = false;
    }

protected:
    std::string _serial; // builds up serialization incrementally
    bool _abort = false; // if true, cannot compute serialization yet
};

namespace detail {
bool unifyType(type_unifier::Unifier* unifier, NodePtr& node);
}

} // namespace hilti::type_unifier
