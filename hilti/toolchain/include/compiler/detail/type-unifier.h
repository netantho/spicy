// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/forward.h>

namespace hilti::detail::type_unifier {

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

} // namespace hilti::detail::type_unifier
