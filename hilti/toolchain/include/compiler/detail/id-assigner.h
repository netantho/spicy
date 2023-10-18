// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/forward.h>

namespace hilti::detail::id_assigner {

/**
 * Computes canonical and fully-qualified IDs for all declarations in the AST.
 *
 * @returns true if least one ID was computed that wasn't before.
 */
bool assign(Builder* builder, const ASTRootPtr& root);

/**
 * Checks that all declarations in an AST have a canonical ID calculated. This
 * is primarily for debugging, and the function will abort execution if it
 * finds a declaration without canonical ID.
 */
void debugEnforceCanonicalIDs(Builder* builder, const ASTRootPtr& root);

} // namespace hilti::detail::id_assigner
