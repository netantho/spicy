// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <spicy/ast/forward.h>

namespace spicy::detail::validator {

/** Implements the corresponding functionality for the default HILTI compiler plugin. */
void validate_pre(Builder* builder, const ASTRootPtr& root);

/** Implements the corresponding functionality for the default HILTI compiler plugin. */
void validate_post(Builder* builder, const ASTRootPtr& root);

} // namespace spicy::detail::validator
