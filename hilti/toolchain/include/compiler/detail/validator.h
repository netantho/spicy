// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/forward.h>

namespace hilti::detail::validator {

/** Implements the corresponding functionality for the default HILTI compiler plugin. */
void validate_pre(Builder* builder, const ASTRootPtr& root);

/** Implements the corresponding functionality for the default HILTI compiler plugin. */
void validate_post(Builder* builder, const ASTRootPtr& root);

} // namespace hilti::detail::validator
