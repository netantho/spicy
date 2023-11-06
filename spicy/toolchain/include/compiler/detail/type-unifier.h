// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>

#include <hilti/compiler/detail/type-unifier.h>

#include <spicy/ast/forward.h>

namespace spicy::type_unifier::detail {

bool unifyType(hilti::type_unifier::Unifier* unifier, NodePtr& node);

}
