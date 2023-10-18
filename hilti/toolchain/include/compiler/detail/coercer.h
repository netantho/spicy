// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <utility>

#include <hilti/rt/3rdparty/ArticleEnumClass-v2/EnumClass.h>

#include <hilti/ast/ctor.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/operator.h>
#include <hilti/ast/type.h>
#include <hilti/base/util.h>
#include <hilti/compiler/coercer.h>

namespace hilti::detail::coercer {

/** Implements the corresponding functionality for the default HILTI compiler plugin. */
CtorPtr coerceCtor(Builder* builder, const CtorPtr& c, const QualifiedTypePtr& dst, bitmask<CoercionStyle> style);

/** Implements the corresponding functionality for the default HILTI compiler plugin. */
QualifiedTypePtr coerceType(Builder* builder, const QualifiedTypePtr& t, const QualifiedTypePtr& dst,
                            bitmask<CoercionStyle> style);

} // namespace hilti::detail::coercer
