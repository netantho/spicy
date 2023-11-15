// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <spicy/compiler/detail/codegen/production.h>
#include <spicy/compiler/detail/codegen/productions/look-ahead.h>

using namespace spicy;
using namespace spicy::detail;

static std::string _fmtAlt(const codegen::Production* alt, const std::set<codegen::Production*>& lahs) {
    auto fmt = [&](const auto& lah) {
        if ( lah->isLiteral() )
            return hilti::util::fmt("%s (id %" PRId64 ")", to_string(*lah), lah->tokenID());

        return hilti::util::fmt("%s (not a literal)", to_string(*lah));
    };

    return hilti::util::fmt("{%s}: %s", hilti::util::join(hilti::util::transform(lahs, fmt), ", "), alt->symbol());
}

std::string codegen::production::LookAhead::render() const {
    return _fmtAlt(_alternatives.first.get(), _lahs.first) + " | " + _fmtAlt(_alternatives.second.get(), _lahs.second);
}
