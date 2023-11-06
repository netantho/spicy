// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/base/logger.h>
#include <hilti/base/timing.h>
#include <hilti/compiler/plugin.h>

#include <spicy/ast/forward.h>
#include <spicy/ast/types/unit-items/field.h>
#include <spicy/ast/types/unit.h>
#include <spicy/ast/visitor.h>
#include <spicy/compiler/detail/printer.h>

using namespace spicy;

namespace {

struct Visitor : visitor::PreOrder {
    Visitor(hilti::detail::printer::Stream& out) : out(out) {}

    hilti::detail::printer::Stream& out;

    bool result = false;

    void operator()(type::Sink* n) final { out << "sink"; }

    void operator()(type::Unit* n) final {
        if ( n->isWildcard() )
            out << "unit<*>";
        else {
            out << "unit { XXX } ";
        }
    }

    void operator()(type::unit::item::Field* n) final { out << n->id(); }
};

} // anonymous namespace

bool spicy::detail::printer::print(hilti::detail::printer::Stream& stream, const NodePtr& root) {
    hilti::util::timing::Collector _("spicy/printer");

    return visitor::dispatch(Visitor(stream), root, [](const auto& v) { return v.result; });
}
