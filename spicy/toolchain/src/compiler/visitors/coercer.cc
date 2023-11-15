// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/attribute.h>
#include <hilti/ast/type.h>
#include <hilti/base/logger.h>
#include <hilti/compiler/context.h>
#include <hilti/compiler/plugin.h>

#include <spicy/ast/detail/visitor.h>
#include <spicy/compiler/detail/visitors.h>

using namespace hilti;
using namespace hilti::operator_;

namespace hilti::logging::debug {
inline const hilti::logging::DebugStream Coercer("coercer");
} // namespace hilti::logging::debug

namespace {

struct Visitor : public visitor::PreOrder<void, Visitor> {
    Visitor(Unit* unit) : unit(unit) {}
    Unit* unit;
    bool modified = false;

    // Log debug message recording updating attributes.
    void logChange(const Node& old, const Node& new_, const char* desc) {
        HILTI_DEBUG(logging::debug::Coercer,
                    util::fmt("[%s] %s -> %s %s (%s)", old.typename_(), old, desc, new_, old.location()));
    }
};

} // anonymous namespace

bool spicy::detail::ast::coerce(const std::shared_ptr<hilti::Context>& ctx, Node* root, Unit* unit) {
    bool hilti_modified = (*hilti::plugin::registry().hiltiPlugin().ast_coerce)(ctx, root, unit);

    hilti::util::timing::Collector _("spicy/compiler/coercer");

    auto v = Visitor(unit);
    for ( auto i : v.walk(root) )
        v.dispatch(i);

    return v.modified || hilti_modified;
}
