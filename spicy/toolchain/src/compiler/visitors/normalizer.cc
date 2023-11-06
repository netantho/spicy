// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/declarations/imported-module.h>
#include <hilti/ast/declarations/type.h>
#include <hilti/ast/scope-lookup.h>
#include <hilti/base/logger.h>
#include <hilti/compiler/context.h>
#include <hilti/compiler/plugin.h>

#include <spicy/ast/declarations/unit-hook.h>
#include <spicy/ast/detail/visitor.h>
#include <spicy/compiler/detail/visitors.h>

using namespace spicy;

namespace hilti::logging::debug {
inline const hilti::logging::DebugStream Normalizer("normalizer");
} // namespace hilti::logging::debug

namespace {

struct Visitor : public visitor::PostOrder<void, Visitor> {
    explicit Visitor(Node* root) : root(root) {}
    Node* root;
    bool modified = false;

    // Log debug message recording resolving a expression.
    void logChange(const Node& old, const ExpressionPtr& nexpr) {
        HILTI_DEBUG(hilti::logging::debug::Normalizer,
                    hilti::util::fmt("[%s] %s -> expression %s (%s)", old.typename_(), old, nexpr, old.location()));
    }

    // Log debug message recording resolving a statement.
    void logChange(const Node& old, const StatementPtr& nstmt) {
        HILTI_DEBUG(hilti::logging::debug::Normalizer,
                    hilti::util::fmt("[%s] %s -> statement %s (%s)", old.typename_(), old, nstmt, old.location()));
    }

    // Log debug message recording resolving a type.
    void logChange(const Node& old, const QualifiedTypePtr& ntype, const char* msg = "type") {
        HILTI_DEBUG(hilti::logging::debug::Normalizer,
                    hilti::util::fmt("[%s] %s -> %s %s (%s)", old.typename_(), old, msg, ntype, old.location()));
    }

    void logChange(const Node& old, const std::string_view msg) {
        HILTI_DEBUG(hilti::logging::debug::Normalizer,
                    hilti::util::fmt("[%s] %s -> %s (%s)", old.typename_(), old, msg, old.location()));
    }

    // Log debug message recording resolving a unit item.
    void logChange(const Node& old, const type::unit::Item& i) {
        HILTI_DEBUG(hilti::logging::debug::Normalizer,
                    hilti::util::fmt("[%s] %s -> %s (%s)", old.typename_(), old, i, old.location()));
    }
};

} // anonymous namespace

bool spicy::detail::ast::normalize(const std::shared_ptr<hilti::Context>& ctx, hilti::Node* root, hilti::Unit* unit) {
    bool hilti_modified = (*hilti::plugin::registry().hiltiPlugin().ast_normalize)(ctx, root, unit);

    hilti::util::timing::Collector _("spicy/compiler/normalizer");

    auto v = Visitor(root);
    for ( auto i : v.walk(root) )
        v.dispatch(i);

    return v.modified || hilti_modified;
}
