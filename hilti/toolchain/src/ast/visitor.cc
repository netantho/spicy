// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/builder/builder.h>
#include <hilti/ast/visitor.h>

using namespace hilti;

detail::visitor::MutatingVisitorBase::MutatingVisitorBase(ASTContext* ctx, logging::DebugStream dbg)
    : _context(ctx), _builder(nullptr), _dbg(std::move(dbg)) {}

detail::visitor::MutatingVisitorBase::MutatingVisitorBase(Builder* builder, logging::DebugStream dbg)
    : _context(builder->context()), _builder(builder), _dbg(std::move(dbg)) {}

void detail::visitor::MutatingVisitorBase::replaceNode(const Node* old, const NodePtr& new_, const std::string& msg) {
    auto location = util::fmt("[%s] ", old->location().render(true));
    std::string msg_;

    if ( ! msg.empty() )
        msg_ = util::fmt(" (%s)", msg);

    if ( new_ )
        HILTI_DEBUG(_dbg, util::fmt("%s%s \"%s\" -> %s \"%s\"%s", location, old->typename_(), *old, new_->typename_(),
                                    *new_, msg_))
    else
        HILTI_DEBUG(_dbg, util::fmt("%s%s \"%s\" -> null%s", location, old->typename_(), *old, msg_))

    assert(old->parent());
    old->parent()->replaceChild(_context, old, new_);
    _modified = true;
}

void detail::visitor::MutatingVisitorBase::recordChange(const Node* old, const NodePtr& changed, const std::string& msg) {
    auto location = util::fmt("[%s] ", old->location().render(true));
    std::string msg_;

    if ( ! msg.empty() )
        msg_ = util::fmt(" (%s)", msg);

    HILTI_DEBUG(_dbg,
                util::fmt("%s%s \"%s\" -> %s \"%s\"%s", location, old->typename_(), *old, changed->typename_(), *changed, msg_))
    _modified = true;
}

void detail::visitor::MutatingVisitorBase::recordChange(const Node* old, const std::string& msg) {
    auto location = util::fmt("[%s] ", old->location().render(true));
    HILTI_DEBUG(_dbg, util::fmt("%s%s \"%s\" -> %s", location, old->typename_(), *old, msg))
    _modified = true;
}
