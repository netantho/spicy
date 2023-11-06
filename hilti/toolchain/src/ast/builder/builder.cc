// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <algorithm>
#include <exception>

#include <hilti/ast/builder/builder.h>

#include "compiler/driver.h"

using namespace hilti;
using util::fmt;

ExpressionPtr Builder::addTmp(const std::string& prefix, const QualifiedTypePtr& t, const Expressions& args) {
    int n = 0;

    if ( auto i = tmps().find(prefix); i != tmps().end() )
        n = i->second;

    ID tmp;

    if ( ++n == 1 )
        tmp = ID(fmt("__%s", prefix));
    else
        tmp = ID(fmt("__%s_%d", prefix, n));

    tmps()[prefix] = n;
    block()->_add(context(), local(tmp, t, args));
    return id(tmp);
}

ExpressionPtr Builder::addTmp(const std::string& prefix, const ExpressionPtr& init) {
    int n = 0;

    if ( auto i = tmps().find(prefix); i != tmps().end() )
        n = i->second;

    ID tmp;

    if ( ++n == 1 )
        tmp = ID(fmt("__%s", prefix));
    else
        tmp = ID(fmt("__%s_%d", prefix, n));

    tmps()[prefix] = n;
    block()->_add(context(), local(tmp, init));
    return id(tmp);
}

ExpressionPtr Builder::addTmp(const std::string& prefix, const QualifiedTypePtr& t, const ExpressionPtr& init) {
    int n = 0;

    if ( auto i = tmps().find(prefix); i != tmps().end() )
        n = i->second;

    ID tmp;

    if ( ++n == 1 )
        tmp = ID(fmt("__%s", prefix));
    else
        tmp = ID(fmt("__%s_%d", prefix, n));

    tmps()[prefix] = n;
    block()->_add(context(), local(tmp, t, init));
    return id(tmp);
}

void Builder::addDebugMsg(const std::string& stream, const std::string& fmt, Expressions args) {
    if ( ! context()->driver()->options().debug )
        return;

    ExpressionPtr call_;

    if ( args.empty() )
        call_ = call("hilti::debug", {string(stream), string(fmt)});
    else if ( args.size() == 1 ) {
        auto msg = modulo(string(fmt), std::move(args.front()));
        call_ = call("hilti::debug", {string(stream), std::move(msg)});
    }
    else {
        auto msg = modulo(string(fmt), tuple(args));
        call_ = call("hilti::debug", {string(stream), std::move(msg)});
    }

    block()->_add(context(), statementExpression(call_, call_->meta()));
}

void Builder::addDebugIndent(const std::string& stream) {
    if ( ! context()->driver()->options().debug )
        return;

    auto call_ = call("hilti::debugIndent", {string(stream)});
    block()->_add(context(), statementExpression(call_));
}

void Builder::addDebugDedent(const std::string& stream) {
    if ( ! context()->driver()->options().debug )
        return;

    auto call_ = call("hilti::debugDedent", {string(stream)});
    block()->_add(context(), statementExpression(call_));
}

void Builder::setLocation(const Location& l) { block()->_add(context(), statementSetLocation(string(l.render()))); }

std::optional<ExpressionPtr> Builder::startProfiler(const std::string& name) {
    if ( ! context()->driver()->options().enable_profiling )
        return {};

    // Note the name of the temp must not clash what HILTI's code generator
    // picks for profiler that it instantiates itself. We do not currently keep
    // those namespace separate.
    return addTmp("prof", call("hilti::profiler_start", {string(name)}));
}

void Builder::stopProfiler(ExpressionPtr profiler) {
    if ( ! context()->driver()->options().enable_profiling )
        return;

    addCall("hilti::profiler_stop", {std::move(profiler)});
}
