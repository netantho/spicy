// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/expressions/name.h>
#include <hilti/ast/expressions/unresolved-operator.h>
#include <hilti/ast/types/name.h>
#include <hilti/base/logger.h>
#include <hilti/base/timing.h>
#include <hilti/compiler/detail/renderer.h>

using namespace hilti;
using util::fmt;

static void render(const NodePtr& n, std::ostream* out, std::optional<logging::DebugStream> dbg, bool include_scopes) {
    util::timing::Collector _("hilti/renderer");

    auto nodes = visitor::RangePreOrder(n);
    for ( auto i = nodes.begin(true); i != nodes.end(); ++i ) {
        if ( dbg )
            logger().debugSetIndent(*dbg, i.depth());

        if ( out )
            (*out) << std::string(i.depth() - 1, ' ');

        std::string s;

        if ( *i )
            s = fmt("- %s", (*i)->renderSelf());
        else
            s = "- <empty>";

        if ( out )
            (*out) << s << '\n';

        if ( dbg )
            HILTI_DEBUG(*dbg, s);

        if ( include_scopes && *i && (*i)->scope() ) {
            std::stringstream buffer;
            (*i)->scope()->render(buffer, "    | ");

            if ( buffer.str().size() ) {
                if ( out )
                    (*out) << buffer.str();

                if ( dbg ) {
                    for ( const auto& line : util::split(buffer.str(), "\n") ) {
                        if ( line.size() )
                            HILTI_DEBUG(*dbg, line);
                    }
                }
            }
        }
    }

    if ( dbg )
        logger().debugSetIndent(*dbg, 0);
}

void detail::renderer::render(std::ostream& out, const NodePtr& node, bool include_scopes) {
    ::render(node, &out, {}, include_scopes);
}

void detail::renderer::render(logging::DebugStream stream, const NodePtr& node, bool include_scopes) {
    ::render(node, nullptr, stream, include_scopes);
}
