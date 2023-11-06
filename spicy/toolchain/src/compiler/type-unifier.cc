// Copyright (c) 2020-2023 by the Zeek project. See license for details.

#include <optional>

#include <spicy/ast/visitor.h>
#include <spicy/compiler/detail/type-unifier.h>

using namespace spicy;

namespace {

// Computes the unified serialization of single unqualified type.
class VisitorSerializer : public visitor::PostOrder {
public:
    VisitorSerializer(hilti::type_unifier::Unifier* unifier) : unifier(unifier) {}

    hilti::type_unifier::Unifier* unifier;

    /*
     * void operator()(type::List* n) final {
     *     unifier->add("list(");
     *     unifier->add(n->elementType());
     *     unifier->add(")");
     * }
     */
};

} // namespace

bool type_unifier::detail::unifyType(hilti::type_unifier::Unifier* unifier, NodePtr& node) {
    auto old_size = unifier->serialization().size();
    VisitorSerializer(unifier).dispatch(node);
    return old_size != unifier->serialization().size();
}
