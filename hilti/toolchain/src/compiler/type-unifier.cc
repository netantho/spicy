// copyright (c) 2020-2023 by the zeek project. see license for details.

#include <optional>

#include <hilti/ast/ast-context.h>
#include <hilti/ast/builder/builder.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/list.h>
#include <hilti/ast/types/map.h>
#include <hilti/ast/types/name.h>
#include <hilti/ast/types/optional.h>
#include <hilti/ast/types/reference.h>
#include <hilti/ast/types/result.h>
#include <hilti/ast/types/set.h>
#include <hilti/ast/types/struct.h>
#include <hilti/ast/types/type.h>
#include <hilti/ast/types/union.h>
#include <hilti/ast/types/vector.h>
#include <hilti/base/timing.h>
#include <hilti/compiler/detail/type-unifier.h>
#include <hilti/global.h>

using namespace hilti;

namespace hilti::logging::debug {
inline const hilti::logging::DebugStream TypeUnifier("type-unifier");
} // namespace hilti::logging::debug

namespace {

// Computes the unified serialization of single unqualified type.
class VisitorSerializer : public visitor::PostOrder {
public:
    std::string serial; // builds up serializaation incrementally
    bool abort = false; // if true, cannot compute serialization yet

    // External entry point.
    std::string unify(UnqualifiedType* t) {
        serial = "";
        abort = false;
        add(t);

        if ( serial.empty() & ! abort ) {
            std::cerr << t->render();
            logger().internalError("empty type serialization for unification, type not implemented?");
        }

        return abort ? "" : serial;
    }

    void add(UnqualifiedType* t) {
        if ( abort )
            return;

        if ( auto name = t->tryAs<type::Name>() ) {
            if ( ! name->resolvedType() ) {
                abort = true;
                return;
            }

            t = type::follow(t);
        }

        if ( t->unification() )
            add(t->unification());
        else if ( t->isNameType() ) {
            if ( const auto& id = t->typeID() )
                add(util::fmt("name(%s)", *id));
            else
                abort = true;
        }
        else {
            if ( t->isWildcard() )
                // Should have been preset.
                logger().internalError(util::fmt("unresolved wildcard type during unification: %s", t->typename_()));

            dispatch(t->as<Node>());
        }
    }

    void add(const QualifiedTypePtr& t) {
        if ( abort )
            return;

        // Due to post-order processing at the outer visitor, types lower in
        // the tree must have been processed already, so either they have a
        // value or they aren't ready yet.
        if ( t->type()->unification() )
            add(t->type()->unification());
        else
            abort = true;
    }

    void add(const std::string& s) { serial += s; }

    void operator()(type::Auto* n) final {
        // We never set this, so that it will be unified once the actual type
        // has been identified.
        abort = true;
    }

    void operator()(type::Bitfield* n) final {
        add("bitfield(");
        add(util::fmt("%u", n->width()));
        add(",");
        for ( const auto& b : n->bits() ) {
            add(util::fmt("%s:%u:%u", b->id(), b->lower(), b->upper()));
            add(",");
        }
        add(")");
    }

    void operator()(type::Function* n) final {
        add("function(result:");
        add(n->result());
        for ( const auto& p : n->parameters() ) {
            add(", ");
            add(p->type());
        }
        add(")");
    }

    void operator()(type::List* n) final {
        add("list(");
        add(n->elementType());
        add(")");
    }

    void operator()(type::Map* n) final {
        add("map(");
        add(n->keyType());
        add("->");
        add(n->valueType());
        add(")");
    }

    void operator()(type::OperandList* n) final {
        add("operand-list(");
        for ( const auto& op : n->operands() ) {
            add(to_string(op->kind()));
            add(op->id());
            add(":");
            add(op->type__().get());
            add(",");
        }
        add(")");
    }

    void operator()(type::Optional* n) final {
        add("optional(");
        add(n->dereferencedType());
        add(")");
    }

    void operator()(type::Result* n) final {
        add("result(");
        add(n->dereferencedType());
        add(")");
    }

    void operator()(type::Set* n) final {
        add("set(");
        add(n->elementType());
        add(")");
    }

    void operator()(type::StrongReference* n) final {
        add("strong_ref(");
        add(n->dereferencedType());
        add(")");
    }

    void operator()(type::Tuple* n) final {
        add("tuple(");
        for ( const auto& t : n->elements() ) {
            add(t->type());
            add(",");
        }
        add(")");
    }

    void operator()(type::Type_* n) final {
        add("type(");
        add(n->typeValue());
        add(")");
    }

    void operator()(type::ValueReference* n) final {
        add("value_ref(");
        add(n->dereferencedType());
        add(")");
    }

    void operator()(type::Vector* n) final {
        add("vector(");
        add(n->elementType());
        add(")");
    }

    void operator()(type::WeakReference* n) final {
        add("weak_ref(");
        add(n->dereferencedType());
        add(")");
    }

    void operator()(type::list::Iterator* n) final {
        add("iterator(list(");
        add(n->dereferencedType());
        add("))");
    }

    void operator()(type::map::Iterator* n) final {
        add("iterator(map(");
        add(n->keyType());
        add("->");
        add(n->valueType());
        add("))");
    }

    void operator()(type::set::Iterator* n) final {
        add("iterator(set(");
        add(n->dereferencedType());
        add("))");
    }

    void operator()(type::vector::Iterator* n) final {
        add("iterator(vector(");
        add(n->dereferencedType());
        add("))");
    }
};

// Unifies all types in an AST.
class VisitorTypeUnifier : public visitor::MutatingPostOrder {
public:
    explicit VisitorTypeUnifier(ASTContext* ctx) : visitor::MutatingPostOrder(ctx, logging::debug::TypeUnifier) {}

    VisitorSerializer unifier;

    void operator()(UnqualifiedType* n) final {
        if ( n->unification() )
            return;

        if ( auto serial = unifier.unify(n); ! serial.empty() ) {
            n->setUnification(type::Unification(serial));
            recordChange(n, util::fmt("unified type: %s", n->unification().str()));
        }
    }
};

} // namespace

bool detail::type_unifier::unify(Builder* builder, const ASTRootPtr& root) {
    util::timing::Collector _("hilti/compiler/ast/type-unifier");

    return hilti::visitor::visit(VisitorTypeUnifier(builder->context()), root,
                                 [](const auto& v) { return v.isModified(); });
}

bool detail::type_unifier::unify(ASTContext* ctx, const UnqualifiedTypePtr& type) {
    util::timing::Collector _("hilti/compiler/ast/type-unifier");

    if ( ! type->unification() )
        hilti::visitor::visit(VisitorTypeUnifier(ctx), type);

    return type->unification();
}
