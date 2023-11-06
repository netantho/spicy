// copyright (c) 2020-2023 by the zeek project. see license for details.

#include <optional>

#include <hilti/ast/ast-context.h>
#include <hilti/ast/ctors/struct.h>
#include <hilti/ast/declarations/all.h>
#include <hilti/ast/statements/try.h>
#include <hilti/base/timing.h>
#include <hilti/compiler/detail/id-assigner.h>
#include <hilti/compiler/detail/renderer.h>

using namespace hilti;

namespace hilti::logging::debug {
inline const hilti::logging::DebugStream IDAssigner("id-assigner");
} // namespace hilti::logging::debug

namespace {

// Visitor computing canonical and fully-qualified IDs.
struct VisitorComputeIDs : visitor::MutatingPreOrder {
    explicit VisitorComputeIDs(Builder* builder) : visitor::MutatingPreOrder(builder, logging::debug::IDAssigner) {}

    std::vector<ID> path_fqdn;
    std::vector<ID> path_canon;
    uint64_t anon_counter = 0;

    auto fqdn() const { return ID(util::join(path_fqdn, "::")); }
    auto canon() const { return ID(util::join(path_canon, "::")); }

    void setFqID(const DeclarationPtr& d, const ID& id) {
        if ( ! d->fullyQualifiedID() ) {
            recordChange(d.get(), util::fmt("fully qualified ID '%s'", id));
            d->setFullyQualifiedID(id);
        }
        else {
            // Double-check that we always compute the same ID.
            if ( id != d->fullyQualifiedID() )
                logger().internalError(util::fmt("fully qualified ID mismatch for %s: %s (old) vs %s (new)", d->id(),
                                                 d->fullyQualifiedID(), id));
        }
    }

    void setCanonID(const DeclarationPtr& d, const ID& id) {
        if ( ! d->canonicalID() ) {
            recordChange(d.get(), util::fmt("fully qualified ID '%s'", id));
            d->setCanonicalID(id);
        }
        else {
            // Double-check that we always compute the same ID.
            if ( id != d->canonicalID() )
                logger().internalError(
                    util::fmt("canonical ID mismatch for %s: %s (old) vs %s (new)", d->id(), d->canonicalID(), id));
        }
    }

#if 0
    // Print visitor path for debugging.
    int indent = 0;
    void dispatch(const NodePtr& n) {
        if ( ! n )
            return;

        for ( int i = 0; i < indent; i++ )
            std::cerr << "    ";
        std::cerr << n->typename_() << " | " << n.get() << " | " << n->print() << std::endl;

        ++indent;
        visitor::MutatingPreOrder::dispatch(n);
        --indent;
    }
#endif

    void operator()(Node* n) final {
        if ( auto d = n->tryAs<Declaration>() ) {
            if ( auto l = d->tryAs<declaration::LocalVariable>() ) {
                setFqID(d, d->id());
                setCanonID(d, canon() + d->id());
                dispatch(l->type());
                dispatch(l->init());
            }

            else if ( auto g = d->tryAs<declaration::GlobalVariable>() ) {
                setFqID(d, fqdn() + d->id());
                setCanonID(d, canon() + d->id());
                dispatch(g->type());
                dispatch(g->init());
            }

            else if ( auto g = d->tryAs<declaration::Expression>() ) {
                if ( g->id() == ID("self") )
                    setFqID(d, ID("self"));
                else
                    setFqID(d, fqdn() + d->id());

                setCanonID(d, canon() + d->id());
            }

            else if ( auto f = d->tryAs<declaration::Function>() ) {
                if ( d->id().namespace_().empty() )
                    setFqID(d, fqdn() + d->id());
                else
                    setFqID(d, d->id()); // for qualified hook names

                setCanonID(d, canon() + d->id());

                auto old = path_fqdn;
                path_fqdn.clear();
                path_canon.emplace_back(f->id());

                for ( const auto& p : f->function()->ftype()->parameters() )
                    dispatch(p);

                dispatch(f->function()->type());
                dispatch(f->function()->body());

                path_canon.pop_back();
                path_fqdn = old;
            }

            else if ( auto f = d->tryAs<declaration::Field>() ) {
                if ( f->parent(3)->isA<ctor::Struct>() ) {
                    // special-case anonymous structs
                    setCanonID(d, canon() + ID(util::fmt("anon_struct_%x", ++anon_counter)) + d->id());
                }
                else {
                    setFqID(d, fqdn() + d->id());
                    setCanonID(d, canon() + d->id());
                }

                if ( auto ftype = f->type()->type()->tryAs<type::Function>() ) {
                    auto old = path_fqdn;
                    path_fqdn.clear();
                    path_canon.emplace_back(f->id());

                    dispatch(f->type());

                    for ( const auto& p : ftype->parameters() )
                        dispatch(p);

                    if ( auto func = f->inlineFunction() )
                        dispatch(func->body());

                    path_canon.pop_back();
                    path_fqdn = old;
                }
                else {
                    path_canon.emplace_back(f->id());
                    dispatch(f->type());
                    path_canon.pop_back();
                }
            }

            else if ( auto p = d->tryAs<declaration::Parameter>() ) {
                if ( n->parent()->isA<statement::try_::Catch>() )
                    setFqID(d, d->id());
                else
                    setFqID(d, fqdn() + d->id());

                setCanonID(d, canon() + d->id());

                dispatch(p->type());
            }

            else if ( auto m = d->tryAs<declaration::Module>() ) {
                path_fqdn.emplace_back(m->id());
                path_canon.emplace_back(util::fmt("%s_%x", m->id(), util::hash(m->uid()) % 0xffff));

                setFqID(d, fqdn());
                setCanonID(d, canon());

                dispatch(m->statements());

                for ( auto& d : m->declarations() )
                    dispatch(d);

                path_fqdn.pop_back();
                path_canon.pop_back();
            }

            else if ( auto t = d->tryAs<declaration::Type>() ) {
                setFqID(d, fqdn() + d->id());
                setCanonID(d, canon() + d->id());

                path_fqdn.emplace_back(t->id());
                path_canon.emplace_back(t->id());
                dispatch(t->type());
                path_fqdn.pop_back();
                path_canon.pop_back();
            }
            else {
                // All other declarations.
                setFqID(d, fqdn() + d->id());
                setCanonID(d, canon() + d->id());
            }
        }

        else {
            bool skip = false;

            if ( auto t = n->tryAs<QualifiedType>() ) {
                if ( ! t->parent()->isA<declaration::Type>() )
                    skip = true;

                if ( t->parent(1)->isA<ctor::Struct>() )
                    // special-case anonymous structs
                    skip = false;
            }

            if ( ! skip ) {
                // Visit all children.
                for ( auto& c : n->children() )
                    dispatch(c);
            }
        }
    }
};

// Visitor double-checking that all declarations have their canonical IDs set.
struct VisitorCheckIDs : visitor::PreOrder {
    void operator()(Declaration* n) final {
        if ( ! n->canonicalID() ) {
            detail::renderer::render(std::cerr, n->parent()->as<Node>());
            logger().internalError(util::fmt("declaration without canonical ID found: %s", n->print()));
        }
    }
};

} // namespace

bool detail::id_assigner::assign(Builder* builder, const ASTRootPtr& root) {
    util::timing::Collector _("hilti/compiler/ast/id-assigner");

    VisitorComputeIDs v(builder);
    v.dispatch(root);
    return v.isModified();
}

void detail::id_assigner::debugEnforceCanonicalIDs(Builder* builder, const ASTRootPtr& root) {
    auto v = VisitorCheckIDs();
    ::hilti::visitor::visit(v, root);
}
