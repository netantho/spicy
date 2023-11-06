// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/ast-context.h>
#include <hilti/ast/declarations/imported-module.h>
#include <hilti/base/logger.h>
#include <hilti/base/timing.h>
#include <hilti/compiler/plugin.h>

#include <spicy/ast/builder/builder.h>
#include <spicy/ast/forward.h>
#include <spicy/ast/visitor.h>
#include <spicy/compiler/detail/resolver.h>

#include "ast/scope-lookup.h"

using namespace spicy;

namespace spicy::logging::debug {
inline const hilti::logging::DebugStream Resolver("resolver");
inline const hilti::logging::DebugStream Operator("operator");
} // namespace spicy::logging::debug

namespace {

// Turns an unresolved field into a resolved field.
template<typename T>
auto resolveField(Builder* builder, const type::unit::item::UnresolvedField* u, T t) {
    auto field = builder->typeUnitItemField(u->fieldID(), std::move(t), u->engine(), u->isSkip(), u->arguments(),
                                            u->repeatCount(), u->sinks(), u->attributes(), u->condition(), u->hooks(),
                                            u->meta());

    assert(u->index());
    field->setIndex(*u->index());
    return field;
}

// Helper type to select which type of a unit field we are interested in.
enum class FieldType {
    DDType,    // type for $$
    ItemType,  // final type of the field's value
    ParseType, // type that the field is being parsed at
};

struct Resolver : visitor::MutatingPostOrder {
    Resolver(Builder* builder, const ASTRootPtr& root)
        : visitor::MutatingPostOrder(builder, logging::debug::Resolver), root(root) {}

    const ASTRootPtr& root;

    std::set<Node*> seen;

    /*
     * void preDispatch(const Node& n, int level) override {
     *     std::string prefix = "# ";
     *
     *     if ( seen.find(&n) != seen.end() )
     *         prefix = "! ";
     *     else
     *         seen.insert(&n);
     *
     *     auto indent = std::string(level * 2, ' ');
     *     std::cerr << prefix << indent << "> " << n.render() << std::endl;
     *     n.scope()->render(std::cerr, "    | ");
     * };
     */

    // Log debug message recording resolving a expression.
    void logChange(const Node& old, const ExpressionPtr& nexpr) {
        HILTI_DEBUG(logging::debug::Resolver,
                    hilti::util::fmt("[%s] %s -> expression %s (%s)", old.typename_(), old, nexpr, old.location()));
    }

    // Log debug message recording resolving a statement.
    void logChange(const Node& old, const StatementPtr& nstmt) {
        HILTI_DEBUG(logging::debug::Resolver,
                    hilti::util::fmt("[%s] %s -> statement %s (%s)", old.typename_(), old, nstmt, old.location()));
    }

    // Log debug message recording resolving a type.
    void logChange(const Node& old, const QualifiedTypePtr& ntype, const char* msg = "type") {
        HILTI_DEBUG(logging::debug::Resolver,
                    hilti::util::fmt("[%s] %s -> %s %s (%s)", old.typename_(), old, msg, ntype, old.location()));
    }

    // Log debug message recording resolving a unit item.
    void logChange(const Node& old, const type::unit::Item& i) {
        HILTI_DEBUG(logging::debug::Resolver,
                    hilti::util::fmt("[%s] %s -> %s (%s)", old.typename_(), old, i, old.location()));
    }

    // Helper method to compute one of several kinds of a field's types.
    QualifiedTypePtr fieldType(const type::unit::item::Field& f, const QualifiedTypePtr& type, FieldType ft,
                               bool is_container, const Meta& meta) {
        // Visitor determining a unit field type.
        struct FieldTypeVisitor : public visitor::PreOrder {
            explicit FieldTypeVisitor(Builder* builder, FieldType ft) : builder(builder), ft(ft) {}

            Builder* builder;
            FieldType ft;

            QualifiedTypePtr result = nullptr;

            void operator()(hilti::type::RegExp* n) final {
                result = builder->qualifiedType(builder->typeBytes(), hilti::Constness::NonConst);
            }
        };

        QualifiedTypePtr nt;
        FieldTypeVisitor v(builder(), ft);
        v.dispatch(type);

        if ( v.result )
            nt = std::move(v.result);
        else
            nt = type;

        if ( ! nt->isResolved() )
            return {};

        if ( is_container )
            return builder()->qualifiedType(builder()->typeVector(nt, meta), hilti::Constness::NonConst);
        else
            return nt;
    }

    // Helper returning the field name containing a given item of an anonymous bitfield.
    ID findBitsFieldID(const hilti::node::Set<type::unit::Item>& items, const ID& id) const {
        for ( const auto& item : items ) {
            if ( auto field = item->tryAs<type::unit::item::Field>() ) {
                if ( ! field->isAnonymous() )
                    continue;

                auto t = field->itemType()->type()->tryAs<hilti::type::Bitfield>();
                if ( ! t )
                    continue;

                if ( auto bits = t->bits(id) )
                    return field->id();
            }
            else if ( auto field = item->tryAs<type::unit::item::Switch>() ) {
                for ( const auto& c : field->cases() ) {
                    if ( auto id_ = findBitsFieldID(c->items(), id) )
                        return id_;
                }
            }
        }

        return {};
    }

    void operator()(hilti::Attribute* n) final {
        if ( n->tag() == "&size" || n->tag() == "&max-size" ) {
            if ( ! n->hasValue() )
                // Caught elsewhere, we don't want to report it here again.
                return;

            if ( auto x = n->coerceValueTo(builder(), builder()->qualifiedType(builder()->typeUnsignedInteger(64),
                                                                               hilti::Constness::Const)) ) {
                if ( *x )
                    recordChange(n, n->tag());
            }
            else
                n->addError(x.error());
        }
    }

    void operator()(Hook* n) final {
        if ( ! n->unitType() || ! n->unitField() ) {
            // A`%print` hook returns a string as the rendering to print, need
            // to adjust its return type, which defaults to void.
            if ( n->id().local().str() == "0x25_print" ) {
                if ( n->ftype()->result()->type()->isA<hilti::type::Void>() ) {
                    recordChange(n, "setting %print result to string");
                    auto optional = builder()->typeOptional(
                        builder()->qualifiedType(builder()->typeString(), hilti::Constness::Const));
                    n->setResult(context(), builder()->qualifiedType(optional, hilti::Constness::Const));
                }
            }

            // If an `%error` hook doesn't provide the optional string argument,
            // add it here so that we can treat the two versions the same.
            if ( n->id().local().str() == "0x25_error" ) {
                auto params = n->ftype()->parameters();
                if ( params.size() == 0 ) {
                    recordChange(n, "adding parameter to %error");
                    n->setParameters(context(), {builder()->parameter("__except", builder()->typeString())});
                }
            }

            // Link hook to its unit type and field.

            auto unit_type = n->parent<type::Unit>();
            if ( unit_type ) {
                // Produce a tailored error message if `%XXX` is used on a unit field.
                if ( auto id = n->id().namespace_(); id && hilti::util::startsWith(n->id().local(), "0x25_") ) {
                    if ( unit_type->as<type::Unit>()->itemByName(n->id().namespace_().local()) ) {
                        n->addError(hilti::util::fmt("cannot use hook '%s' with a unit field",
                                                     hilti::util::replace(n->id().local(), "0x25_", "%")));
                        return;
                    }
                }
            }
            else {
                // External hook, do name lookup.
                auto ns = n->id().namespace_();
                if ( ! ns )
                    return;

                auto resolved = hilti::scope::lookupID<hilti::declaration::Type>(ns, n, "unit type");
                if ( ! resolved ) {
                    // Look up as a type directly. If found, add explicit `%done`.
                    resolved = hilti::scope::lookupID<hilti::declaration::Type>(n->id(), n, "unit type");
                    if ( resolved ) {
                        recordChange(n, "adding explicit %done hook");
                        n->setID(n->id() + ID("0x25_done"));
                    }
                    else {
                        // Produce a tailored error message if `%XXX` is used on a unit field.
                        if ( auto id = ns.namespace_(); id && hilti::util::startsWith(n->id().local(), "0x25_") ) {
                            if ( auto resolved =
                                     hilti::scope::lookupID<hilti::declaration::Type>(id, n, "unit type") ) {
                                if ( auto utype = resolved->first->template as<hilti::declaration::Type>()
                                                      ->type()
                                                      ->type()
                                                      ->tryAs<type::Unit>();
                                     utype && utype->itemByName(ns.local()) ) {
                                    n->addError(hilti::util::fmt("cannot use hook '%s' with a unit field",
                                                                 hilti::util::replace(n->id().local(), "0x25_", "%")));
                                    // We failed to resolve the ID since it refers to a hook.
                                    // Return early here and do not emit below resolution error.
                                    return;
                                }
                            }
                        }

                        n->addError(resolved.error());
                        return;
                    }
                }

                if ( auto x = resolved->first->as<hilti::declaration::Type>()->type()->type()->tryAs<type::Unit>() )
                    unit_type = x.get();
                else {
                    n->addError(hilti::util::fmt("'%s' is not a unit type", ns));
                    return;
                }
            }

            assert(unit_type);

            if ( ! n->unitType() ) {
                recordChange(unit_type, "unit type");
                n->setUnitType(unit_type->as<type::Unit>());
            }

            type::unit::Item* unit_field = n->parent<type::unit::item::Field>();
            if ( ! unit_field ) {
                // External or out-of-line hook.
                if ( ! n->id() ) {
                    n->addError("hook name missing");
                    return;
                }

                unit_field = unit_type->as<type::Unit>()->itemByName(n->id().local()).get();
                if ( ! unit_field )
                    // We do not record an error here because we'd need to account
                    // for %init/%done/etc. We'll leave that to the validator.
                    return;

                if ( ! unit_field->isA<type::unit::item::Field>() ) {
                    n->addError(hilti::util::fmt("'%s' is not a unit field", n->id()));
                    return;
                }
            }

            assert(unit_field);

            if ( unit_field->isA<type::unit::item::Field>() && ! n->unitField() ) {
                recordChange(n, unit_field->as<type::unit::Item>());
                n->setField(unit_field->as<type::unit::item::Field>());
            }
        }

        if ( n->unitField() || n->dd() ) {
            QualifiedTypePtr dd;

            if ( n->isForEach() ) {
                if ( ! n->unitField()->ddType() )
                    return;

                dd = n->unitField()->ddType();
                if ( ! dd->isResolved() )
                    return;

                /*
                 * TODO: Bring back isIterable()
                 *
                 * if ( ! dd->type()->isIterable() ) {
                 *     h->addError("'foreach' hook can only be used with containers");
                 *     return;
                 * }
                 */

                dd = dd->type()->elementType();
            }
            else
                dd = n->unitField()->itemType();

            if ( dd && dd->isResolved() && ! dd->type()->isA<hilti::type::Void>() ) {
                recordChange(n, dd, "$$ type");
                n->setDD(context(), dd);
            }
        }
    }
    void operator()(hilti::declaration::Module* n) final {
        // Because we alias some Spicy types to HILTI types, we need to make
        // the HILTI library available.
        if ( n->id() == ID("spicy_rt") || n->id() == ID("hilti") )
            return;

        bool have_hilti_import = false;

        for ( const auto& d : n->declarations() ) {
            if ( auto i = d->tryAs<hilti::declaration::ImportedModule>(); i && i->id() == ID("spicy_rt") )
                have_hilti_import = true;
        }

        if ( ! have_hilti_import ) {
            // Import "spicy_rt", which uses HILTI syntax, so we need to set
            // the parsing extension to ".hlt". We then however process it as
            // an Spicy AST, so that it participates in our resolving.
            recordChange(n, "import spicy_rt & hilti");
            n->add(context(), builder()->import("spicy_rt", ".hlt"));
            n->add(context(), builder()->import("hilti", ".hlt"));
        }
    }

    void operator()(hilti::declaration::Type* n) final {
        if ( auto u = n->type()->type()->tryAs<type::Unit>() ) {
            if ( n->linkage() == hilti::declaration::Linkage::Public && ! u->isPublic() ) {
                recordChange(n, "set public");
                u->setPublic(true);
            }

            // Create unit property items from global module items where the unit
            // does not provide an overriding one.
            std::vector<type::unit::Item> ni;
            for ( const auto& prop : root->as<hilti::declaration::Module>()->moduleProperties({}) ) {
                if ( u->propertyItem(prop->id()) )
                    continue;

                auto i = builder()->typeUnitItemProperty(prop->id(), prop->expression(), {}, true, prop->meta());
                recordChange(n, hilti::util::fmt("add module-level property %s", prop->id()));
                u->addItems(context(), {std::move(i)});
            }
        }
    }

    void operator()(hilti::expression::Assign* n) final {
        // Rewrite assignments involving unit fields to use the non-const member operator.
        if ( auto member_const = n->children().front()->tryAs<operator_::unit::MemberConst>() ) {
            auto struct_member = hilti::operator_::registry().byName("struct::MemberNonConst");
            assert(struct_member);
            auto new_lhs = struct_member->instantiate(builder(), member_const->operands(), member_const->meta());
            auto new_assign = builder()->expressionAssign(*new_lhs, n->source(), n->meta());
            replaceNode(n, new_assign);
        }
    }

    void operator()(hilti::expression::Name* n) final {
        // Allow `$$` as an alias for `self` in unit convert attributes for symmetry with field convert attributes.
        if ( n->id() == ID("__dd") ) {
            // The following loop searches for `&convert` attribute nodes directly under `Unit` nodes.
            for ( auto p = n->parent(); p; p = p->parent() ) {
                auto attr = p->tryAs<hilti::Attribute>();
                if ( ! attr )
                    continue;

                if ( attr->tag() != "&convert" )
                    return;

                // The direct parent of the attribute set containing the attribute should be the unit.
                if ( ! p->parent(2)->isA<type::Unit>() )
                    return;

                recordChange(n, "set self");
                n->setID("self");
            }
        }
    }

    void operator()(operator_::unit::HasMember* n) final {
        auto unit = n->op0()->type()->type()->tryAs<type::Unit>();
        auto id = n->op1()->tryAs<hilti::expression::Member>()->id();

        if ( unit && id && ! unit->itemByName(id) ) {
            // See if we got an anonymous bitfield with a member of that
            // name. If so, rewrite the access to transparently refer to the
            // member through the field's internal name.
            if ( auto field_id = findBitsFieldID(unit->items(), id) ) {
                auto has_member = hilti::operator_::registry().byName("unit::HasMember");
                assert(has_member);
                auto has_field =
                    has_member->instantiate(builder(), {n->op0(), builder()->expressionMember(field_id)}, n->meta());
                replaceNode(n, *has_field);
            }
        }
    }

    void operator()(operator_::unit::MemberConst* n) final {
        auto unit = n->op0()->type()->type()->tryAs<type::Unit>();
        auto id = n->op1()->tryAs<hilti::expression::Member>()->id();

        if ( unit && id && ! unit->itemByName(id) ) {
            // See if we got an anonymous bitfield with a member of that
            // name. If so, rewrite the access to transparently refer to the
            // member through the field's internal name.
            if ( auto field_id = findBitsFieldID(unit->items(), id) ) {
                auto unit_member = hilti::operator_::registry().byName("unit::MemberConst");
                auto bitfield_member = hilti::operator_::registry().byName("bitfield::Member");
                assert(unit_member && bitfield_member);
                auto access_field =
                    unit_member->instantiate(builder(), {n->op0(), builder()->expressionMember(field_id)}, n->meta());
                auto access_bits =
                    bitfield_member->instantiate(builder(), {std::move(*access_field), n->op1()}, n->meta());
                replaceNode(n, *access_bits);
            }
        }
    }

    void operator()(operator_::unit::MemberNonConst* n) final {
        auto unit = n->op0()->type()->type()->tryAs<type::Unit>();
        auto id = n->op1()->tryAs<hilti::expression::Member>()->id();

        if ( unit && id && ! unit->itemByName(id) ) {
            // See if we got an anonymous bitfield with a member of that
            // name. If so, rewrite the access to transparently refer to the
            // member through the field's internal name.
            if ( auto field_id = findBitsFieldID(unit->items(), id) ) {
                auto unit_member = hilti::operator_::registry().byName("unit::MemberNonConst");
                auto bitfield_member = hilti::operator_::registry().byName("bitfield::Member");
                assert(unit_member && bitfield_member);
                auto access_field =
                    unit_member->instantiate(builder(), {n->op0(), builder()->expressionMember(field_id)}, n->meta());
                auto access_bits =
                    bitfield_member->instantiate(builder(), {std::move(*access_field), n->op1()}, n->meta());
                replaceNode(n, *access_bits);
            }
        }
    }

    void operator()(operator_::unit::TryMember* n) final {
        auto unit = n->op0()->type()->type()->tryAs<type::Unit>();
        auto id = n->op1()->tryAs<hilti::expression::Member>()->id();

        if ( unit && id && ! unit->itemByName(id) ) {
            // See if we we got an anonymous bitfield with a member of that
            // name. If so, rewrite the access to transparently to refer to the
            // member through the field's internal name.
            if ( auto field_id = findBitsFieldID(unit->items(), id) ) {
                auto try_member = hilti::operator_::registry().byName("unit::TryMember");
                auto bitfield_member = hilti::operator_::registry().byName("bitfield::Member");
                assert(try_member && bitfield_member);

                auto try_field =
                    try_member->instantiate(builder(), {n->op0(), builder()->expressionMember(field_id)}, n->meta());
                auto access_bits =
                    bitfield_member->instantiate(builder(), {std::move(*try_field), n->op1()}, n->meta());
                replaceNode(n, *access_bits);
            }
        }
    }

    void operator()(hilti::type::Bitfield* n) final {
        if ( auto field = n->parent()->tryAs<type::unit::item::Field>() ) {
            // Transfer any "&bitorder" attribute over to the type.
            if ( auto a = field->attributes()->find("&bit-order"); a && ! n->attributes()->find("&bit-order") ) {
                recordChange(n, "transfer &bitorder attribute");
                n->attributes()->add(context(), a);
            }
        }

        if ( auto decl = n->tryAs<hilti::declaration::Type>() ) {
            // Transfer any "&bitorder" attribute over to the type.
            if ( auto a = decl->attributes()->find("&bit-order"); a && ! n->attributes()->find("&bit-order") ) {
                recordChange(n, "transfer &bitorder attribute");
                n->attributes()->add(context(), a);
            }
        }
    }

    void operator()(type::Unit* n) final {
        if ( ! n->typeID() )
            return;

        /*
         * if ( ! u->self() )
         *     type::Unit::setSelf(&p.node);
         */

        if ( n->inheritScope() ) {
            recordChange(n, "set no-inherit");
            n->setInheritScope(false);
        }

        /*
         * if ( t.typeID() && ! u.id() ) {
         *     recordChange(hilti::util::fmt("unit ID %s", *t.typeID()));
         *     n->setID(*t.typeID());
         *     modified = true;
         * }
         */
    }

    void operator()(type::unit::item::Field* n) final {
        if ( (n->isAnonymous() || n->isSkip()) && ! n->isTransient() ) {
            // Make the field transient if it's either top-level, or a direct
            // parent field is already transient.
            bool make_transient = false;

            if ( n->parent()->isA<type::Unit>() )
                make_transient = true;

            if ( auto pf = n->parent<type::unit::item::Field>(); pf && pf->isTransient() )
                make_transient = true;

            if ( make_transient ) {
                // Make anonymous top-level fields transient.
                recordChange(n, "set transient");
                n->setTransient(true);
            }
        }

        if ( ! n->parseType()->isResolved() ) {
            if ( auto t = fieldType(*n, n->originalType(), FieldType::ParseType, n->isContainer(), n->meta()) ) {
                recordChange(n, "parse type");
                n->setParseType(context(), std::move(t));
            }
        }

        if ( ! n->ddType()->isResolved() && n->parseType()->isResolved() ) {
            if ( auto dd = fieldType(*n, n->originalType(), FieldType::DDType, n->isContainer(), n->meta()) ) {
                if ( ! dd->type()->isA<hilti::type::Void>() ) {
                    recordChange(n, "$$ type");
                    n->setDDType(context(), dd);
                }
            }
        }

        if ( ! n->itemType()->isResolved() && n->parseType()->isResolved() ) {
            QualifiedTypePtr t;

            if ( auto x = n->convertExpression() ) {
                if ( x->second ) {
                    // Unit-level convert on the sub-item.
                    auto u = x->second->type()->as<type::Unit>();
                    auto a = u->attributes()->find("&convert");
                    assert(a);
                    auto e = a->valueAsExpression()->get();
                    if ( e->isResolved() )
                        t = e->type();
                }
                else if ( x->first->isResolved() ) {
                    t = x->first->type();

                    // If there's list comprehension, morph the type into a vector.
                    // Assignment will transparently work.
                    if ( auto x = t->type()->tryAs<hilti::type::List>() )
                        t = builder()->qualifiedType(builder()->typeVector(x->elementType(), x->meta()),
                                                     t->constness());
                }
            }
            else if ( const auto& i = n->item(); i && i->isA<type::unit::item::Field>() ) {
                const auto& inner_f = i->as<type::unit::item::Field>();
                t = fieldType(*inner_f, i->itemType(), FieldType::ItemType, n->isContainer(), n->meta());
            }
            else
                t = fieldType(*n, n->originalType(), FieldType::ItemType, n->isContainer(), n->meta());

            if ( t ) {
                recordChange(n, "item type");
                n->setItemType(context(), std::move(t));
            }
        }
    }
    void operator()(type::unit::item::UnresolvedField* n) final {
        if ( n->type() && n->type()->type()->isA<hilti::type::Void>() && n->attributes() ) {
            // Transparently map void fields that aim to parse data into
            // skipping bytes fields. Use of such void fields is deprecated and
            // will be removed later.
            size_t ok_attrs = 0;
            const auto& attrs = n->attributes()->attributes();
            for ( const auto& a : attrs ) {
                if ( a->tag() == "&requires" )
                    ok_attrs++;
            }

            if ( ok_attrs != attrs.size() ) {
                hilti::logger().deprecated(
                    "using `void` fields with attributes is deprecated and support will be removed in a future "
                    "release; replace 'void ...' with 'skip bytes ...'",
                    n->meta().location());

                n->setSkip(true);
                n->setType(context(), builder()->qualifiedType(builder()->typeBytes(), hilti::Constness::NonConst));
            }
        }

        if ( const auto& id = n->unresolvedID() ) { // check for unresolved IDs first to overrides the other cases below
            auto resolved = hilti::scope::lookupID<hilti::Declaration>(id, n, "field");
            if ( ! resolved ) {
                n->addError(resolved.error());
                return;
            }

            if ( auto t = resolved->first->template tryAs<hilti::declaration::Type>() ) {
                QualifiedTypePtr tt = builder()->qualifiedType(builder()->typeName(id), hilti::Constness::NonConst);

                // If a unit comes with a &convert attribute, we wrap it into a
                // subitem so that we have our recursive machinery available
                // (which we don't have for pure types).
                if ( auto unit_type = t->type()->type()->tryAs<type::Unit>();
                     unit_type && unit_type->attributes()->has("&convert") ) {
                    auto inner_field = builder()->typeUnitItemField({}, tt, spicy::Engine::All, false, n->arguments(),
                                                                    {}, {}, {}, {}, {}, n->meta());
                    inner_field->setIndex(*n->index());

                    auto outer_field =
                        builder()->typeUnitItemField(n->fieldID(), std::move(inner_field), n->engine(), n->isSkip(), {},
                                                     n->repeatCount(), n->sinks(), n->attributes(), n->condition(),
                                                     n->hooks(), n->meta());

                    outer_field->setIndex(*n->index());

                    replaceNode(n, std::move(outer_field));
                }

                else
                    // Default treatment for types is to create a corresponding field.
                    replaceNode(n, resolveField(builder(), n, t->type()));
            }

            else if ( auto c = resolved->first->tryAs<hilti::declaration::Constant>() ) {
                if ( auto ctor = c->value()->template tryAs<hilti::expression::Ctor>() )
                    replaceNode(n, resolveField(builder(), n, ctor->ctor()));
                else
                    n->addError("field value must be a constant");
            }
            else
                n->addError(hilti::util::fmt("field value must be a constant or type (but is a %s)",
                                             resolved->first->as<hilti::Declaration>()->displayName()));
        }

        else if ( auto c = n->ctor() )
            replaceNode(n, resolveField(builder(), n, c));

        else if ( auto t = n->type() ) {
            if ( ! t->isResolved() )
                return;

            if ( auto bf = t->type()->tryAs<hilti::type::Bitfield>() ) {
                // If a bitfield type comes with values for at least one of its
                // items, it's actually a bitfield ctor. Replace the type with the
                // ctor then.
                if ( auto ctor = bf->ctorValue(context()) ) {
                    replaceNode(n, resolveField(builder(), n, ctor));
                    return;
                }
            }

            replaceNode(n, resolveField(builder(), n, t));
        }

        else if ( auto i = n->item() )
            replaceNode(n, resolveField(builder(), n, i));

        else
            hilti::logger().internalError("no known type for unresolved field", n->location());
    }
};

} // anonymous namespace

bool detail::resolver::resolve(Builder* builder, const ASTRootPtr& root) {
    hilti::util::timing::Collector _("spicy/compiler/ast/resolver");

    bool hilti_modified = (*hilti::plugin::registry().hiltiPlugin().ast_resolve)(builder->context(), root);

    return visitor::visit(Resolver(builder, root), root,
                          [&](const auto& v) { return v.isModified() || hilti_modified; });
}
