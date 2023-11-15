// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <functional>
#include <optional>
#include <sstream>
#include <utility>

#include <hilti/ast/ast-context.h>
#include <hilti/ast/builder/builder.h>
#include <hilti/ast/ctors/reference.h>
#include <hilti/ast/declaration.h>
#include <hilti/ast/declarations/global-variable.h>
#include <hilti/ast/declarations/imported-module.h>
#include <hilti/ast/declarations/local-variable.h>
#include <hilti/ast/declarations/parameter.h>
#include <hilti/ast/detail/operator-registry.h>
#include <hilti/ast/expressions/deferred.h>
#include <hilti/ast/expressions/keyword.h>
#include <hilti/ast/expressions/list-comprehension.h>
#include <hilti/ast/expressions/name.h>
#include <hilti/ast/expressions/type.h>
#include <hilti/ast/expressions/typeinfo.h>
#include <hilti/ast/node.h>
#include <hilti/ast/operator.h>
#include <hilti/ast/operators/generic.h>
#include <hilti/ast/scope-lookup.h>
#include <hilti/ast/scope.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/function.h>
#include <hilti/ast/types/reference.h>
#include <hilti/ast/types/unknown.h>
#include <hilti/ast/types/void.h>
#include <hilti/base/timing.h>
#include <hilti/base/util.h>
#include <hilti/compiler/coercer.h>
#include <hilti/compiler/context.h>
#include <hilti/compiler/detail/constant-folder.h>
#include <hilti/compiler/detail/resolver.h>
#include <hilti/compiler/driver.h>
#include <hilti/compiler/unit.h>

using namespace hilti;

namespace hilti::logging::debug {
inline const hilti::logging::DebugStream Resolver("resolver");
inline const hilti::logging::DebugStream Operator("operator");
} // namespace hilti::logging::debug

namespace {

struct Resolver : visitor::MutatingPostOrder {
    explicit Resolver(Builder* builder, const ASTRootPtr& root)
        : visitor::MutatingPostOrder(builder, logging::debug::Resolver), root(root) {}

    const ASTRootPtr& root;
    std::map<ID, QualifiedTypePtr> auto_params; // mapping of `auto` parameters inferred, indexed by canonical ID

    // If an expression is a reference, dereference it; otherwise return the
    // expression itself.
    ExpressionPtr skipReferenceValue(const ExpressionPtr& op) {
        static auto value_reference_deref = operator_::get("value_reference::Deref");
        static auto strong_reference_deref = operator_::get("strong_reference::Deref");
        static auto weak_reference_deref = operator_::get("weak_reference::Deref");

        if ( ! op->type()->type()->isReferenceType() )
            return op;

        if ( op->type()->type()->isA<type::ValueReference>() )
            return *value_reference_deref->instantiate(builder(), {op}, op->meta());
        else if ( op->type()->type()->isA<type::StrongReference>() )
            return *strong_reference_deref->instantiate(builder(), {op}, op->meta());
        else if ( op->type()->type()->isA<type::WeakReference>() )
            return *weak_reference_deref->instantiate(builder(), {op}, op->meta());
        else
            logger().internalError("unknown reference type");
    }

    // If a type is a reference type, dereference it; otherwise return the type
    // itself.
    QualifiedTypePtr skipReferenceType(const QualifiedTypePtr& t) {
        if ( t && t->type()->isReferenceType() )
            return t->type()->dereferencedType();
        else
            return t;
    }

    // Checks if a set of operator candidates contains only calls to hooks of the same type.
    bool checkForHooks(Builder* builder, expression::UnresolvedOperator* u, const std::vector<ExpressionPtr>& matches) {
        if ( u->kind() != operator_::Kind::Call )
            return false;

        ID hook_id;
        type::FunctionPtr hook_type;

        for ( const auto& i : matches ) {
            auto ftype = i->as<expression::ResolvedOperator>()->op0()->type()->type()->tryAs<type::Function>();
            auto fid = i->as<expression::ResolvedOperator>()->op0()->tryAs<expression::Name>();

            if ( ! ftype || ! fid || ftype->flavor() != type::function::Flavor::Hook )
                return false;

            assert(fid->resolvedDeclaration());
            auto canon_id = fid->resolvedDeclaration()->canonicalID();

            // If it's scoped ID, look that up to find the canonical of the main declaration.
            if ( fid->id().namespace_() ) {
                if ( auto x = builder->context()->root()->scope()->lookupAll(fid->id()); ! x.empty() ) {
                    // Just the 1st hit is fine, others are assume to match.
                    canon_id = x.front().node->canonicalID();
                    assert(canon_id);
                }
                else
                    return false;
            }

            if ( ! hook_id ) {
                hook_id = canon_id;
                hook_type = ftype;
            }
            else {
                if ( canon_id != hook_id || ! type::same(ftype, hook_type) )
                    return false;
            }
        }

        return true;
    };

    // Attempts to infer a common type from a list of expression. Ignores
    // constness of the individual expressions when comparing types, and always
    // returns a non-constant type as the one inferred. If old type is given,
    // returns null if inferred type is the same as the old one.
    QualifiedTypePtr typeForExpressions(Node* n, node::Range<Expression> exprs,
                                        const QualifiedTypePtr& old_type = nullptr) {
        UnqualifiedTypePtr t;

        for ( const auto& e : exprs ) {
            if ( ! e->type()->isResolved() )
                return {};

            if ( ! t )
                t = e->type()->type();
            else {
                if ( ! type::same(e->type()->type(), t) ) {
                    t = builder()->typeUnknown(); // inconsistent types, won't be able to resolve here
                    break;
                }
            }
        }

        if ( ! t )
            return nullptr;

        auto ntype = builder()->qualifiedType(t, false);

        if ( old_type && type::same(old_type, ntype) )
            return nullptr;

        return ntype;
    }

    // Casts an uint64 to int64, with range check.
    int64_t to_int64(uint64_t x) {
        if ( x > static_cast<uint64_t>(std::numeric_limits<int64_t>::max()) )
            throw hilti::rt::OutOfRange("integer value out of range");

        return static_cast<int64_t>(x);
    }

    // Casts an int64 to uint64, with range check.
    uint64_t to_uint64(int64_t x) {
        if ( x < 0 )
            throw hilti::rt::OutOfRange("integer value out of range");

        return static_cast<uint64_t>(x);
    }

    // Overload that doesn't need to do any checking.
    int64_t to_int64(int64_t x) { return x; }

    // Returns the i'th argument of a call expression.
    auto callArgument(const expression::ResolvedOperator* o, int i) {
        auto ctor = o->op1()->as<expression::Ctor>()->ctor();

        if ( auto x = ctor->tryAs<ctor::Coerced>() )
            ctor = x->coercedCtor();

        return ctor->as<ctor::Tuple>()->value()[i];
    }

    // Returns a method call's i-th argument.
    ExpressionPtr methodArgument(const expression::ResolvedOperator* o, size_t i) {
        auto ops = o->op2();

        // If the argument list was the result of a coercion unpack its result.
        if ( auto coerced = ops->tryAs<expression::Coerced>() )
            ops = coerced->expression();

        if ( auto ctor_ = ops->tryAs<expression::Ctor>() ) {
            auto ctor = ctor_->ctor();

            // If the argument was the result of a coercion unpack its result.
            if ( auto x = ctor->tryAs<ctor::Coerced>() )
                ctor = x->coercedCtor();

            if ( auto args = ctor->tryAs<ctor::Tuple>(); args && i < args->value().size() )
                return args->value()[i];
        }

        util::cannot_be_reached();
    }

    // Coerces an expression to a given type, returning the new value if it's
    // changed from the old one. Records an error with the node if coercion is
    // not possible, and returns null then. Will indicate no-change if
    // expression or type hasn't been resolved.
    ExpressionPtr coerceTo(Node* n, const ExpressionPtr& e, const QualifiedTypePtr& t, bool contextual,
                           bool assignment) {
        if ( ! (e->isResolved() && t->isResolved()) )
            return nullptr;

        if ( type::same(e->type(), t) )
            return nullptr;

        bitmask<CoercionStyle> style =
            (assignment ? CoercionStyle::TryAllForAssignment : CoercionStyle::TryAllForMatching);

        if ( contextual )
            style |= CoercionStyle::ContextualConversion;

        if ( auto c = hilti::coerceExpression(builder(), e, t, style) )
            return c.nexpr;

        n->addError(util::fmt("cannot coerce expression '%s' of type '%s' to type '%s'", *e, *e->type(), *t));
        return nullptr;
    }

    // Coerces a set if expressions to the types of a corresponding set of
    // function parameters. Returns an empty result reset if coercion succeeded
    // but didn't change any expressions. Will indicate no-change also if the
    // expressions or the type aren't fully resolved yet. Returns an error if a
    // coercion failed with a hard error.
    template<typename Container1, typename Container2>
    Result<std::optional<Expressions>> coerceCallArguments(Container1 exprs, Container2 params) {
        // Build a tuple to coerce expression according to an OperandList.
        for ( const auto& e : exprs ) {
            if ( ! e->isResolved() )
                return {std::nullopt};
        }

        auto src = builder()->expressionCtor(builder()->ctorTuple(std::move(exprs)));
        auto dst = type::OperandList::fromParameters(context(), std::move(params));

        auto coerced = coerceExpression(builder(), src, builder()->qualifiedType(dst, Const),
                                        CoercionStyle::TryAllForFunctionCall);
        if ( ! coerced )
            return result::Error("coercion failed");

        if ( ! coerced.nexpr )
            // No change.
            return {std::nullopt};

        return {coerced.nexpr->template as<expression::Ctor>()->ctor()->template as<ctor::Tuple>()->value()};
    }

    // Coerces a set of expressions all to the same destination. Returns an
    // empty result reset if coercion succeeded but didn't change any
    // expressions. Will indicate no-change also if the expressions or the type
    // aren't fully resolved yet. Returns an error if a coercion failed with a
    // hard error.
    template<typename Container>
    Result<std::optional<Expressions>> coerceExpressions(const Container& exprs, const QualifiedTypePtr& dst) {
        if ( ! (dst->isResolved() && expression::areResolved(exprs)) )
            return {std::nullopt};

        bool changed = false;
        Expressions nexprs;

        for ( const auto& e : exprs ) {
            auto coerced = coerceExpression(builder(), e, dst, CoercionStyle::TryAllForAssignment);
            if ( ! coerced )
                return result::Error("coercion failed");

            if ( coerced.nexpr )
                changed = true;

            nexprs.emplace_back(std::move(*coerced.coerced));
        }

        if ( changed )
            return {std::move(nexprs)};
        else
            // No change.
            return {std::nullopt};
    }

    // Coerces a specific call argument to a given type returning the coerced
    // expression (only) if its type has changed.
    Result<ExpressionPtr> coerceMethodArgument(const expression::ResolvedOperator* o, size_t i,
                                               const QualifiedTypePtr& t) {
        auto ops = o->op2();

        // If the argument list was the result of a coercion unpack its result.
        if ( auto coerced = ops->tryAs<expression::Coerced>() )
            ops = coerced->expression();

        auto ctor_ = ops->as<expression::Ctor>()->ctor();

        // If the argument was the result of a coercion unpack its result.
        if ( auto x = ctor_->tryAs<ctor::Coerced>() )
            ctor_ = x->coercedCtor();

        const auto& args = ctor_->as<ctor::Tuple>()->value();
        if ( i >= args.size() )
            return {nullptr};

        if ( auto narg = hilti::coerceExpression(builder(), args[i], t); ! narg )
            return result::Error(util::fmt("cannot coerce argument %d from %s to %s", i, *args[i]->type(), *t));
        else if ( narg.nexpr ) {
            auto nargs = args;
            nargs[i] = narg.nexpr;
            return {builder()->expressionCtor(builder()->ctorTuple(nargs))};
        }

        return {nullptr};
    }

    // Records the actual type of an `auto` parameter as inferred from a
    // concrete argument value passed to it.
    void recordAutoParameters(const type::Function& ftype, const ExpressionPtr& args) {
        auto arg = args->as<expression::Ctor>()->ctor()->as<ctor::Tuple>()->value().begin();
        std::vector<type::function::Parameter> params;
        for ( auto& rp : ftype.parameters() ) {
            auto p = rp->as<declaration::Parameter>();
            if ( ! p->type()->isAuto() )
                continue;

            auto t = (*arg)->type();
            if ( ! t->isResolved() )
                continue;

            assert(p->canonicalID());
            const auto& i = auto_params.find(p->canonicalID());
            if ( i == auto_params.end() ) {
                auto_params.emplace(p->canonicalID(), t);
                HILTI_DEBUG(logging::debug::Resolver,
                            util::fmt("recording auto parameter %s as of type %s", p->canonicalID(), *t));
            }
            else {
                if ( i->second != t )
                    rp->addError("mismatch for auto parameter");
            }

            ++arg;
        }
    }

    // Matches an unresolved operator against a set of operator candidates,
    // returning instantiations of all matches.
    std::vector<ExpressionPtr> matchOperators(expression::UnresolvedOperator* u,
                                              const std::vector<const Operator*> candidates,
                                              bool disallow_type_changes = false) {
        // TODO: Can we simplify the rounds?
        const std::array<bitmask<CoercionStyle>, 6> styles = {
            CoercionStyle::OperandMatching | CoercionStyle::TryExactMatch,
            CoercionStyle::OperandMatching | CoercionStyle::TryExactMatch | CoercionStyle::TryDeref,
            CoercionStyle::OperandMatching | CoercionStyle::TryExactMatch | CoercionStyle::TryCoercionWithinSameType,
            CoercionStyle::OperandMatching | CoercionStyle::TryExactMatch | CoercionStyle::TryCoercion,
            CoercionStyle::OperandMatching | CoercionStyle::TryExactMatch | CoercionStyle::TryConstPromotion,
            CoercionStyle::OperandMatching | CoercionStyle::TryExactMatch | CoercionStyle::TryConstPromotion |
                CoercionStyle::TryCoercion,
        };

        auto deref_operands = [&](const node::Range<Expression>& ops) {
            return node::transform(ops, [this](const auto& op) { return skipReferenceValue(op); });
        };

        auto coerce_operands = [&](const Operator* candidate, const auto& operands, const auto& expressions,
                                   bitmask<CoercionStyle> style) {
            // First, match the operands against the operator's general signature.
            auto result = coerceOperands(builder(), candidate->kind(), operands, expressions, style);
            if ( ! result )
                return result;

            // Then, if the operator provides more specific operands through filtering, match against those as well.
            if ( auto filtered = candidate->filter(builder(), operands) ) {
                assert(filtered->size() == candidate->operands().size());
                result = coerceOperands(builder(), candidate->kind(), operands, *filtered, style);
            }

            return result;
        };

        auto try_candidate = [&](const Operator* candidate, const node::Range<Expression>& operands, auto style,
                                 const Meta& meta, const auto& dbg_msg) -> ExpressionPtr {
            auto noperands = coerce_operands(candidate, operands, candidate->operands(), style);
            if ( ! noperands ) {
                if ( (style & CoercionStyle::TryDeref) && ! (style & CoercionStyle::DisallowTypeChanges) ) {
                    // If any of the operands is a reference type, try the derefed operands, too.
                    for ( const auto& op : operands ) {
                        if ( op->type()->type()->isReferenceType() ) {
                            noperands =
                                coerce_operands(candidate, deref_operands(operands), candidate->operands(), style);
                            break;
                        }
                    }
                }
            }

            if ( ! noperands ) {
                HILTI_DEBUG(logging::debug::Operator, util::fmt("-> cannot coerce operands: %s", noperands.error()));
                return {};
            }

            auto r = candidate->instantiate(builder(), noperands->second, meta);
            if ( ! r ) {
                u->addError(r.error());
                return {};
            }

            // Some operators may not be able to determine their type before the
            // resolver had a chance to provide the information needed. They will
            // return "auto" in that case (specifically, that's the case for Spicy
            // unit member access). Note we can't check if ->isResolved() here
            // because operators may legitimately return other unresolved types
            // (e.g., IDs that still need to be looked up).
            if ( (*r)->type()->isAuto() )
                return {};

            ExpressionPtr resolved = *r;

            // Fold any constants right here in case downstream resolving depends
            // on finding a constant (like for coercion).
            if ( auto ctor = detail::constant_folder::fold(builder(), resolved); ctor && *ctor ) {
                HILTI_DEBUG(logging::debug::Operator,
                            util::fmt("folded %s -> constant %s (%s)", *resolved, **ctor, resolved->location()));
                resolved = builder()->expressionCtor(*ctor, resolved->meta());
            }

            HILTI_DEBUG(logging::debug::Operator, util::fmt("-> %s, resolves to %s", dbg_msg, *resolved))
            return resolved;
        };

        auto try_all_candidates = [&](std::vector<ExpressionPtr>* resolved, std::set<operator_::Kind>* kinds_resolved,
                                      operator_::Priority priority) {
            for ( auto style : styles ) {
                if ( disallow_type_changes )
                    style |= CoercionStyle::DisallowTypeChanges;

                HILTI_DEBUG(logging::debug::Operator, util::fmt("style: %s", to_string(style)));
                logging::DebugPushIndent _(logging::debug::Operator);

                for ( const auto& c : candidates ) {
                    if ( priority != c->signature().priority )
                        // Not looking at operators of this priority right now.
                        continue;

                    if ( priority == operator_::Priority::Low && kinds_resolved->count(c->kind()) )
                        // Already have a higher priority match for this operator kind.
                        continue;

                    HILTI_DEBUG(logging::debug::Operator, util::fmt("candidate: %s (%s)", c->name(), c->print()));
                    logging::DebugPushIndent _(logging::debug::Operator);

                    if ( auto r = try_candidate(c, u->operands(), style, u->meta(), "candidate matches") ) {
                        kinds_resolved->insert(c->kind());
                        resolved->push_back(std::move(r));
                    }
                    else {
                        auto operands = u->operands();
                        // Try to swap the operators for commutative operators.
                        if ( operator_::isCommutative(c->kind()) && operands.size() == 2 ) {
                            if ( auto r = try_candidate(c, node::Range<Expression>({operands[1], operands[0]}), style,
                                                        u->meta(), "candidate matches with operands swapped") ) {
                                kinds_resolved->insert(c->kind());
                                resolved->emplace_back(std::move(r));
                            }
                        }
                    }
                }

                if ( resolved->size() )
                    return;
            }
        };

        HILTI_DEBUG(logging::debug::Operator,
                    util::fmt("trying to resolve: %s (%s)", u->printSignature(), u->location()));
        logging::DebugPushIndent _(logging::debug::Operator);

        std::set<operator_::Kind> kinds_resolved;
        std::vector<ExpressionPtr> resolved;

        try_all_candidates(&resolved, &kinds_resolved, operator_::Priority::Normal);
        if ( resolved.size() )
            return resolved;

        try_all_candidates(&resolved, &kinds_resolved, operator_::Priority::Low);
        return resolved;
    }

    void operator()(Attribute* n) final {
        if ( const auto& tag = n->tag(); tag == "&cxxname" && n->hasValue() ) {
            // Normalize values passed as `&cxxname` so they always are interpreted as FQNs by enforcing leading
            // `::`.
            if ( const auto& value = n->valueAsString(); value && ! util::startsWith(*value, "::") ) {
                auto a = builder()->attribute(tag, builder()->string(util::fmt("::%s", *value)));
                replaceNode(n, a);
            }
        }
    }

    void operator()(ctor::Default* n) final {
        if ( auto t = skipReferenceType(n->type()); t->isResolved() ) {
            if ( ! t->type()->parameters().empty() ) {
                if ( auto x = n->typeArguments(); x.size() ) {
                    if ( auto coerced = coerceCallArguments(x, t->type()->parameters()); coerced && *coerced ) {
                        recordChange(n, builder()->ctorTuple(**coerced), "call arguments");
                        n->setTypeArguments(context(), std::move(**coerced));
                    }
                }
            }
        }
    }

    void operator()(ctor::List* n) final {
        if ( ! expression::areResolved(n->value()) )
            return; // cannot do anything yet

        if ( ! n->type()->isResolved() ) {
            if ( auto ntype = typeForExpressions(n, n->value(), n->type()->type()->elementType()) ) {
                recordChange(n, ntype, "type");
                n->setType(context(), builder()->qualifiedType(builder()->typeList(ntype), false));
            }
        }

        if ( n->elementType()->type()->isA<type::Unknown>() ) {
            // If we use a list to initialize another list/set/vector, and
            // coercion has figured out how to type the list for that coercion
            // even though the list's type on its own isn't known, then
            // transfer the container's element type over.
            if ( auto parent = n->parent()->tryAs<ctor::Coerced>(); parent && parent->type()->isResolved() ) {
                QualifiedTypePtr etype;

                if ( auto l = parent->type()->type()->tryAs<type::List>() )
                    etype = l->elementType();
                else if ( auto s = parent->type()->type()->tryAs<type::Set>() )
                    etype = s->elementType();
                else if ( auto v = parent->type()->type()->tryAs<type::Vector>() )
                    etype = v->elementType();

                if ( etype && ! etype->type()->isA<type::Unknown>() ) {
                    recordChange(n, util::fmt("set type inferred from container to %s", *etype));
                    n->setType(context(), builder()->qualifiedType(builder()->typeList(etype), true));
                }
            }
        }

        if ( auto coerced = coerceExpressions(n->value(), n->elementType()); coerced && *coerced ) {
            recordChange(n, builder()->ctorTuple(**coerced), "elements");
            n->setValue(context(), **coerced);
        }
    }

    void operator()(ctor::Map* n) final {
        for ( const auto& e : n->value() ) {
            if ( ! (e->key()->isResolved() && e->value()->isResolved()) )
                return; // cannot do anything yet
        }

        if ( ! n->type()->isResolved() ) {
            QualifiedTypePtr key;
            QualifiedTypePtr value;

            for ( const auto& e : n->value() ) {
                if ( ! key )
                    key = e->key()->type();
                else if ( ! type::same(e->key()->type(), key) ) {
                    n->addError("inconsistent key types in map");
                    return;
                }

                if ( ! value )
                    value = e->value()->type();
                else if ( ! type::same(e->value()->type(), value) ) {
                    n->addError("inconsistent value types in map");
                    return;
                }
            }

            if ( ! (key && value) ) {
                // empty map
                key = builder()->qualifiedType(builder()->typeUnknown(), true);
                value = builder()->qualifiedType(builder()->typeUnknown(), true);
            }

            auto ntype = builder()->qualifiedType(builder()->typeMap(key, value, n->meta()), false);
            if ( ! type::same(ntype, n->type()) ) {
                recordChange(n, ntype, "type");
                n->setType(context(), ntype);
            }
        }

        bool changed = false;
        ctor::map::Elements nelems;
        for ( const auto& e : n->value() ) {
            auto k = coerceExpression(builder(), e->key(), n->keyType());
            auto v = coerceExpression(builder(), e->value(), n->valueType());
            if ( ! (k && v) ) {
                changed = false;
                break;
            }

            if ( k.nexpr || v.nexpr ) {
                nelems.emplace_back(builder()->ctorMapElement(*k.coerced, *v.coerced));
                changed = true;
            }
            else
                nelems.push_back(e);
        }

        if ( changed ) {
            recordChange(n, builder()->ctorMap(nelems), "value");
            n->setValue(context(), nelems);
        }
    }

    void operator()(ctor::Optional* n) final {
        if ( ! n->type()->isResolved() && n->value()->isResolved() ) {
            recordChange(n, n->value()->type(), "type");
            n->setType(context(), builder()->qualifiedType(builder()->typeOptional(n->value()->type()), false));
        }
    }

    void operator()(ctor::Result* n) final {
        if ( ! n->type()->isResolved() && n->value()->isResolved() ) {
            recordChange(n, n->value()->type(), "type");
            n->setType(context(), builder()->qualifiedType(builder()->typeResult(n->value()->type()), true));
        }
    }

    void operator()(ctor::Set* n) final {
        if ( ! expression::areResolved(n->value()) )
            return; // cannot do anything yet

        if ( ! n->type()->isResolved() ) {
            if ( auto ntype = typeForExpressions(n, n->value(), n->type()->type()->elementType()) ) {
                recordChange(n, ntype, "type");
                n->setType(context(), builder()->qualifiedType(builder()->typeSet(ntype), false));
            }
        }

        if ( auto coerced = coerceExpressions(n->value(), n->elementType()); coerced && *coerced ) {
            recordChange(n, builder()->ctorTuple(**coerced), "elements");
            n->setValue(context(), **coerced);
        }
    }

    void operator()(ctor::Struct* n) final {
        for ( const auto& f : n->fields() ) {
            if ( ! f->expression()->isResolved() )
                return; // cannot do anything yet
        }

        if ( ! n->type()->isResolved() ) {
            Declarations fields;
            for ( const auto& f : n->fields() )
                fields.emplace_back(builder()->declarationField(f->id(), f->expression()->type(),
                                                                builder()->attributeSet({}), f->meta()));

            auto ntype = builder()->qualifiedType(builder()->typeStruct(type::Struct::AnonymousStruct(),
                                                                        std::move(fields), n->meta()),
                                                  false);
            recordChange(n, ntype, "type");
            n->setType(context(), ntype);
        }
    }

    void operator()(ctor::Tuple* n) final {
        if ( ! n->type()->isResolved() && expression::areResolved(n->value()) ) {
            auto elems = node::transform(n->value(), [](const auto& e) { return e->type(); });
            auto t = builder()->qualifiedType(builder()->typeTuple(elems, n->meta()), true);
            recordChange(n, t, "type");
            n->setType(context(), t);
        }
    }

    void operator()(ctor::Vector* n) final {
        if ( ! expression::areResolved(n->value()) )
            return; // cannot do anything yet

        if ( ! n->type()->isResolved() ) {
            if ( auto ntype = typeForExpressions(n, n->value(), n->type()->type()->elementType()) ) {
                recordChange(n, ntype, "type");
                n->setType(context(), builder()->qualifiedType(builder()->typeVector(ntype), false));
            }
        }

        if ( auto coerced = coerceExpressions(n->value(), n->elementType()); coerced && *coerced ) {
            recordChange(n, builder()->ctorTuple(**coerced), "elements");
            n->setValue(context(), **coerced);
        }
    }

    void operator()(declaration::GlobalVariable* n) final {
        ExpressionPtr init;
        std::optional<Expressions> args;

        if ( auto e = n->init(); e && ! type::sameExceptForConstness(n->type(), e->type()) ) {
            if ( auto x = coerceTo(n, e, n->type(), false, true) )
                init = x;
        }

        if ( n->type()->isResolved() && (! n->type()->type()->parameters().empty()) && n->typeArguments().size() ) {
            auto coerced = coerceCallArguments(n->typeArguments(), n->type()->type()->parameters());
            if ( coerced && *coerced )
                args = std::move(*coerced);
        }

        if ( init || args ) {
            if ( init ) {
                recordChange(n, init, "init expression");
                n->setInit(context(), init);
            }

            if ( args ) {
                recordChange(n, builder()->ctorTuple(*args), "type arguments");
                n->setTypeArguments(context(), std::move(*args));
            }
        }

        if ( n->type()->isAuto() ) {
            if ( auto init = n->init(); init && init->isResolved() ) {
                recordChange(n, init->type(), "type");
                n->setType(context(), init->type());
            }
        }
    }

    void operator()(declaration::Constant* n) final {
        if ( auto x = coerceTo(n, n->value(), n->type()->recreateAsLhs(context()), false, true) ) {
            recordChange(n, x, "value");
            n->setValue(context(), x);
        }
    }

    void operator()(declaration::LocalVariable* n) final {
        ExpressionPtr init;
        std::optional<Expressions> args;

        if ( auto e = n->init() ) {
            if ( auto x = coerceTo(n, e, n->type(), false, true) )
                init = std::move(x);
        }

        if ( (! n->type()->type()->parameters().empty()) && n->typeArguments().size() ) {
            auto coerced = coerceCallArguments(n->typeArguments(), n->type()->type()->parameters());
            if ( coerced && *coerced )
                args = std::move(*coerced);
        }

        if ( init || args ) {
            if ( init ) {
                recordChange(n, init, "init expression");
                n->setInit(context(), init);
            }

            if ( args ) {
                recordChange(n, builder()->ctorTuple(*args), "type arguments");
                n->setTypeArguments(context(), std::move(*args));
            }
        }

        if ( n->type()->isAuto() ) {
            if ( auto init = n->init(); init && init->isResolved() ) {
                recordChange(n, init->type(), "type");
                n->setType(context(), init->type());
            }
        }
    }

    void operator()(declaration::Field* n) final {
        if ( ! n->linkedType() ) {
            auto t = n->parent()->as<UnqualifiedType>();
            n->setLinkedType(t);
            recordChange(n, util::fmt("linked to type '%s'", *t));
        }

        if ( auto a = n->attributes()->find("&default") ) {
            auto val = a->valueAsExpression();
            if ( auto x = coerceTo(n, *val, n->type(), false, true) ) {
                recordChange(val->get(), x, "attribute");
                n->attributes()->remove("&default");
                n->attributes()->add(context(), builder()->attribute("&default", x));
            }
        }

        if ( n->type()->type()->isA<type::Function>() && ! n->operator_() ) {
            if ( auto t = n->linkedType(); t && t->typeID() ) {
                // We register operators here so that we have the type ID for
                // the struct available.
                recordChange(n, "creating member call operator");
                std::unique_ptr<struct_::MemberCall> op(new struct_::MemberCall(n->as<declaration::Field>()));
                n->setOperator(op.get());
                operator_::registry().register_(std::move(op));
            }
        }
    }

    void operator()(declaration::Function* n) final {
        if ( auto ns = n->id().namespace_() ) {
            // Link namespaced function to its base type and/or prototype.
            NodeDerivedPtr<declaration::Type> linked_type;
            NodeDerivedPtr<Declaration> linked_prototype;

            if ( auto resolved = scope::lookupID<declaration::Type>(ns, n, "struct type") ) {
                linked_type = resolved->first;

                for ( const auto& field : linked_type->type()->type()->as<type::Struct>()->fields(n->id().local()) ) {
                    auto method_type = field->type()->type()->tryAs<type::Function>();
                    if ( ! method_type ) {
                        n->addError(util::fmt("'%s' is not a method of type '%s'", n->id().local(), linked_type->id()));
                        return;
                    }

                    if ( areEquivalent(n->function()->ftype(), method_type) )
                        linked_prototype = field;
                }

                if ( ! linked_prototype ) {
                    n->addError(
                        util::fmt("struct type '%s' has no matching method '%s'", linked_type->id(), n->id().local()));
                    return;
                }
            }

            else {
                for ( const auto& x : context()->root()->scope()->lookupAll(n->id()) ) {
                    if ( auto f = x.node->tryAs<declaration::Function>() ) {
                        if ( areEquivalent(n->function()->ftype(), f->function()->ftype()) ) {
                            if ( ! linked_prototype ||
                                 ! f->function()->body() ) // prefer declarations wo/ implementation
                                linked_prototype = f;
                        }
                    }
                }
            }

            if ( linked_type ) {
                if ( ! n->linkedType() ) {
                    n->setLinkedType(linked_type);
                    recordChange(n, util::fmt("linked to type '%s'", linked_type->canonicalID()));

                    n->setLinkage(declaration::Linkage::Struct);
                    recordChange(n, util::fmt("set linkage to struct"));
                }
                else {
                    assert(linked_type->canonicalID() ==
                           n->linkedType()->canonicalID()); // shouldn't changed once bound
                    assert(n->linkage() == declaration::Linkage::Struct);
                }
            }

            if ( linked_prototype ) {
                if ( ! n->linkedPrototype() ) {
                    n->setLinkedPrototype(linked_prototype);
                    recordChange(n, util::fmt("linked to prototype '%s'", linked_prototype->canonicalID()));
                }
                else
                    assert(linked_prototype->canonicalID() ==
                           n->linkedPrototype()->canonicalID()); // shouldn't changed once bound
            }
        }

        if ( n->linkage() != declaration::Linkage::Struct && ! n->operator_() ) {
            recordChange(n, "creating function call operator");
            std::unique_ptr<function::Call> op(new function::Call(n->as<declaration::Function>()));
            n->setOperator(op.get());
            operator_::registry().register_(std::move(op));
        }
    }

    void operator()(declaration::ImportedModule* n) final {
        if ( ! n->uid() ) {
            auto current_module = n->parent<declaration::Module>();
            assert(current_module);

            auto uid = context()->importModule(n->id(), n->scope(), n->parseExtension(),
                                               current_module->uid().process_extension, n->searchDirectories());

            if ( ! uid ) {
                logger().error(util::fmt("cannot import module '%s': %s", n->id(), uid.error()), n->meta().location());
                return;
            }

            recordChange(n, util::fmt("imported module %s", *uid));
            n->setUID(*uid);
            current_module->addDependency(*uid);

            if ( ! context()->driver()->driverOptions().skip_dependencies )
                context()->driver()->registerUnit(Unit::fromExistingUID(context()->driver()->context(), *uid));
        }
    }

    void operator()(declaration::Module* n) final {
        if ( auto p = n->moduleProperty("%skip-implementation") )
            n->setSkipImplementation(true);
    }

    void operator()(declaration::Parameter* n) final {
        if ( auto def = n->default_() ) {
            if ( auto x = coerceTo(n, def, n->type(), false, true) ) {
                recordChange(n, x, "default value");
                n->setDefault(context(), x);
            }
        }
    }

    void operator()(declaration::Type* n) final {
        if ( auto t = n->type()->type(); ! t->declaration() ) {
            t->setDeclaration(n->as<declaration::Type>());
            recordChange(t.get(),
                         util::fmt("set declaration to '%s'", n->canonicalID())); // record after making change to log
                                                                                  // with ID instead  of rolling out
        }
    }

    void operator()(Expression* n) final {
        if ( n->isResolved() && ! n->isA<expression::Ctor>() ) {
            auto ctor = detail::constant_folder::fold(builder(), n->as<Expression>());
            if ( ! ctor ) {
                n->addError(ctor.error());
                return;
            }

            if ( *ctor ) {
                auto nexpr = builder()->expressionCtor(*ctor, (*ctor)->meta());
                replaceNode(n, nexpr);
            }
        }
    }

    void operator()(expression::Assign* n) final {
        // Rewrite assignments to map elements to use the `index_assign` operator.
        if ( auto index_non_const = n->target()->tryAs<operator_::map::IndexNonConst>() ) {
            const auto& map = index_non_const->op0();
            const auto& map_type = map->type()->type()->as<type::Map>();
            const auto& key_type = map_type->keyType();
            const auto& value_type = map_type->valueType();

            auto key = index_non_const->op1();
            if ( key->type() != key_type ) {
                if ( auto nexpr = hilti::coerceExpression(builder(), key, key_type).nexpr )
                    key = std::move(nexpr);
            }

            auto value = n->source();
            if ( value->type() != value_type ) {
                if ( auto nexpr = hilti::coerceExpression(builder(), value, value_type).nexpr )
                    value = std::move(nexpr);
            }

            auto index_assign =
                builder()->expressionUnresolvedOperator(hilti::operator_::Kind::IndexAssign,
                                                        {map, std::move(key), std::move(value)}, n->meta());

            replaceNode(n, index_assign);
        }

        // Rewrite assignments involving struct elements to use the non-const member operator.
        if ( auto member_const = n->target()->tryAs<operator_::struct_::MemberConst>() ) {
            auto op = operator_::registry().byName("struct::MemberNonConst");
            assert(op);
            auto new_lhs = op->instantiate(builder(), member_const->operands(), member_const->meta());
            auto new_assign = builder()->expressionAssign(*new_lhs, n->source(), n->meta());
            replaceNode(n, new_assign);
        }

        // Rewrite assignments involving tuple ctors on the LHS to use the
        // tuple's custom by-element assign operator. We need this to get
        // constness right.
        auto lhs_ctor = n->target()->tryAs<expression::Ctor>();
        if ( lhs_ctor && lhs_ctor->ctor()->isA<ctor::Tuple>() ) {
            if ( n->source()->isResolved() && n->target()->isResolved() ) {
                auto op = operator_::registry().byName("tuple::CustomAssign");
                assert(op);
                auto x = *op->instantiate(builder(), {n->target(), n->source()}, n->meta());
                replaceNode(n, x);
            }
        }

        if ( auto x = coerceTo(n, n->source(), n->target()->type(), false, true) ) {
            recordChange(n, x, "source");
            n->setSource(context(), x);
        }
    }

    void operator()(expression::BuiltInFunction* n) final {
        if ( auto coerced = coerceCallArguments(n->arguments(), n->parameters()); coerced && *coerced ) {
            recordChange(n, builder()->ctorTuple(**coerced), "call arguments");
            n->setArguments(context(), **coerced);
        }
    }

    void operator()(expression::Deferred* n) final {
        if ( ! n->type()->isResolved() && n->expression()->isResolved() ) {
            recordChange(n, n->expression()->type());
            n->setType(context(), n->expression()->type());
        }
    }

    void operator()(expression::Keyword* n) final {
        if ( n->kind() == expression::keyword::Kind::Scope && ! n->type()->isResolved() ) {
            auto ntype = builder()->qualifiedType(builder()->typeString(), true);
            recordChange(n, ntype);
            n->setType(context(), ntype);
        }
    }

    void operator()(expression::ListComprehension* n) final {
        if ( ! n->type()->isResolved() && n->output()->isResolved() ) {
            auto ntype = builder()->qualifiedType(builder()->typeList(n->output()->type()), false);
            recordChange(n, ntype);
            n->setType(context(), ntype);
        }

        if ( ! n->local()->type()->isResolved() && n->input()->isResolved() ) {
            auto container = n->input()->type();
            if ( ! container->type()->iteratorType() ) {
                n->addError("right-hand side of list comprehension is not iterable");
                return;
            }

            const auto& et = container->type()->elementType();
            recordChange(n->local().get(), et);
            n->local()->setType(context(), et);
        }
    }

    void operator()(expression::LogicalAnd* n) final {
        if ( auto x = coerceTo(n, n->op0(), n->type(), true, false) ) {
            recordChange(n, x, "op0");
            n->setOp0(context(), std::move(x));
        }

        if ( auto x = coerceTo(n, n->op1(), n->type(), true, false) ) {
            recordChange(n, x, "op1");
            n->setOp1(context(), std::move(x));
        }
    }

    void operator()(expression::LogicalNot* n) final {
        if ( auto x = coerceTo(n, n->expression(), n->type(), true, false) ) {
            recordChange(n, x, "expression");
            n->setExpression(context(), std::move(x));
        }
    }

    void operator()(expression::LogicalOr* n) final {
        if ( auto x = coerceTo(n, n->op0(), n->type(), true, false) ) {
            recordChange(n, x, "op0");
            n->setOp0(context(), std::move(x));
        }

        if ( auto x = coerceTo(n, n->op1(), n->type(), true, false) ) {
            recordChange(n, x, "op1");
            n->setOp1(context(), std::move(x));
        }
    }

    void operator()(expression::Name* n) final {
        if ( ! n->resolvedDeclaration() ) {
            auto resolved = scope::lookupID<Declaration>(n->id(), n, "declaration");
            if ( resolved ) {
                recordChange(n, resolved->first);
                n->setResolvedDeclaration(context(), resolved->first);
            }
            else {
                // If we are inside a call expression, the name may map to multiple
                // function declarations (overloads and hooks). We leave it to operator
                // resolving to figure that out and don't report an error here.
                auto op = n->parent()->tryAs<expression::UnresolvedOperator>();
                if ( ! op || op->kind() != operator_::Kind::Call ) {
                    if ( n->id() == ID("__dd") )
                        // Provide better error message
                        n->addError("$$ is not available in this context", node::ErrorPriority::High);
                    else
                        n->addError(resolved.error(), node::ErrorPriority::High);
                }
            }
        }
    }

    void operator()(expression::PendingCoerced* n) final {
        if ( auto ner = hilti::coerceExpression(builder(), n->expression(), n->type()); ner.coerced ) {
            if ( ner.nexpr )
                // A coercion expression was created, use it.
                replaceNode(n, ner.nexpr);
            else
                replaceNode(n, n->expression());
        }
        else
            n->addError(util::fmt("cannot coerce expression '%s' to type '%s'", *n->expression(), *n->type()));
    }

    void operator()(expression::Ternary* n) final {
        if ( ! n->true_()->isResolved() || ! n->false_()->isResolved() ) {
            // Coerce the second branch to the type of the first. This isn't quite
            // ideal, but as good as we can do right now.
            if ( auto coerced = coerceExpression(builder(), n->false_(), n->true_()->type());
                 coerced && coerced.nexpr ) {
                recordChange(n, coerced.nexpr, "ternary");
                n->setFalse(context(), coerced.nexpr);
            }
        }
    }

    void operator()(expression::UnresolvedOperator* n) final {
        if ( n->kind() == operator_::Kind::Cast && n->areOperandsUnified() ) {
            // We hardcode that a cast<> operator can always perform any
            // legal coercion. This helps in cases where we need to force a
            // specific coercion to take place.
            static auto casted_coercion = operator_::get("generic::CastedCoercion");
            if ( hilti::coerceExpression(builder(), n->operands()[0], n->op1()->as<expression::Type_>()->typeValue(),
                                         CoercionStyle::TryAllForMatching | CoercionStyle::ContextualConversion) ) {
                replaceNode(n, *casted_coercion->instantiate(builder(), n->operands(), n->meta()));
                return;
            }
        }

        // Try to resolve operator.

        std::vector<const Operator*> candidates;

        if ( n->kind() == operator_::Kind::Call ) {
            if ( ! n->op1()->isResolved() )
                return;

            auto [valid, functions] = operator_::registry().functionCallCandidates(n);
            if ( ! valid )
                return;

            candidates = *functions;
        }

        if ( n->areOperandsUnified() ) {
            if ( n->kind() == operator_::Kind::MemberCall )
                candidates = operator_::registry().byMethodID(n->op1()->as<expression::Member>()->id());

            if ( candidates.empty() )
                candidates = operator_::registry().byKind(n->kind());
        }

        if ( candidates.empty() )
            return;

        auto matches = matchOperators(n, candidates, n->kind() == operator_::Kind::Cast);
        if ( matches.empty() )
            return;

        if ( matches.size() > 1 ) {
            // This is only ok if all matches are function calls executing
            // implementations of the same hook.
            if ( ! checkForHooks(builder(), n, matches) ) {
                std::vector<std::string> context = {"candidates:"};
                for ( const auto& op : matches ) {
                    auto resolved = op->as<hilti::expression::ResolvedOperator>();
                    context.emplace_back(
                        util::fmt("- %s [%s]", resolved->printSignature(), resolved->operator_().name()));
                }

                n->addError(util::fmt("operator usage is ambiguous: %s", n->printSignature()), std::move(context));
                return;
            }
        }

        if ( auto match = matches[0]->tryAs<expression::ResolvedOperator>() ) {
            if ( n->kind() == operator_::Kind::Call ) {
                if ( auto ftype = match->op0()->type()->type()->tryAs<type::Function>() )
                    recordAutoParameters(*ftype, match->op1());
            }

            if ( n->kind() == operator_::Kind::MemberCall ) {
                if ( auto stype = match->op0()->type()->type()->tryAs<type::Struct>() ) {
                    auto id = match->op1()->as<expression::Member>()->id();
                    if ( auto field = stype->field(id) ) {
                        auto ftype = field->type()->type()->as<type::Function>();
                        recordAutoParameters(*ftype, match->op2());
                    }
                }
            }
        }

        replaceNode(n, matches[0]);
    }

    void operator()(Function* n) final {
        if ( n->ftype()->result()->isAuto() ) {
            // Look for a `return` to infer the return type.
            auto v = visitor::PreOrder();
            for ( const auto i : v.walk(n->as<Function>()) ) {
                if ( auto x = i->tryAs<statement::Return>(); x && x->expression() && x->expression()->isResolved() ) {
                    const auto& rt = x->expression()->type();
                    recordChange(n, rt, "auto return");
                    n->ftype()->setResultType(context(), rt);
                    break;
                }
            }
        }
    }

    void operator()(operator_::generic::New* n) final {
        if ( auto etype = n->op0()->tryAs<expression::Type_>();
             etype && ! etype->typeValue()->type()->parameters().empty() ) {
            auto args = n->op1()->as<expression::Ctor>()->ctor()->as<ctor::Tuple>()->value();
            if ( auto coerced = coerceCallArguments(args, etype->typeValue()->type()->parameters());
                 coerced && *coerced ) {
                auto ntuple = builder()->expressionCtor(builder()->ctorTuple(**coerced), n->op1()->meta());
                recordChange(n, ntuple, "type arguments");
                n->setOp1(context(), ntuple);
            }
        }
    }

    void operator()(operator_::map::Get* n) final {
        if ( auto nargs = coerceMethodArgument(n, 1, n->result()) ) {
            if ( *nargs ) {
                recordChange(n, *nargs, "default value");
                n->setOp2(context(), *nargs);
            }
        }
        else
            n->addError(nargs.error());
    }

    // TODO(bbannier): Ideally instead of inserting this coercion we would
    // define the operator to take some `keyType` derived from the type of the
    // passed `map` and perform the coercion automatically when resolving the
    // function call.
    void operator()(operator_::map::In* n) final {
        if ( auto x = coerceTo(n, n->op0(), n->op1()->type()->type()->as<type::Map>()->keyType(), true, false) ) {
            recordChange(n, x, "call argument");
            n->setOp0(context(), x);
        }
    }

    // TODO(bbannier): Ideally instead of inserting this coercion we would
    // define the operator to take some `elementType` derived from the type of the
    // passed `set` and perform the coercion automatically when resolving the
    // function call.
    void operator()(operator_::set::In* n) final {
        if ( auto x = coerceTo(n, n->op0(), n->op1()->type()->type()->as<type::Set>()->elementType(), true, false) ) {
            recordChange(n, x, "call argument");
            n->setOp0(context(), x);
        }
    }

    void operator()(operator_::tuple::CustomAssign* n) final {
        if ( n->op0()->isResolved() && n->op1()->isResolved() ) {
            auto lhs = n->op0()->as<expression::Ctor>()->ctor()->as<ctor::Tuple>();

            if ( ! type::same(lhs->type(), n->op1()->type()) ) {
                auto lhs_type = lhs->type()->type()->as<type::Tuple>();
                auto rhs_type = n->op1()->type()->type()->tryAs<type::Tuple>();

                if ( rhs_type && lhs_type->elements().size() ==
                                     rhs_type->elements().size() ) { // validator will report if not same size
                    bool changed = false;
                    Expressions new_elems;

                    const auto& lhs_type_elements = lhs_type->elements();
                    const auto& rhs_type_elements = rhs_type->elements();

                    for ( auto i = 0U; i < lhs_type->elements().size(); i++ ) {
                        static auto op = operator_::get("tuple::Index");
                        const auto& lhs_elem_type = lhs_type_elements[i]->type();
                        auto rhs_elem_type = rhs_type_elements[i]->type();
                        auto rhs_elem =
                            builder()->expressionTypeWrapped(*op->instantiate(builder(),
                                                                              {n->op1(), builder()->integer(i)},
                                                                              n->meta()),
                                                             rhs_elem_type);


                        if ( auto x = coerceTo(n, rhs_elem, lhs_elem_type, false, true) ) {
                            changed = true;
                            new_elems.push_back(std::move(x));
                        }
                        else
                            new_elems.emplace_back(std::move(rhs_elem));
                    }

                    if ( changed ) {
                        auto new_rhs = builder()->tuple(new_elems);
                        recordChange(n, new_rhs, "tuple assign");
                        n->setOp1(context(), new_rhs);
                    }
                }
            }
        }
    }

    void operator()(operator_::vector::PushBack* n) final {
        if ( n->op0()->isResolved() && n->op2()->isResolved() ) {
            // Need to coerce the element here as the normal overload resolution
            // couldn't know the element type yet.
            auto etype = n->op0()->type()->type()->as<type::Vector>()->elementType();
            auto elem = methodArgument(n, 0);

            if ( auto x =
                     coerceTo(n, n->op2(), builder()->qualifiedType(builder()->typeTuple({std::move(etype)}), true),
                              false, true) ) {
                recordChange(n, x, "element type");
                n->setOp2(context(), x);
            }
        }
    }

    void operator()(statement::Assert* n) final {
        if ( ! n->expectException() ) {
            if ( auto x = coerceTo(n, n->expression(), builder()->qualifiedType(builder()->typeBool(), true), true,
                                   false) ) {
                recordChange(n, x, "expression");
                n->setExpression(context(), x);
            }
        }
    }

    void operator()(statement::If* n) final {
        if ( auto cond = n->condition() ) {
            if ( auto x = coerceTo(n, cond, builder()->qualifiedType(builder()->typeBool(), true), true, false) ) {
                recordChange(n, x, "condition");
                n->setCondition(context(), x);
            }
        }

        if ( n->init() && ! n->condition() ) {
            auto cond = builder()->expressionName(n->init()->id());
            n->setCondition(context(), std::move(cond));
            recordChange(n, cond);
        }
    }

    void operator()(statement::For* n) final {
        if ( ! n->local()->type()->isResolved() && n->sequence()->isResolved() ) {
            const auto& t = n->sequence()->type();
            if ( ! t->type()->iteratorType() ) {
                n->addError("expression is not iterable");
                return;
            }

            const auto& et = t->type()->iteratorType()->type()->dereferencedType();
            recordChange(n, et);
            n->local()->setType(context(), et);
        }
    }

    void operator()(statement::Return* n) final {
        auto func = n->parent<Function>();
        if ( ! func ) {
            n->addError("return outside of function");
            return;
        }

        if ( auto e = n->expression() ) {
            const auto& t = func->ftype()->result();

            if ( auto x = coerceTo(n, e, t, false, true) ) {
                recordChange(n, x, "expression");
                n->setExpression(context(), x);
            }
        }
    }

    void operator()(statement::Switch* n) final { n->preprocessCases(context()); }

    void operator()(statement::While* n) final {
        if ( auto cond = n->condition() ) {
            if ( auto x = coerceTo(n, cond, builder()->qualifiedType(builder()->typeBool(), true), true, false) ) {
                recordChange(n, x, "condition");
                n->setCondition(context(), x);
            }
        }
    }

    void operator()(type::bitfield::BitRange* n) final {
        if ( ! type::isResolved(n->itemType()) ) {
            auto t = n->ddType();

            if ( auto a = n->attributes()->find("&convert") )
                t = (*a->valueAsExpression())->type();

            if ( t->isResolved() ) {
                recordChange(n, t, "set item type");
                n->setItemType(context(), t);
            }
        }

        if ( n->ctorValue() ) {
            if ( auto x = coerceTo(n, n->ctorValue(), n->itemType(), false, true) ) {
                recordChange(n, x, "bits value");
                n->setCtorValue(context(), x);
            }
        }
    }

    void operator()(type::Name* n) final {
        if ( ! n->resolvedType() ) {
            if ( auto resolved = scope::lookupID<declaration::Type>(n->id(), n, "type") ) {
                auto decl = resolved->first;
                recordChange(n, decl);
                n->setResolvedType(decl);
            }
            else
                n->addError(resolved.error(), node::ErrorPriority::High);
        }

        if ( auto decl = n->resolvedType(); decl && decl->isOnHeap() ) {
            if ( auto qtype = n->parent()->tryAs<QualifiedType>() ) {
                auto replace = false;

                if ( n->parent(2)->tryAs<Declaration>() )
                    replace = true;

                if ( decl->parent(2)->isA<declaration::LocalVariable>() &&
                     ! decl->parent(3)->isA<statement::Declaration>() )
                    replace = false;

                if ( replace ) {
                    auto rt = builder()->typeValueReference(qtype, Location("<on-heap-replacement>"));
                    replaceNode(qtype.get(), builder()->qualifiedType(rt, false, Side::LHS));
                }
            }
        }
    }
};

// Visitor to resolve any auto parameters that we inferred during the main resolver pass.
struct VisitorApplyAutoParameters : visitor::MutatingPostOrder {
    VisitorApplyAutoParameters(Builder* builder, const ::Resolver& v)
        : visitor::MutatingPostOrder(builder, logging::debug::Resolver), resolver(v) {}

    const ::Resolver& resolver;

    void operator()(declaration::Parameter* n) final {
        if ( ! n->type()->type()->isA<type::Auto>() )
            return;

        assert(n->canonicalID());
        auto i = resolver.auto_params.find(n->canonicalID());
        if ( i == resolver.auto_params.end() )
            return;

        recordChange(n, i->second);
        n->setType(context(), i->second);
    }
};


} // anonymous namespace

bool detail::resolver::resolve(Builder* builder, const ASTRootPtr& root) {
    util::timing::Collector _("hilti/compiler/ast/resolver");

    auto v1 = Resolver(builder, root);
    hilti::visitor::visit(v1, root);

    auto v2 = VisitorApplyAutoParameters(builder, v1);
    hilti::visitor::visit(v2, root);

    return v1.isModified() || v2.isModified();
}
