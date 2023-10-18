// Copyright (c) 2023 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/builder/builder.h>
#include <hilti/ast/detail/operator-registry.h>

using namespace hilti;
using namespace hilti::operator_;

namespace hilti::logging::debug {
inline const DebugStream Operator("operator");
} // namespace hilti::logging::debug

void Registry::register_(std::unique_ptr<Operator> op) { _pending.push_back(std::move(op)); }

void Registry::initPending(ASTContext* ctx) {
    if ( _pending.empty() )
        return;

    HILTI_DEBUG(hilti::logging::debug::Operator,
                hilti::util::fmt("%d operators pending to be resolved for initialization", _pending.size()));

    Builder builder(ctx);

    for ( auto i = _pending.begin(); i != _pending.end(); ) {
        auto current = i++;
        auto&& op = *current;

        auto x = op->init(&builder, ctx->root());
        if ( ! x )
            continue;

        if ( (op->kind() != Kind::Call || op->isBuiltIn()) && op->kind() != Kind::MemberCall ) {
            assert(_operators_by_name.find(op->name()) == _operators_by_name.end());
            _operators_by_name[op->name()] = op.get();
        }

        if ( op->hasOperands() ) { // only register if to be instantiated by the resolver through its operands
            _operators_by_kind[op->kind()].push_back(op.get());
            if ( op->kind() == Kind::MemberCall ) {
                auto id = op->signature().operands->op1()->type__()->as<type::Member>()->id();
                _operators_by_method[id].push_back(op.get());
            }

            if ( op->kind() == Kind::Call && op->isBuiltIn() ) {
                if ( auto member = op->signature().operands->op0()->type__()->tryAs<type::Member>() )
                    _operators_by_builtin_function[member->id()].push_back(op.get());
            }
        }
        int status;
        const auto& op_ = *op;
        std::string n = abi::__cxa_demangle(typeid(op_).name(), nullptr, nullptr, &status);
        n = util::replace(n, "::(anonymous namespace)", "");
        HILTI_DEBUG(hilti::logging::debug::Operator,
                    hilti::util::fmt("initialized operator '%s' (%s)", op->print(), n));

        _operators.push_back(std::move(op));
        _pending.erase(current);
    }
}

void Registry::debugEnforceBuiltInsAreResolved() const {
    bool abort = false;

    for ( const auto& op : _pending ) {
        if ( ! op->isBuiltIn() )
            continue;

        if ( ! abort )
            logger().error("[Internal Error] The following builtin operators were not resolved:");

        logger().error(util::fmt("    %s", op->name()));
        abort = true;
    }

    if ( abort )
        logger().fatalError("Aborting.");
}


std::pair<bool, std::optional<std::vector<const Operator*>>> Registry::functionCallCandidates(
    const expression::UnresolvedOperator* op) {
    assert(op->operands().size() > 0);

    // Try built-in function operators first, they override anything found
    // by scope lookup. (The validator will reject functions with a name
    // matching a built-in one anyway.)
    if ( auto member = op->op0()->tryAs<expression::Member>() ) {
        auto candidates = byBuiltinFunctionID(member->id());
        if ( ! candidates.empty() )
            return std::make_pair(true, std::move(candidates));
    }

    std::vector<const Operator*> candidates;
    auto callee = op->op0()->tryAs<expression::Name>();
    if ( ! callee )
        return std::make_pair(true, std::move(candidates));

    for ( const Node* n = op; n; n = n->parent() ) {
        if ( ! n->scope() )
            continue;

        for ( const auto& r : n->scope()->lookupAll(callee->id()) ) {
            auto d = r.node->tryAs<declaration::Function>();
            if ( ! d ) {
                // TODO: It's ok to refer to types for some constructor
                // expressions. Can we catch error here in some other
                // way? We don't want functions *and* types.
                continue;
                /*
                 * u->addError(util::fmt("ID '%s' resolves to something other than just functions", callee->id()));
                 * return std::make_pair(false, std::nullopt);
                 */
            }

            if ( r.external && d->linkage() != declaration::Linkage::Public )
                return std::make_pair(false, std::nullopt);

            if ( d->operator_() && d->operator_()->isInitialized() ) // not necessarily initialized yet
                candidates.emplace_back(d->operator_());
        }
    }

    return std::make_pair(true, std::move(candidates));
}
