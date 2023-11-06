// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/attribute.h>
#include <hilti/ast/ctor.h>
#include <hilti/ast/declarations/expression.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/expressions/keyword.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/auto.h>
#include <hilti/base/uniquer.h>

#include <spicy/ast/engine.h>
#include <spicy/ast/hook.h>
#include <spicy/ast/types/sink.h>
#include <spicy/ast/types/unit-item.h>
#include <spicy/ast/types/unit-items/unit-hook.h>

namespace spicy::type::unit::item {

/** AST node for a unit field. */
class Field : public unit::Item, public hilti::node::WithDocString {
public:
    auto id() const { return _id; }
    const auto& index() const { return _index; }

    // Only one of these will have return value.
    auto ctor() const { return child<Ctor>(5); }
    auto item() const { return child<Item>(5); }
    auto type() const { return child<QualifiedType>(5); }

    auto repeatCount() const { return child<Expression>(6); }
    auto attributes() const { return child<AttributeSet>(7); }
    auto condition() const { return child<Expression>(8); }
    auto arguments() const { return children<Expression>(_args_start, _args_end); }
    auto sinks() const { return children<Expression>(_sinks_start, _sinks_end); }
    auto hooks() const { return children<Hook>(_sinks_end, {}); }

    Engine engine() const { return _engine; }

    auto isSkip() const { return _is_skip; }
    auto isContainer() const { return repeatCount() != nullptr; }
    auto isForwarding() const { return _is_forwarding; }
    auto isTransient() const { return _is_transient; }
    auto isAnonymous() const { return _is_anonymous; }
    auto emitHook() const { return ! isAnonymous() || hooks().size(); }

    QualifiedTypePtr originalType() const {
        if ( auto t = child<QualifiedType>(1) )
            return t;

        if ( auto c = ctor() )
            return c->type();

        if ( auto i = item() )
            return i->itemType();

        hilti::util::cannot_be_reached();
    }

    auto parseType() const { return child<QualifiedType>(2); }

    QualifiedTypePtr ddType() const {
        if ( auto x = child<hilti::declaration::Expression>(3) )
            return x->expression()->type();
        else
            return child<QualifiedType>(0); // `auto`
    }

    DeclarationPtr dd() const {
        if ( auto x = child<hilti::declaration::Expression>(3) )
            return x;
        else
            return {};
    }

    // Get the `&convert` expression, if any.
    std::optional<std::pair<ExpressionPtr, QualifiedTypePtr>> convertExpression() const;

    void setForwarding(bool is_forwarding) { _is_forwarding = is_forwarding; }
    void setTransient(bool is_transient) { _is_transient = is_transient; }
    void setDDType(ASTContext* ctx, const QualifiedTypePtr& t) {
        setChild(ctx, 3, hilti::expression::Keyword::createDollarDollarDeclaration(ctx, t));
    }
    void setIndex(uint64_t index) { _index = index; }
    void setItemType(ASTContext* ctx, QualifiedTypePtr t) { setChild(ctx, 4, std::move(t)); }
    void setParseType(ASTContext* ctx, QualifiedTypePtr t) { setChild(ctx, 2, std::move(t)); }
    void setSkip(bool skip) { _is_skip = skip; }
    void setOriginalType(ASTContext* ctx, QualifiedTypePtr t) { setChild(ctx, 1, std::move(t)); }

    QualifiedTypePtr itemType() const final { return child<QualifiedType>(4); }

    bool isResolved() const final { return item() || itemType()->isResolved(); }

    node::Properties properties() const final {
        auto p = node::Properties{{"engine", to_string(_engine)},
                                  {"anonymous", _is_anonymous},
                                  {"transient", _is_transient},
                                  {"forwarding", _is_forwarding},
                                  {"skip", _is_skip}};
        return unit::Item::properties() + p;
    }

    static auto create(ASTContext* ctx, ID id, const QualifiedTypePtr& type, Engine engine, bool skip, Expressions args,
                       ExpressionPtr repeat, Expressions sinks, AttributeSetPtr attrs, ExpressionPtr cond,
                       spicy::Hooks hooks, const Meta& meta = {}) {
        return _create(ctx, std::move(id), type, type, engine, skip, std::move(args), std::move(repeat),
                       std::move(sinks), std::move(attrs), std::move(cond), std::move(hooks), meta);
    }

    static auto create(ASTContext* ctx, ID id, CtorPtr ctor, Engine engine, bool skip, Expressions args,
                       ExpressionPtr repeat, Expressions sinks, AttributeSetPtr attrs, ExpressionPtr cond,
                       spicy::Hooks hooks, const Meta& meta = {}) {
        return _create(ctx, std::move(id), nullptr, std::move(ctor), engine, skip, std::move(args), std::move(repeat),
                       std::move(sinks), std::move(attrs), std::move(cond), std::move(hooks), meta);
    }

    static auto create(ASTContext* ctx, ID id, type::unit::ItemPtr item, Engine engine, bool skip, Expressions args,
                       ExpressionPtr repeat, Expressions sinks, AttributeSetPtr attrs, ExpressionPtr cond,
                       spicy::Hooks hooks, const Meta& meta = {}) {
        return _create(ctx, std::move(id), nullptr, std::move(item), engine, skip, std::move(args), std::move(repeat),
                       std::move(sinks), std::move(attrs), std::move(cond), std::move(hooks), meta);
    }

protected:
    Field(ASTContext* ctx, Nodes children, size_t args_start, size_t args_end, size_t sinks_start, size_t sinks_end,
          size_t hooks_start, size_t hooks_end, ID id, Engine engine, bool skip, const Meta& meta)
        : unit::Item(ctx, std::move(children), meta),
          _id(id ? std::move(id) : _uniquer.get("anon")),
          _is_anonymous(! _id),
          _is_skip(skip),
          _engine(engine),
          _args_start(static_cast<int>(args_start)),
          _args_end(static_cast<int>(args_end)),
          _sinks_start(static_cast<int>(sinks_start)),
          _sinks_end(static_cast<int>(sinks_end)),
          _hooks_start(static_cast<int>(hooks_start)),
          _hooks_end(static_cast<int>(hooks_end)) {}

    HILTI_NODE(spicy, Field)

private:
    static NodeDerivedPtr<Field> _create(ASTContext* ctx, ID id, QualifiedTypePtr org_type, NodePtr node, Engine engine,
                                         bool skip, Expressions args, ExpressionPtr repeat, Expressions sinks,
                                         AttributeSetPtr attrs, ExpressionPtr cond, spicy::Hooks hooks,
                                         const Meta& meta) {
        if ( ! attrs )
            attrs = AttributeSet::create(ctx);

        auto auto_ = QualifiedType::create(ctx, hilti::type::Auto::create(ctx), hilti::Constness::Const, meta);
        auto num_args = args.size();
        auto num_sinks = sinks.size();
        auto num_hooks = hooks.size();

        return NodeDerivedPtr<Field>(
            new Field(ctx,
                      node::flatten(auto_, std::move(org_type), auto_, nullptr, auto_, std::move(node),
                                    std::move(repeat), std::move(attrs), std::move(cond), std::move(args),
                                    std::move(sinks), std::move(hooks)),
                      9U, 9U + num_args, 9U + num_args, 9U + num_args + num_sinks, 9U + num_args + num_sinks,
                      9U + num_args + num_sinks + num_hooks, std::move(id), engine, skip, meta));
    }

    ID _id;
    bool _is_forwarding = false;
    bool _is_transient = false;
    bool _is_anonymous;
    bool _is_skip;
    Engine _engine;
    std::optional<uint64_t> _index;
    const int _args_start;
    const int _args_end;
    const int _sinks_start;
    const int _sinks_end;
    const int _hooks_start;
    const int _hooks_end;

    static inline hilti::util::Uniquer<ID> _uniquer;
};

} // namespace spicy::type::unit::item
