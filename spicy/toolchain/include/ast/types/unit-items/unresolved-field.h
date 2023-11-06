// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/attribute.h>
#include <hilti/ast/ctor.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/auto.h>

#include <spicy/ast/engine.h>
#include <spicy/ast/hook.h>
#include <spicy/ast/types/sink.h>
#include <spicy/ast/types/unit-item.h>

namespace spicy::type::unit::item {

/**
 * AST node for a unit field with its type determined by a not yet resolved
 * ID. The ID may refer to either a type or an ctor.
 */
class UnresolvedField : public unit::Item {
public:
    auto fieldID() const { return _id; }
    auto unresolvedID() const { return _unresolved_id; }
    const auto& index() const { return _index; }

    // Only one of these will have return value.
    auto ctor() const { return child<Ctor>(1); }
    auto item() const { return child<Item>(1); }
    auto type() const { return child<QualifiedType>(1); }

    auto repeatCount() const { return child<Expression>(2); }
    auto attributes() const { return child<AttributeSet>(3); }
    auto condition() const { return child<Expression>(4); }
    auto arguments() const { return children<Expression>(_args_start, _args_end); }
    auto sinks() const { return children<Expression>(_sinks_start, _sinks_end); }
    auto hooks() const { return children<Hook>(_sinks_end, {}); }
    auto isSkip() const { return _is_skip; }
    Engine engine() const { return _engine; }

    void setIndex(uint64_t index) { _index = index; }
    void setSkip(bool skip) { _is_skip = skip; }
    void setType(ASTContext* ctx, QualifiedTypePtr t) { setChild(ctx, 1, std::move(t)); }

    QualifiedTypePtr itemType() const final { return child<QualifiedType>(0); /* return `auto` */ }

    bool isResolved() const final { return false; }

    node::Properties properties() const final {
        auto p = node::Properties{{"engine", to_string(_engine)}};
        return unit::Item::properties() + p;
    }

    static auto create(ASTContext* ctx, ID id, QualifiedTypePtr type, Engine engine, bool skip, Expressions args,
                       ExpressionPtr repeat, Expressions sinks, AttributeSetPtr attrs, ExpressionPtr cond,
                       spicy::Hooks hooks, const Meta& meta = {}) {
        return _create(ctx, std::move(id), std::move(type), engine, skip, std::move(args), std::move(repeat),
                       std::move(sinks), std::move(attrs), std::move(cond), std::move(hooks), meta);
    }

    static auto create(ASTContext* ctx, ID id, CtorPtr ctor, Engine engine, bool skip, Expressions args,
                       ExpressionPtr repeat, Expressions sinks, AttributeSetPtr attrs, ExpressionPtr cond,
                       spicy::Hooks hooks, const Meta& meta = {}) {
        return _create(ctx, std::move(id), std::move(ctor), engine, skip, std::move(args), std::move(repeat),
                       std::move(sinks), std::move(attrs), std::move(cond), std::move(hooks), meta);
    }

    static auto create(ASTContext* ctx, ID id, type::unit::ItemPtr item, Engine engine, bool skip, Expressions args,
                       ExpressionPtr repeat, Expressions sinks, AttributeSetPtr attrs, ExpressionPtr cond,
                       spicy::Hooks hooks, const Meta& meta = {}) {
        return _create(ctx, std::move(id), std::move(item), engine, skip, std::move(args), std::move(repeat),
                       std::move(sinks), std::move(attrs), std::move(cond), std::move(hooks), meta);
    }

    static auto create(ASTContext* ctx, ID id, ID unresolved_id, Engine engine, bool skip, Expressions args,
                       ExpressionPtr repeat, Expressions sinks, AttributeSetPtr attrs, ExpressionPtr cond,
                       spicy::Hooks hooks, const Meta& meta = {}) {
        auto f = _create(ctx, std::move(id), nullptr, engine, skip, std::move(args), std::move(repeat),
                         std::move(sinks), std::move(attrs), std::move(cond), std::move(hooks), meta);
        f->_unresolved_id = std::move(unresolved_id);
        return f;
    }


protected:
    UnresolvedField(ASTContext* ctx, Nodes children, size_t args_start, size_t args_end, size_t sinks_start,
                    size_t sinks_end, ID id, Engine engine, bool skip, const Meta& meta)
        : unit::Item(ctx, std::move(children), meta),
          _id(std::move(id)),
          _is_skip(skip),
          _engine(engine),
          _args_start(static_cast<int>(args_start)),
          _args_end(static_cast<int>(args_end)),
          _sinks_start(static_cast<int>(sinks_start)),
          _sinks_end(static_cast<int>(sinks_end)) {}

    HILTI_NODE(spicy, UnresolvedField)

private:
    static NodeDerivedPtr<UnresolvedField> _create(ASTContext* ctx, ID id, NodePtr node, Engine engine, bool skip,
                                                   Expressions args, ExpressionPtr repeat, Expressions sinks,
                                                   AttributeSetPtr attrs, ExpressionPtr cond, spicy::Hooks hooks,
                                                   const Meta& meta) {
        if ( ! attrs )
            attrs = AttributeSet::create(ctx);

        auto auto_ = QualifiedType::create(ctx, hilti::type::Auto::create(ctx), hilti::Constness::Const, meta);
        auto num_args = args.size();
        auto num_sinks = sinks.size();

        return NodeDerivedPtr<UnresolvedField>(
            new UnresolvedField(ctx,
                                node::flatten(std::move(auto_), std::move(node), std::move(repeat), std::move(attrs),
                                              std::move(cond), std::move(args), std::move(sinks), std::move(hooks)),
                                4U, 4U + num_args, 4U + num_args, 4U + num_args + num_sinks, std::move(id), engine,
                                skip, meta));
    }

    ID _id;
    ID _unresolved_id;
    bool _is_skip;
    Engine _engine;
    std::optional<uint64_t> _index;
    const int _args_start;
    const int _args_end;
    const int _sinks_start;
    const int _sinks_end;
};

} // namespace spicy::type::unit::item
