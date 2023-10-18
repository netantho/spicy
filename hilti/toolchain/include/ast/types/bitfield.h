// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>
#include <vector>

#include <hilti/ast/attribute.h>
#include <hilti/ast/declarations/expression.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/expressions/keyword.h>
#include <hilti/ast/id.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/integer.h>

namespace hilti::type {

class Bitfield;

namespace bitfield {

/** AST node for a bitfield element. */
class BitRange final : public Node {
public:
    ~BitRange() final;

    const auto& id() const { return _id; }
    auto lower() const { return _lower; }
    auto upper() const { return _upper; }
    auto fieldWidth() const { return _field_width; }
    auto itemType() const { return child<QualifiedType>(0); }
    auto attributes() const { return child<AttributeSet>(1); }
    auto ctorValue() const { return child<Expression>(2); }
    auto dd() const { return child<declaration::Expression>(3); }
    auto ddType() const { return dd()->expression()->type(); }

    node::Properties properties() const final {
        auto p = node::Properties{
            {"id", _id},
            {"lower", _lower},
            {"upper", _upper},
            {"field_width", _field_width},
        };

        return Node::properties() + p;
    }

    void setItemType(ASTContext* ctx, const QualifiedTypePtr& t) { setChild(ctx, 0, t); }
    void setAttributes(ASTContext* ctx, const AttributeSetPtr& attrs) { setChild(ctx, 1, attrs); }
    void setCtorValue(ASTContext* ctx, const ExpressionPtr& e) { setChild(ctx, 2, e); }

    static auto create(ASTContext* ctx, const ID& id, int lower, int upper, int field_width, AttributeSetPtr attrs = {},
                       const ExpressionPtr& ctor_value = nullptr, const Meta& meta = Meta()) {
        if ( ! attrs )
            attrs = AttributeSet::create(ctx);

        auto dd = expression::Keyword::createDollarDollarDeclaration(
            ctx, QualifiedType::create(ctx, type::UnsignedInteger::create(ctx, field_width), Constness::Const));

        return NodeDerivedPtr<BitRange>(
            new BitRange(ctx, node::flatten(QualifiedType::createAuto(ctx), attrs, ctor_value, dd), id, lower, upper,
                         field_width, meta));
    }

    static auto create(ASTContext* ctx, const ID& id, int lower, int upper, int field_width, AttributeSetPtr attrs = {},
                       const Meta& meta = Meta()) {
        if ( ! attrs )
            attrs = AttributeSet::create(ctx);

        return create(ctx, id, lower, upper, field_width, attrs, nullptr, meta);
    }

protected:
    friend class type::Bitfield;

    BitRange(ASTContext* ctx, Nodes children, ID id, int lower, int upper, int field_width, Meta meta = {})
        : Node(ctx, std::move(children), std::move(meta)),
          _id(std::move(id)),
          _lower(lower),
          _upper(upper),
          _field_width(field_width) {}

    HILTI_NODE(BitRange);

private:
    ID _id;
    int _lower = 0;
    int _upper = 0;
    int _field_width = 0;
};

using BitRangePtr = std::shared_ptr<BitRange>;
using BitRanges = std::vector<BitRangePtr>;

} // namespace bitfield

/** AST node for a `bitfield` type. */
class Bitfield : public UnqualifiedType {
public:
    int width() const { return _width; }
    auto attributes() const { return child<AttributeSet>(1); }

    auto bits(bool include_hidden = false) const {
        if ( include_hidden )
            return children<bitfield::BitRange>(1, {});
        else
            return children<bitfield::BitRange>(1, -1);
    }

    bitfield::BitRangePtr bits(const ID& id) const;
    std::optional<int> bitsIndex(const ID& id) const;

    /**
     * If at least one of the bits comes with a pre-defined value, this builds
     * a bitfield ctor value that corresponds to all values defined by any of
     * the bits. If none does, return nothing.
     */
    CtorPtr ctorValue(ASTContext* ctx);

    void addField(ASTContext* ctx, const bitfield::BitRangePtr& f) { addChild(ctx, f); }

    std::string_view typeClass() const final { return "bitfield"; }

    bool isAllocable() const final { return true; }
    bool isMutable() const final { return true; }
    bool isResolved() const final {
        auto bs = bits();
        return std::all_of(bs.begin(), bs.end(), [&](const auto& b) { return b->itemType()->isResolved(); });
    }

    node::Properties properties() const final {
        auto p = node::Properties{{"width", _width}};
        return UnqualifiedType::properties() + p;
    }

    static auto create(ASTContext* ctx, int width, type::bitfield::BitRanges bits, AttributeSetPtr attrs,
                       const Meta& m = Meta()) {
        if ( ! attrs )
            attrs = AttributeSet::create(ctx);

        auto value = bitfield::BitRange::create(ctx, ID("__value__"), 0, width - 1, width, {}, m);
        return NodeDerivedPtr<Bitfield>(new Bitfield(ctx, node::flatten(attrs, std::move(bits), value), width, m));
    }

    static auto create(ASTContext* ctx, Wildcard _, const Meta& m = Meta()) {
        return NodeDerivedPtr<Bitfield>(new Bitfield(ctx, Wildcard(), m));
    }

protected:
    Bitfield(ASTContext* ctx, Nodes children, int width, Meta meta)
        : UnqualifiedType(ctx, {}, std::move(children), std::move(meta)), _width(width) {}

    Bitfield(ASTContext* ctx, Wildcard _, const Meta& meta) : UnqualifiedType(ctx, Wildcard(), {"bitfield(*)"}, meta) {}

    HILTI_NODE(Bitfield)

private:
    int _width = 0;
};


} // namespace hilti::type
