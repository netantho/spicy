// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <utility>

#include <hilti/ast/builder/builder.h>
#include <hilti/ast/ctors/coerced.h>
#include <hilti/ast/ctors/null.h>
#include <hilti/ast/ctors/tuple.h>
#include <hilti/ast/expressions/coerced.h>
#include <hilti/ast/expressions/ctor.h>
#include <hilti/ast/expressions/member.h>
#include <hilti/ast/expressions/resolved-operator.h>
#include <hilti/ast/expressions/unresolved-operator.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/any.h>
#include <hilti/ast/types/auto.h>
#include <hilti/ast/types/operand-list.h>
#include <hilti/ast/types/optional.h>
#include <hilti/ast/types/reference.h>
#include <hilti/ast/types/result.h>
#include <hilti/base/logger.h>
#include <hilti/base/timing.h>
#include <hilti/compiler/detail/coercer.h>
#include <hilti/compiler/plugin.h>
#include <hilti/global.h>

#include "ast/type.h"

using namespace hilti;
using namespace util;

namespace hilti::logging::debug {
inline const DebugStream Coercer("coercer");
} // namespace hilti::logging::debug

namespace {

struct VisitorCtor : visitor::PreOrder {
    explicit VisitorCtor(Builder* builder, QualifiedTypePtr dst, bitmask<CoercionStyle> style)
        : builder(builder), dst(std::move(dst)), style(style) {}

    Builder* builder;
    QualifiedTypePtr dst;
    bitmask<CoercionStyle> style;

    CtorPtr result = nullptr;

    void operator()(ctor::Enum* c) final {
        if ( dst->type()->isA<type::Bool>() && (style & CoercionStyle::ContextualConversion) )
            result = builder->ctorBool(c->value()->id() != ID("Undef"), c->meta());
    }

    void operator()(ctor::Map* c) final {
        if ( auto t = dst->type()->tryAs<type::Map>() ) {
            ctor::map::Elements nelemns;
            for ( const auto& e : c->value() ) {
                auto k = hilti::coerceExpression(builder, e->key(), t->keyType(), style);
                auto v = hilti::coerceExpression(builder, e->value(), t->elementType(), style);

                if ( k && v )
                    nelemns.emplace_back(builder->ctorMapElement(*k.coerced, *v.coerced));
                else
                    return;
            }

            result = builder->ctorMap(t->keyType(), t->elementType(), nelemns, c->meta());
        }
    }

    void operator()(ctor::Null* c) final {
        if ( auto t = dst->type()->tryAs<type::Optional>() ) {
            result = builder->ctorOptional(t->dereferencedType());
            return;
        }

        if ( auto t = dst->type()->tryAs<type::StrongReference>() ) {
            result = builder->ctorStrongReference(t->dereferencedType());
            return;
        }

        if ( auto t = dst->type()->tryAs<type::WeakReference>() ) {
            result = builder->ctorWeakReference(t->dereferencedType());
            return;
        }
    }

    void operator()(ctor::List* c) final {
        if ( auto t = dst->type()->tryAs<type::List>() ) {
            Expressions nexprs;
            for ( const auto& e : c->value() ) {
                if ( auto x =
                         hilti::coerceExpression(builder, e, t->elementType(), CoercionStyle::TryAllForAssignment) )
                    nexprs.push_back(*x.coerced);
                else
                    return;
            }
            result = builder->ctorList(t->elementType(), std::move(nexprs), c->meta());
        }

        if ( auto t = dst->type()->tryAs<type::Vector>() ) {
            auto dt = t->isWildcard() ? c->elementType() : t->elementType();

            Expressions nexprs;
            for ( const auto& e : c->value() ) {
                if ( auto x = hilti::coerceExpression(builder, e, dt, CoercionStyle::TryAllForAssignment) )
                    nexprs.push_back(*x.coerced);
                else
                    return;
            }
            result = builder->ctorVector(dt, std::move(nexprs), c->meta());
        }

        if ( auto t = dst->type()->tryAs<type::Set>() ) {
            auto dt = t->isWildcard() ? c->elementType() : t->elementType();

            Expressions nexprs;
            for ( const auto& e : c->value() ) {
                if ( auto x = hilti::coerceExpression(builder, e, dt, CoercionStyle::TryAllForAssignment) )
                    nexprs.push_back(*x.coerced);
                else
                    return;
            }
            result = builder->ctorSet(dt, nexprs, c->meta());
        }
    }

    void operator()(ctor::Real* c) final {
        // Note: double->Integral constant conversions check 'non-narrowing' via
        // double->Int->double roundtrip - the generated code looks good.

        if ( auto t = dst->type()->tryAs<type::SignedInteger>() ) {
            double d = c->value();

            if ( static_cast<double>(static_cast<int64_t>(d)) == d ) {
                switch ( t->isWildcard() ? 64 : t->width() ) {
                    case 8:
                        if ( static_cast<double>(int8_t(d)) == d )
                            result = builder->ctorSignedInteger(int64_t(d), 8, c->meta());
                        break;

                    case 16:
                        if ( static_cast<double>(static_cast<int16_t>(d)) == d )
                            result = builder->ctorSignedInteger(static_cast<int64_t>(d), 16, c->meta());
                        break;

                    case 32:
                        if ( static_cast<double>(static_cast<int32_t>(d)) == d )
                            result = builder->ctorSignedInteger(static_cast<int64_t>(d), 32, c->meta());
                        break;

                    case 64: result = builder->ctorSignedInteger(static_cast<int64_t>(d), 64, c->meta()); break;
                }
            }
        }

        if ( auto t = dst->type()->tryAs<type::UnsignedInteger>() ) {
            double d = c->value();

            if ( static_cast<double>(static_cast<uint64_t>(d)) == d ) {
                switch ( t->isWildcard() ? 64 : t->width() ) {
                    case 8:
                        if ( static_cast<double>(static_cast<uint8_t>(d)) == d )
                            result = builder->ctorUnsignedInteger(static_cast<uint64_t>(d), 8, c->meta());
                        break;

                    case 16:
                        if ( static_cast<double>(static_cast<uint16_t>(d)) == d )
                            result = builder->ctorUnsignedInteger(uint64_t(d), 16, c->meta());
                        break;

                    case 32:
                        if ( static_cast<double>(static_cast<uint32_t>(d)) == d )
                            result = builder->ctorUnsignedInteger(static_cast<uint64_t>(d), 32, c->meta());
                        break;

                    case 64: result = builder->ctorUnsignedInteger(static_cast<uint64_t>(d), 64, c->meta()); break;
                }
            }
        }
    }

    void operator()(ctor::Set* c) final {
        if ( auto t = dst->type()->tryAs<type::Set>() ) {
            Expressions nexprs;
            for ( const auto& e : c->value() ) {
                if ( auto x = hilti::coerceExpression(builder, e, t->elementType(), style) )
                    nexprs.push_back(*x.coerced);
                else
                    return;
            }
            result = builder->ctorSet(t->elementType(), std::move(nexprs), c->meta());
        }
    }

    void operator()(ctor::SignedInteger* c) final {
        if ( auto t = dst->type()->tryAs<type::SignedInteger>() ) {
            if ( t->width() == 64 ) {
                result = c->as<Ctor>();
                return;
            }

            int64_t i = c->value();

            if ( t->isWildcard() ) {
                result = builder->ctorSignedInteger(i, c->width(), c->meta());
                return;
            }

            else if ( auto [imin, imax] = util::signed_integer_range(t->width()); i >= imin && i <= imax ) {
                result = builder->ctorSignedInteger(i, t->width(), c->meta());
                return;
            }
        }

        if ( auto t = dst->type()->tryAs<type::UnsignedInteger>(); t && c->value() >= 0 ) {
            auto u = static_cast<uint64_t>(c->value());

            if ( t->isWildcard() ) {
                result = builder->ctorUnsignedInteger(u, c->width(), c->meta());
                return;
            }

            else if ( auto [zero, umax] = util::unsigned_integer_range(t->width()); u <= umax ) {
                result = builder->ctorUnsignedInteger(u, t->width(), c->meta());
                return;
            }
        }

        if ( auto t = dst->type()->tryAs<type::Real>() ) {
            if ( static_cast<int64_t>(static_cast<double>(c->value())) == c->value() ) {
                result = builder->ctorReal(static_cast<double>(c->value()));
                return;
            }
        }

        if ( dst->type()->isA<type::Bool>() && (style & CoercionStyle::ContextualConversion) ) {
            result = builder->ctorBool(c->value() != 0, c->meta());
            return;
        }

        if ( auto t = dst->type()->tryAs<type::Bitfield>(); t && c->value() >= 0 ) {
            auto u = static_cast<uint64_t>(c->value());
            if ( auto [umin, umax] = util::unsigned_integer_range(t->width()); u >= umin && u <= umax ) {
                result = builder->ctorUnsignedInteger(u, t->width(), c->meta());
                return;
            }
        }
    }

    void operator()(ctor::Vector* c) final {
        if ( auto t = dst->type()->tryAs<type::Vector>() ) {
            Expressions nexprs;
            for ( const auto& e : c->value() ) {
                if ( auto x = hilti::coerceExpression(builder, e, t->elementType(), style) )
                    nexprs.push_back(*x.coerced);
                else
                    return;
            }
            result = builder->ctorVector(t->elementType(), std::move(nexprs), c->meta());
        }
    }

    void operator()(ctor::UnsignedInteger* c) final {
        if ( auto t = dst->type()->tryAs<type::UnsignedInteger>() ) {
            if ( t->width() == 64 ) {
                result = c->as<Ctor>();
                return;
            }

            uint64_t u = c->value();

            if ( t->isWildcard() ) {
                result = builder->ctorUnsignedInteger(u, c->width(), c->meta());
                return;
            }

            else if ( auto [umin, umax] = util::unsigned_integer_range(t->width()); u >= umin && u <= umax ) {
                result = builder->ctorUnsignedInteger(u, t->width(), c->meta());
                return;
            }
        }

        if ( auto t = dst->type()->tryAs<type::SignedInteger>(); t && static_cast<int64_t>(c->value()) >= 0 ) {
            auto i = static_cast<int64_t>(c->value());

            if ( t->isWildcard() ) {
                result = builder->ctorSignedInteger(i, c->width(), c->meta());
                return;
            }

            else if ( auto [imin, imax] = util::signed_integer_range(t->width()); i >= imin && i <= imax ) {
                result = builder->ctorSignedInteger(i, t->width(), c->meta());
                return;
            }
        }

        if ( dst->type()->isA<type::Bool>() && (style & CoercionStyle::ContextualConversion) ) {
            result = builder->ctorBool(c->value() != 0, c->meta());
            return;
        }

        if ( auto t = dst->type()->tryAs<type::Real>() ) {
            if ( static_cast<uint64_t>(static_cast<double>(c->value())) == c->value() ) {
                result = builder->ctorReal(static_cast<double>(c->value()));
                return;
            }
        }

        if ( auto t = dst->type()->tryAs<type::Bitfield>() ) {
            uint64_t u = c->value();
            if ( auto [umin, umax] = util::unsigned_integer_range(t->width()); u >= umin && u <= umax ) {
                result = builder->ctorUnsignedInteger(u, t->width(), c->meta());
                return;
            }
        }
    }

    void operator()(ctor::Tuple* c) final {
        if ( auto t = dst->type()->tryAs<type::Tuple>() ) {
            auto vc = c->value();
            auto ve = t->elements();

            if ( vc.size() != ve.size() )
                return;

            Expressions coerced;
            coerced.reserve(vc.size());

            for ( auto i = std::make_pair(vc.begin(), ve.begin()); i.first != vc.end(); ++i.first, ++i.second ) {
                if ( auto x = hilti::coerceExpression(builder, *i.first, (*i.second)->type(),
                                                      CoercionStyle::TryAllForAssignment) ) {
                    coerced.push_back(*x.coerced);
                }
                else
                    return;
            }

            result = builder->ctorTuple(coerced, c->meta());
        }
    }

    void operator()(ctor::Struct* c) final {
        auto dst_ = dst;

        if ( (dst->type()->isA<type::ValueReference>() || dst->type()->isA<type::StrongReference>()) &&
             ! dst->type()->isReferenceType() )
            // Allow coercion from value to reference type with new instance.
            dst_ = dst->type()->dereferencedType();

        if ( auto dtype = dst_->type()->tryAs<type::Struct>() ) {
            if ( ! dst_->type() )
                // Wait for this to be resolved.
                return;

            auto stype = c->type()->type()->as<type::Struct>();

            std::set<ID> src_fields;
            for ( const auto& f : stype->fields() )
                src_fields.insert(f->id());

            std::set<ID> dst_fields;
            for ( const auto& f : dtype->fields() )
                dst_fields.insert(f->id());

            // Check for fields in ctor that type does not have.
            if ( ! util::set_difference(src_fields, dst_fields).empty() )
                return;

            // Check for fields that the type has, but are left out in the
            // ctor. These must all be either optional, internal, or have a
            // default.
            auto x = util::set_difference(dst_fields, src_fields);

            std::set<ID> can_be_missing;

            for ( const auto& k : x ) {
                auto f = dtype->field(k);
                if ( f->isOptional() || f->isInternal() || f->default_() || f->type()->type()->isA<type::Function>() )
                    can_be_missing.insert(k);
            }

            x = util::set_difference(x, can_be_missing);

            if ( ! x.empty() )
                // Uninitialized fields.
                return;

            // Coerce each field.
            ctor::struct_::Fields nf;

            for ( const auto& sf : stype->fields() ) {
                const auto& df = dtype->field(sf->id());
                const auto& se = c->field(sf->id());
                assert(df && se);
                if ( const auto& ne = hilti::coerceExpression(builder, se->expression(), df->type(), style) )
                    nf.emplace_back(builder->ctorStructField(sf->id(), *ne.coerced));
                else
                    // Cannot coerce.
                    return;
            }

            result = builder->ctorStruct(std::move(nf), dst_, c->meta());

            // The original type might go away, so clear the `self` declaration
            // that keeps a weak pointer to it.
            stype->clearSelf(builder->context());
        }

        if ( auto dtype = dst_->type()->tryAs<type::Bitfield>() ) {
            if ( ! dst_->type()->typeID() )
                // Wait for this to be resolved.
                return;

            auto stype = c->type()->type()->as<type::Struct>();

            std::set<ID> src_fields;
            for ( const auto& f : stype->fields() )
                src_fields.insert(f->id());

            std::set<ID> dst_fields;
            for ( const auto& f : dtype->bits() )
                dst_fields.insert(f->id());

            // Check for fields in ctor that type does not have.
            if ( ! util::set_difference(src_fields, dst_fields).empty() )
                return;

            // Coerce each field.
            ctor::bitfield::BitRanges bits;

            for ( const auto& sf : stype->fields() ) {
                const auto& dbits = dtype->bits(sf->id());
                const auto& se = c->field(sf->id());
                assert(dbits && se);
                if ( const auto& ne = coerceExpression(builder, se->expression(), dbits->itemType(), style) )
                    bits.emplace_back(builder->ctorBitfieldBitRange(sf->id(), *ne.coerced));
                else
                    // Cannot coerce.
                    return;
            }

            result = builder->ctorBitfield(bits, builder->qualifiedType(dtype, Const), c->meta());
            return;
        }
    }
};

struct VisitorType : visitor::PreOrder {
    explicit VisitorType(Builder* builder, QualifiedTypePtr dst, bitmask<CoercionStyle> style)
        : builder(builder), dst(std::move(dst)), style(style) {}

    Builder* builder;
    QualifiedTypePtr dst;
    bitmask<CoercionStyle> style;

    QualifiedTypePtr result = nullptr;

    void operator()(type::Enum* c) final {
        if ( auto t = dst->type()->tryAs<type::Bool>(); t && (style & CoercionStyle::ContextualConversion) )
            result = dst;
    }

    void operator()(type::Interval* c) final {
        if ( auto t = dst->type()->tryAs<type::Bool>(); t && (style & CoercionStyle::ContextualConversion) )
            result = dst;
    }

    void operator()(type::Null* c) final {
        if ( auto t = dst->type()->tryAs<type::Optional>() )
            result = dst;
        else if ( auto t = dst->type()->tryAs<type::StrongReference>() )
            result = dst;
        else if ( auto t = dst->type()->tryAs<type::WeakReference>() )
            result = dst;
    }

    void operator()(type::Bytes* c) final {
        if ( dst->type()->tryAs<type::Stream>() && (style & (CoercionStyle::Assignment | CoercionStyle::FunctionCall)) )
            result = dst;
    }

    void operator()(type::Error* e) final {
        if ( auto t = dst->type()->tryAs<type::Result>() )
            result = dst;
    }

    void operator()(type::List* e) final {
        if ( auto t = dst->type()->tryAs<type::Set>(); t && type::same(t->elementType(), e->elementType()) )
            result = dst;

        else if ( auto t = dst->type()->tryAs<type::Vector>(); t && type::same(t->elementType(), e->elementType()) )
            result = dst;
    }

    void operator()(type::Optional* r) final {
        if ( auto t = dst->type()->tryAs<type::Optional>() ) {
            const auto& s = r->dereferencedType();
            const auto& d = t->dereferencedType();

            if ( type::sameExceptForConstness(s, d) && (style & CoercionStyle::Assignment) ) {
                // Assignments copy, so it's safe to turn  into the
                // destination without considering constness.
                result = dst;
                return;
            }
        }

        if ( auto t = dst->type()->tryAs<type::Bool>(); (style & CoercionStyle::ContextualConversion) && t )
            result = dst;
    }

    void operator()(type::StrongReference* r) final {
        if ( auto t = dst->type()->tryAs<type::Bool>(); (style & CoercionStyle::ContextualConversion) && t ) {
            result = dst;
            return;
        }

        if ( dst->type()->isReferenceType() ) {
            if ( type::sameExceptForConstness(r->dereferencedType(), dst->type()->dereferencedType()) ) {
                result = dst;
                return;
            }
        }

        if ( ! (style & CoercionStyle::Assignment) ) {
            if ( type::same(r->dereferencedType(), dst) ) {
                result = dst;
            }
        }
    }

    void operator()(type::Time* c) final {
        if ( auto t = dst->type()->tryAs<type::Bool>(); t && (style & CoercionStyle::ContextualConversion) )
            result = dst;
    }

    void operator()(type::Result* r) final {
        if ( auto t = dst->type()->tryAs<type::Bool>(); (style & CoercionStyle::ContextualConversion) && t )
            result = dst;

        else if ( auto t = dst->type()->tryAs<type::Optional>();
                  t && type::same(t->dereferencedType(), r->dereferencedType()) )
            result = dst;
    }

    void operator()(type::SignedInteger* src) final {
        if ( dst->type()->isA<type::Bool>() && (style & CoercionStyle::ContextualConversion) )
            result = dst;

        else if ( auto t = dst->type()->tryAs<type::SignedInteger>() ) {
            if ( src->width() <= t->width() )
                result = dst;
        }
    }

    void operator()(type::Stream* c) final {
        if ( auto t = dst->type()->tryAs<type::stream::View>() )
            result = dst;
    }

    void operator()(type::stream::View* c) final {
        if ( dst->type()->tryAs<type::Bytes>() && (style & (CoercionStyle::Assignment | CoercionStyle::FunctionCall)) )
            result = dst;
    }

    void operator()(type::Type_* src) final {
        if ( auto t = dst->type()->tryAs<type::Type_>() ) {
            // We don't allow arbitrary coercions here, just (more or less) direct matches.
            if ( auto x =
                     hilti::coerceType(builder, src->typeValue(), t->typeValue(), CoercionStyle::TryDirectForMatching) )
                result = builder->qualifiedType(builder->typeType(*x), true);
        }
    }

    void operator()(type::Union* c) final {
        if ( auto t = dst->type()->tryAs<type::Bool>(); t && (style & CoercionStyle::ContextualConversion) )
            result = dst;
    }

    void operator()(type::UnsignedInteger* src) final {
        if ( dst->type()->isA<type::Bool>() && (style & CoercionStyle::ContextualConversion) ) {
            result = dst;
            return;
        }

        if ( auto t = dst->type()->tryAs<type::UnsignedInteger>() ) {
            if ( src->width() <= t->width() ) {
                result = dst;
                return;
            }
        }

        if ( auto t = dst->type()->tryAs<type::SignedInteger>() ) {
            // As long as the target type has more bits, we can coerce.
            if ( src->width() < t->width() ) {
                result = dst;
                return;
            }
        }

        if ( auto t = dst->type()->tryAs<type::Bitfield>() ) {
            if ( src->width() <= t->width() ) {
                result = dst;
                return;
            }
        }
    }

    void operator()(type::Tuple* src) final {
        if ( auto t = dst->type()->tryAs<type::Tuple>() ) {
            auto vc = src->elements();
            auto ve = t->elements();

            if ( vc.size() != ve.size() )
                return;

            for ( auto i = std::make_pair(vc.begin(), ve.begin()); i.first != vc.end(); ++i.first, ++i.second ) {
                if ( auto x = hilti::coerceType(builder, (*i.first)->type(), (*i.second)->type()); ! x )
                    return;
            }

            result = dst;
        }
    }

    void operator()(type::ValueReference* r) final {
        if ( auto t = dst->type()->tryAs<type::Bool>(); (style & CoercionStyle::ContextualConversion) && t ) {
            if ( auto t = hilti::coerceType(builder, r->dereferencedType(), dst, style) )
                result = *t;

            return;
        }

        if ( dst->type()->isReferenceType() ) {
            if ( type::sameExceptForConstness(r->dereferencedType(), dst->type()->dereferencedType()) ) {
                result = dst;
                return;
            }
        }

        if ( type::same(r->dereferencedType(), dst) ) {
            result = dst;
            return;
        }
    }

    void operator()(type::WeakReference* r) final {
        if ( auto t = dst->type()->tryAs<type::Bool>(); (style & CoercionStyle::ContextualConversion) && t ) {
            result = dst;
            return;
        }

        if ( dst->type()->isReferenceType() ) {
            if ( type::sameExceptForConstness(r->dereferencedType(), dst->type()->dereferencedType()) ) {
                result = dst;
                return;
            }
        }

        if ( ! (style & CoercionStyle::Assignment) ) {
            if ( type::same(r->dereferencedType(), dst) ) {
                result = dst;
                return;
            }
        }
    }
};

} // anonymous namespace

// Public version going through all plugins.
Result<CtorPtr> hilti::coerceCtor(Builder* builder, CtorPtr c, const QualifiedTypePtr& dst,
                                  bitmask<CoercionStyle> style) {
    if ( type::same(c->type(), dst) )
        return std::move(c);

    for ( auto p : plugin::registry().plugins() ) {
        if ( ! (p.coerce_ctor) )
            continue;

        if ( auto nc = (*p.coerce_ctor)(builder, c, dst, style) )
            return nc;
    }

    return result::Error("could not coerce type for constructor");
}

static Result<QualifiedTypePtr> _coerceType(Builder* builder, const QualifiedTypePtr& src_,
                                            const QualifiedTypePtr& dst_, bitmask<CoercionStyle> style) {
    // TODO(robin): Not sure if this should/must replicate all the type coercion
    // login in coerceExpression(). If so, we should factor that out.
    // Update: I believe the answer is yes ... Added a few more cases, but this will
    // likely need more work.

    auto src = src_;
    while ( true ) {
        auto name = src->type()->tryAs<type::Name>();
        if ( ! name )
            break;

        if ( ! name->resolvedType() )
            return result::Error("type name has not been resolved");

        src = name->resolvedType()->type();
    }

    auto dst = dst_;
    while ( true ) {
        auto name = dst->type()->tryAs<type::Name>();
        if ( ! name )
            break;

        if ( ! name->resolvedType() )
            return result::Error("type name has not been resolved");

        dst = name->resolvedType()->type();
    }

    if ( src->type()->typeID() && dst->type()->typeID() ) {
        if ( *src->type()->typeID() == *dst->type()->typeID() )
            return dst;
        else
            return result::Error("type IDs do not match");
    }

    if ( type::same(src, dst) )
        return src;

    if ( style & CoercionStyle::Assignment ) {
        if ( type::sameExceptForConstness(src, dst) )
            return dst;
    }

    if ( style & (CoercionStyle::Assignment | CoercionStyle::FunctionCall) ) {
        if ( auto opt = dst->type()->tryAs<type::Optional>() ) {
            if ( dst->type()->isWildcard() )
                return dst;

            // All types converts into a corresponding optional.
            if ( auto x = coerceType(builder, src, opt->dereferencedType(), style | CoercionStyle::Assignment) )
                return builder->qualifiedType(builder->typeOptional(*x, src->meta()), false);
        }

        if ( auto opt = dst->type()->tryAs<type::Result>() ) {
            if ( dst->type()->isWildcard() )
                return dst;

            // All types converts into a corresponding result.
            if ( auto x = coerceType(builder, src, opt->dereferencedType(), style) )
                return builder->qualifiedType(builder->typeResult(*x, src->meta()), false);
        }

        if ( auto x = dst->type()->tryAs<type::ValueReference>(); x && ! src->type()->isReferenceType() ) {
            // All types converts into a corresponding value_ref.
            if ( auto y = coerceType(builder, src, x->dereferencedType(), style) )
                return builder->qualifiedType(builder->typeValueReference(dst, src->meta()), false);
        }
    }

    for ( auto p : plugin::registry().plugins() ) {
        if ( ! (p.coerce_type) )
            continue;

        if ( auto nt = (*p.coerce_type)(builder, src, dst, style) )
            return nt;
    }

    return result::Error("cannot coerce types");
}

// Public version going through all plugins.
Result<QualifiedTypePtr> hilti::coerceType(Builder* builder, const QualifiedTypePtr& src, const QualifiedTypePtr& dst,
                                           bitmask<CoercionStyle> style) {
    return _coerceType(builder, src, dst, style);
}

std::string hilti::to_string(bitmask<CoercionStyle> style) {
    std::vector<std::string> labels;

    if ( style & CoercionStyle::TryExactMatch )
        labels.emplace_back("try-exact-match");

    if ( style & CoercionStyle::TryConstPromotion )
        labels.emplace_back("try-const-promotion");

    if ( style & CoercionStyle::TryCoercion )
        labels.emplace_back("try-coercion");

    if ( style & CoercionStyle::TryCoercionWithinSameType )
        labels.emplace_back("try-coercion-within-same-type");

    if ( style & CoercionStyle::Assignment )
        labels.emplace_back("assignment");

    if ( style & CoercionStyle::FunctionCall )
        labels.emplace_back("function-call");

    if ( style & CoercionStyle::OperandMatching )
        labels.emplace_back("operand-matching");

    if ( style & CoercionStyle::DisallowTypeChanges )
        labels.emplace_back("disallow-type-changes");

    if ( style & CoercionStyle::ContextualConversion )
        labels.emplace_back("contextual-conversion");

    return util::join(labels, ",");
};

Result<std::pair<bool, Expressions>> hilti::coerceOperands(Builder* builder, operator_::Kind kind,
                                                           const Expressions& exprs,
                                                           const operator_::Operands& operands,
                                                           bitmask<CoercionStyle> style) {
    int num_type_changes = 0;
    bool changed = false;
    Expressions transformed;

    if ( exprs.size() > operands.size() )
        return result::Error("more expressions than operands");

    for ( const auto&& [i, op] : util::enumerate(operands) ) {
        if ( i >= exprs.size() ) {
            // Running out of operands, must have a default or be optional.
            if ( auto d = op->default_() ) {
                transformed.emplace_back(d);
                changed = true;
            }
            else if ( op->isOptional() ) {
                // transformed.push_back(hilti::expression::Ctor(hilti::builder->ctorNull()));
            }
            else
                return result::Error("stray operand");

            continue;
        }

        assert(op->type__());

        bool needs_mutable;
        QualifiedTypePtr oat;

        switch ( op->kind() ) {
            case parameter::Kind::In:
            case parameter::Kind::Copy:
                needs_mutable = false;
                oat = builder->qualifiedType(op->type__(), true, Side::RHS, op->type__()->meta());
                oat->type()->unify(builder->context(), builder->context()->root());
                break;

            case parameter::Kind::InOut:
                needs_mutable = true;
                oat = builder->qualifiedType(op->type__(), false, Side::LHS, op->type__()->meta());
                oat->type()->unify(builder->context(), builder->context()->root());
                break;

            case parameter::Kind::Unknown: logger().internalError("unknown operand kind"); break;
        }

        if ( needs_mutable && exprs[i]->isConstant() ) {
            HILTI_DEBUG(logging::debug::Coercer, util::fmt("  [param %d] need mutable expression -> failure", i));
            return result::Error("parameter requires non-constant expression");
        }

        CoercedExpression result;

        if ( kind == operator_::Kind::Call && i == 0 && exprs[0]->isA<expression::Name>() &&
             ! exprs[0]->isResolved() ) {
            // Special case: For function calls, this expression will not have
            // been resolved by the resolver because it might not unambiguously
            // refer to just a single declaration (overloading, hooks).
            // However, the resolver will have ensured a name match with all
            // the candidates, so we can just accept it.
            result.coerced = exprs[i];
        }
        else
            result = coerceExpression(builder, exprs[i], oat, style);

        if ( ! result ) {
            HILTI_DEBUG(logging::debug::Coercer,
                        util::fmt("  [param %d] matching %s against %s -> failure [%s vs %s]", i, *exprs[i]->type(),
                                  *oat, exprs[i]->type()->type()->unification().str(),
                                  oat->type()->unification().str()));
            return result::Error("could not match coercion operands");
        }

        HILTI_DEBUG(logging::debug::Coercer,
                    util::fmt("  [param %d] matching %s against %s -> success: %s (coerced expression is %s) (%s)", i,
                              *exprs[i]->type(), *oat, *(*result.coerced)->type(),
                              ((*result.coerced)->type()->isConstant() ? "const" : "non-const"),
                              (result.consider_type_changed ? "type changed" : "type not changed")));

        // We check if the primary type of the alternative has changed. Only
        // one operand must change its primary type for an alternative to
        // match.
        if ( result.consider_type_changed && (++num_type_changes > 1 || style & CoercionStyle::DisallowTypeChanges) &&
             ! (style & CoercionStyle::FunctionCall) )
            return result::Error("no valid coercion found");

        transformed.emplace_back(*result.coerced);

        if ( result.nexpr )
            changed = true;
    }

    Expressions x;
    x.reserve(transformed.size());
    for ( const auto& n : transformed )
        x.push_back(n->as<Expression>());

    return std::make_pair(changed, std::move(x));
}

static CoercedExpression _coerceExpression(Builder* builder, const ExpressionPtr& e, const QualifiedTypePtr& src_,
                                           const QualifiedTypePtr& dst_, bitmask<CoercionStyle> style, bool lhs) {
    if ( ! (style & CoercionStyle::_Recursing) )
        style |= CoercionStyle::_Recursing;

    const auto& no_change = e;
    CoercedExpression _result;
    int _line = 0;

#define RETURN(x)                                                                                                      \
    {                                                                                                                  \
        _result = (x);                                                                                                 \
        _line = __LINE__;                                                                                              \
        goto exit;                                                                                                     \
    }

    auto src = src_;
    while ( true ) {
        auto name = src->type()->tryAs<type::Name>();
        if ( ! name )
            break;

        if ( ! name->resolvedType() )
            break;

        src = name->resolvedType()->type();
    }

    auto dst = dst_;
    while ( true ) {
        auto name = dst->type()->tryAs<type::Name>();
        if ( ! name )
            break;

        if ( ! name->resolvedType() )
            break;

        dst = name->resolvedType()->type();
    }

    bool try_coercion = false;

    if ( dst->type()->isA<type::Auto>() )
        // Always accept, we're going to update the auto type later.
        RETURN(no_change);

    if ( src->type()->cxxID() && dst->type()->cxxID() ) {
        if ( *src->type()->cxxID() == *dst->type()->cxxID() ) {
            RETURN(no_change);
        }
    }

    if ( src->type()->typeID() && dst->type()->typeID() ) {
        if ( *src->type()->typeID() == *dst->type()->typeID() ) {
            RETURN(no_change);
        }
        else {
            RETURN(result::Error());
        }
    }

    if ( style & CoercionStyle::TryExactMatch ) {
        if ( type::same(src, dst) )
            RETURN(no_change);

        // TODO: Can we get rid of this special case here?
        if ( auto st = src->type()->tryAs<type::Type_>() ) {
            if ( auto dt = dst->type()->tryAs<type::Type_>() ) {
                if ( type::sameExceptForConstness(st->typeValue(), dt->typeValue()) )
                    RETURN(no_change);
            }
        }
    }

    if ( style & CoercionStyle::TryConstPromotion ) {
        if ( style & (CoercionStyle::OperandMatching | CoercionStyle::FunctionCall) ) {
            if ( type::sameExceptForConstness(src, dst) )
                RETURN(no_change);
        }

        if ( style & CoercionStyle::Assignment ) {
            /*
             * // Don't allow assigning to a constant.
             * if ( dst_is_const )
             *     RETURN(result::Error());
             */

            if ( type::sameExceptForConstness(src, dst) )
                RETURN(no_change);

            if ( dst->type()->isWildcard() && src->type()->typeClass() == dst->type()->typeClass() )
                RETURN(no_change);
        }
    }

    if ( style & CoercionStyle::Assignment ) {
        // Don't allow assignment to a non-constant target.
        /*
         * if ( dst_is_const )
         *     RETURN(result::Error());
         */
    }

    if ( dst->type()->isA<type::Any>() )
        // type::Any accepts anything without actual coercion.
        RETURN(no_change);

    if ( auto x = e->tryAs<expression::Member>() ) {
        // Make sure the expression remains a member expression, as we will
        // be expecting to cast it to that.
        if ( auto t = hilti::coerceType(builder, x->type(), dst, style) ) {
            RETURN(CoercedExpression(src, builder->expressionMember(*t, x->id(), x->meta())));
        }
        else
            RETURN(result::Error());
    }

    if ( auto o = dst->type()->template tryAs<type::OperandList>() ) {
        // Match tuple against operands according to function call rules.
        HILTI_DEBUG(logging::debug::Coercer, util::fmt("matching against call parameters"));
        logging::DebugPushIndent _(logging::debug::Coercer);

        auto c = e->template tryAs<expression::Ctor>();
        if ( ! c )
            RETURN(CoercedExpression());

        if ( auto t = c->ctor()->template tryAs<hilti::ctor::Tuple>() ) {
            // The two style options both implicitly set CoercionStyle::FunctionCall.
            CoercionStyle function_style =
                (style & CoercionStyle::TryCoercion ? CoercionStyle::TryAllForFunctionCall :
                                                      CoercionStyle::TryDirectMatchForFunctionCall);
            if ( auto result =
                     coerceOperands(builder, operator_::Kind::Call, t->value(), o->operands(), function_style) ) {
                if ( result->first ) {
                    RETURN(CoercedExpression(e->type(), builder->expressionCtor(builder->ctorTuple(result->second))));
                }
                else
                    RETURN(no_change);
            }
        }

        RETURN(CoercedExpression());
    }

    if ( style & (CoercionStyle::Assignment | CoercionStyle::FunctionCall) ) {
        if ( auto opt = dst->type()->tryAs<type::Optional>() ) {
            if ( opt->isWildcard() )
                RETURN(no_change);

            // All types converts into a corresponding optional.
            if ( auto x = coerceExpression(builder, e, opt->dereferencedType(), style) )
                RETURN(CoercedExpression(src, builder->expressionCoerced(*x.coerced, dst, e->meta())));
        }

        if ( auto result = dst->type()->tryAs<type::Result>() ) {
            if ( result->isWildcard() )
                RETURN(no_change);

            // All types convert into a corresponding result.
            if ( auto x = coerceExpression(builder, e, result->dereferencedType(), style) )
                RETURN(CoercedExpression(src, builder->expressionCoerced(*x.coerced, dst, e->meta())));
        }

        if ( auto x = dst->type()->tryAs<type::ValueReference>(); x && ! src->type()->isReferenceType() ) {
            // All types converts into a corresponding value_ref.
            if ( auto y = coerceExpression(builder, e, x->dereferencedType(), style) )
                RETURN(CoercedExpression(src, builder->expressionCoerced(*y.coerced, dst, e->meta())));
        }
    }

    if ( style & CoercionStyle::TryCoercion )
        try_coercion = true;

    if ( style & CoercionStyle::TryCoercionWithinSameType ) {
        if ( src->type()->typeClass() == dst->type()->typeClass() )
            try_coercion = true;
    }

    if ( try_coercion ) {
        if ( auto c = e->tryAs<expression::Ctor>() ) {
            if ( auto nc = hilti::coerceCtor(builder, c->ctor(), dst, style) )
                RETURN(CoercedExpression(src, builder->expressionCtor(builder->ctorCoerced(c->ctor(), *nc, c->meta()),
                                                                      e->meta())));
        }

        if ( auto t = hilti::coerceType(builder, src, dst, style) )
            // We wrap the expression into a coercion even if the new type is
            // the same as *dst*. That way the overloader has a way to
            // recognize that the types aren't identical.
            RETURN(CoercedExpression(src, builder->expressionCoerced(e, *t, e->meta())));
    }

    _result = result::Error();

exit:
    if ( logger().isEnabled(logging::debug::Coercer) )
        HILTI_DEBUG(logging::debug::Coercer,
                    util::fmt("coercing %s (%s) to %s (%s) -> %s [%s] (%s) (#%d)", *src,
                              util::replace(src->type()->unification(), "hilti::type::", ""), *dst,
                              util::replace(dst->type()->unification(), "hilti::type::", ""),
                              (_result ? util::fmt("%s (%s)", *(*_result.coerced)->type(),
                                                   util::replace((*_result.coerced)->type()->type()->unification(),
                                                                 "hilti::type::", "")) :
                                         "fail"),
                              to_string(style), e->meta().location(), _line));

#undef RETURN

    return _result;
}

// Public version going through all plugins.
CoercedExpression hilti::coerceExpression(Builder* builder, const ExpressionPtr& e, const QualifiedTypePtr& src,
                                          const QualifiedTypePtr& dst, bitmask<CoercionStyle> style, bool lhs) {
    return _coerceExpression(builder, e, src, dst, style, lhs);
}

// Public version going through all plugins.
CoercedExpression hilti::coerceExpression(Builder* builder, const ExpressionPtr& e, const QualifiedTypePtr& dst,
                                          bitmask<CoercionStyle> style, bool lhs) {
    return coerceExpression(builder, e, e->type(), dst, style, lhs);
}

// Plugin-specific version just kicking off the local visitor.
CtorPtr hilti::detail::coercer::coerceCtor(Builder* builder, const CtorPtr& c, const QualifiedTypePtr& dst,
                                           bitmask<CoercionStyle> style) {
    util::timing::Collector _("hilti/compiler/ast/coerce");

    if ( ! (c->type()->isResolved() && dst->isResolved()) )
        return {};

    auto v = VisitorCtor(builder, dst, style);
    v.dispatch(c);
    return v.result;
}

// Plugin-specific version just kicking off the local visitor.
QualifiedTypePtr hilti::detail::coercer::coerceType(Builder* builder, const QualifiedTypePtr& t,
                                                    const QualifiedTypePtr& dst, bitmask<CoercionStyle> style) {
    util::timing::Collector _("hilti/compiler/ast/coerce");

    if ( ! (t->isResolved() && dst->isResolved()) )
        return {};

    auto v = VisitorType(builder, dst, style);
    v.dispatch(t->type());
    return v.result;
}
