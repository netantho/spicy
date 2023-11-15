
#include <hilti/ast/detail/operator-registry.h>
#include <hilti/ast/operator.h>

#include <spicy/ast/builder/builder.h>
#include <spicy/ast/types/unit.h>

using namespace spicy;
using namespace hilti::operator_;

spicy::unit::MemberCall::MemberCall(const type::unit::item::FieldPtr& field)
    : hilti::Operator(field->meta(), false), _field(field) {}

spicy::unit::MemberCall::~MemberCall() {}

hilti::operator_::Signature spicy::unit::MemberCall::signature(hilti::Builder* builder) const {
    auto field = MemberCall::field();
    assert(field);

    auto ftype = field->itemType()->type()->as<hilti::type::Function>();
    auto stype = field->parent(1)->as<type::Unit>();
    auto params = hilti::type::OperandList::fromParameters(builder->context(), ftype->parameters());
    auto result = ftype->result();

    return {
        .kind = Kind::MemberCall,
        .self = {hilti::parameter::Kind::InOut, nullptr, "", stype},
        .op1 = {hilti::parameter::Kind::In, builder->typeMember(ID(field->id()))},
        .op2 = {hilti::parameter::Kind::In, params},
        .result = {result->constness(), result->type()},
    };
}

hilti::Result<hilti::ResolvedOperatorPtr> spicy::unit::MemberCall::instantiate(hilti::Builder* builder,
                                                                               Expressions operands,
                                                                               const Meta& meta) const {
    auto field = MemberCall::field();
    assert(field);

    auto callee = operands[0];
    auto member = operands[1];
    auto args = operands[2];
    auto result = field->itemType()->type()->as<hilti::type::Function>()->result();

    return {operator_::unit::MemberCall::create(builder->context(), this, result,
                                                {std::move(callee), std::move(member), std::move(args)}, meta)};
}

namespace {

namespace unit {

void _checkName(hilti::expression::ResolvedOperator* op) {
    auto id = op->op1()->as<hilti::expression::Member>()->id();
    auto i = op->op0()->type()->type()->as<type::Unit>()->itemByName(id);

    if ( ! i )
        op->addError(hilti::util::fmt("unit does not have field '%s'", id));
}


QualifiedTypePtr _itemType(hilti::Builder* builder, const Expressions& operands) {
    if ( auto item = operands[0]->type()->type()->as<type::Unit>()->itemByName(
             operands[1]->as<hilti::expression::Member>()->id()) )
        return item->itemType();
    else
        return builder->qualifiedType(builder->typeUnknown(), hilti::Const);
}

QualifiedTypePtr _contextResult(hilti::Builder* builder, const Expressions& operands) {
    if ( operands.empty() )
        return builder->qualifiedType(builder->typeDocOnly("<context>&"), hilti::Const);

    if ( const auto& ctype = operands[0]->type()->type()->as<type::Unit>()->contextType() )
        return builder->qualifiedType(builder->typeStrongReference(
                                          builder->qualifiedType(ctype, hilti::Constness::NonConst)),
                                      hilti::Constness::Const);

    return builder->qualifiedType(builder->typeVoid(), hilti::Const);
}


class Unset : public hilti::Operator {
public:
    Signature signature(hilti::Builder* builder_) const final {
        auto builder = Builder(builder_);
        return {
            .kind = Kind::Unset,
            .op0 = {hilti::parameter::Kind::In, builder.typeUnit(hilti::type::Wildcard()), "unit"},
            .op1 = {hilti::parameter::Kind::In, builder.typeMember(hilti::type::Wildcard()), "<field>"},
            .ns = "unit",
            .doc = "Clears an optional field.",
        };
    }

    void validate(hilti::expression::ResolvedOperator* n) const final { _checkName(n); }

    HILTI_OPERATOR(spicy, unit::Unset)
};

class MemberNonConst : public hilti::Operator {
public:
    Signature signature(hilti::Builder* builder_) const final {
        auto builder = Builder(builder_);
        return {
            .kind = Kind::Member,
            .op0 = {hilti::parameter::Kind::InOut, builder.typeUnit(hilti::type::Wildcard()), "<unit>"},
            .op1 = {hilti::parameter::Kind::In, builder.typeMember(hilti::type::Wildcard()), "<field>"},
            .result_doc = "<field type>",
            .ns = "unit",
            .doc = R"(
Retrieves the value of a unit's field. If the field does not have a value assigned,
it returns its ``&default`` expression if that has been defined; otherwise it
triggers an exception.
)",
        };
    }

    QualifiedTypePtr result(hilti::Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return _itemType(builder, operands)->recreateAsLhs(builder->context());
    }

    void validate(hilti::expression::ResolvedOperator* n) const final { _checkName(n); }

    HILTI_OPERATOR(spicy, unit::MemberNonConst)
};

class MemberConst : public hilti::Operator {
public:
    Signature signature(hilti::Builder* builder_) const final {
        auto builder = Builder(builder_);
        return {
            .kind = Kind::Member,
            .op0 = {hilti::parameter::Kind::In, builder.typeUnit(hilti::type::Wildcard()), "<unit>"},
            .op1 = {hilti::parameter::Kind::In, builder.typeMember(hilti::type::Wildcard()), "<field>"},
            .result_doc = "<field type>",
            .ns = "unit",
            .doc = R"(
Retrieves the value of a unit's field. If the field does not have a value assigned,
it returns its ``&default`` expression if that has been defined; otherwise it
triggers an exception.
)",
        };
    }

    QualifiedTypePtr result(hilti::Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return _itemType(builder, operands)->recreateAsLhs(builder->context());
    }

    void validate(hilti::expression::ResolvedOperator* n) const final { _checkName(n); }


    HILTI_OPERATOR(spicy, unit::MemberConst)
};

class TryMember : public hilti::Operator {
public:
    Signature signature(hilti::Builder* builder_) const final {
        auto builder = Builder(builder_);
        return {
            .kind = Kind::TryMember,
            .op0 = {hilti::parameter::Kind::InOut, builder.typeUnit(hilti::type::Wildcard()), "<unit>"},
            .op1 = {hilti::parameter::Kind::In, builder.typeMember(hilti::type::Wildcard()), "<field>"},
            .result_doc = "<field type>",
            .ns = "unit",
            .doc = R"(
Retrieves the value of a unit's field. If the field does not have a value
assigned, it returns its ``&default`` expression if that has been defined;
otherwise it signals a special non-error exception to the host application
(which will normally still lead to aborting execution, similar to the standard
dereference operator, unless the host application specifically handles this
exception differently).
)",
        };
    }

    QualifiedTypePtr result(hilti::Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return _itemType(builder, operands)->recreateAsLhs(builder->context());
    }

    void validate(hilti::expression::ResolvedOperator* n) const final { _checkName(n); }

    HILTI_OPERATOR(spicy, unit::TryMember)
};

class HasMember : public hilti::Operator {
public:
    Signature signature(hilti::Builder* builder_) const final {
        auto builder = Builder(builder_);
        return {
            .kind = Kind::HasMember,
            .op0 = {hilti::parameter::Kind::InOut, builder.typeUnit(hilti::type::Wildcard()), "<unit>"},
            .op1 = {hilti::parameter::Kind::In, builder.typeMember(hilti::type::Wildcard()), "<field>"},
            .result = {hilti::Const, builder.typeBool()},
            .result_doc = "<field type>",
            .ns = "unit",
            .doc = R"(
Returns true if the unit's field has a value assigned (not counting any ``&default``).
)",
        };
    }

    QualifiedTypePtr result(hilti::Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return _itemType(builder, operands)->recreateAsLhs(builder->context());
    }

    void validate(hilti::expression::ResolvedOperator* n) const final { _checkName(n); }

    HILTI_OPERATOR(spicy, unit::HasMember)
};

class Offset : public hilti::BuiltInMemberCall {
public:
    Signature signature(hilti::Builder* builder_) const final {
        auto builder = Builder(builder_);
        return {
            .kind = Kind::MemberCall,
            .self = {hilti::parameter::Kind::In, builder.typeUnit(hilti::type::Wildcard()), "<unit>"},
            .member = "offset",
            .result = {hilti::Const, builder.typeUnsignedInteger(64)},
            .ns = "unit",
            .doc = R"(
Returns the offset of the current location in the input stream relative to the
unit's start. If executed from inside a field hook, the offset will represent
the first byte that the field has been parsed from. If this method is called
before the unit's parsing has begun, it will throw a runtime exception. Once
parsing has started, the offset will remain available for the unit's entire
life time.
)",
        };
    }

    HILTI_OPERATOR(spicy, unit::Offset);
};
HILTI_OPERATOR_IMPLEMENTATION(Offset);

class Position : public hilti::BuiltInMemberCall {
public:
    Signature signature(hilti::Builder* builder_) const final {
        auto builder = Builder(builder_);
        return {
            .kind = Kind::MemberCall,
            .self = {hilti::parameter::Kind::In, builder.typeUnit(hilti::type::Wildcard()), "<unit>"},
            .member = "position",
            .result = {hilti::Const, builder.typeStreamIterator()},
            .ns = "unit",
            .doc = R"(
Returns an iterator to the current position in the unit's input stream. If
executed from inside a field hook, the position will represent the first byte
that the field has been parsed from. If this method is called before the unit's
parsing has begun, it will throw a runtime exception.
)",
        };
    }

    HILTI_OPERATOR(spicy, unit::Position);
};
HILTI_OPERATOR_IMPLEMENTATION(Position);

class Input : public hilti::BuiltInMemberCall {
public:
    Signature signature(hilti::Builder* builder_) const final {
        auto builder = Builder(builder_);
        return {
            .kind = Kind::MemberCall,
            .self = {hilti::parameter::Kind::In, builder.typeUnit(hilti::type::Wildcard()), "<unit>"},
            .member = "input",
            .result = {hilti::Const, builder.typeStreamIterator()},
            .ns = "unit",
            .doc = R"(
Returns an iterator referring to the input location where the current unit has
begun parsing. If this method is called before the units parsing has begun, it
will throw a runtime exception. Once available, the input position will remain
accessible for the unit's entire life time.
)",
        };
    }

    HILTI_OPERATOR(spicy, unit::Input);
};
HILTI_OPERATOR_IMPLEMENTATION(Input);

class SetInput : public hilti::BuiltInMemberCall {
public:
    Signature signature(hilti::Builder* builder_) const final {
        auto builder = Builder(builder_);
        return {
            .kind = Kind::MemberCall,
            .self = {hilti::parameter::Kind::InOut, builder.typeUnit(hilti::type::Wildcard()), "<unit>"},
            .member = "set_input",
            .param0 = {.name = "i", .type = {hilti::parameter::Kind::In, builder.typeStreamIterator()}},
            .result = {hilti::Const, builder.typeVoid()},
            .ns = "unit",
            .doc = R"(
Moves the current parsing position to *i*. The iterator *i* must be into the
input of the current unit, or the method will throw a runtime exception.
)",
        };
    }

    HILTI_OPERATOR(spicy, unit::SetInput);
};
HILTI_OPERATOR_IMPLEMENTATION(SetInput);

class Find : public hilti::BuiltInMemberCall {
public:
    Signature signature(hilti::Builder* builder_) const final {
        auto builder = Builder(builder_);
        return {
            .kind = Kind::MemberCall,
            .self = {hilti::parameter::Kind::In, builder.typeUnit(hilti::type::Wildcard()), "<unit>"},
            .member = "find",
            .param0 = {.name = "needle", .type = {hilti::parameter::Kind::In, builder.typeBytes()}},
            .param1 =
                {
                    .name = "dir",
                    .type = {hilti::parameter::Kind::In, builder.typeName("spicy::Direction")},
                    .optional = true,
                },
            .param2 =
                {
                    .name = "start",
                    .type = {hilti::parameter::Kind::In, builder.typeStreamIterator()},
                    .optional = true,
                },
            .result = {hilti::Const, builder.typeOptional(
                                         builder.qualifiedType(builder.typeStreamIterator(), hilti::Constness::Const))},
            .ns = "unit",
            .doc = R"(
Searches a *needle* pattern inside the input region defined by where the unit
began parsing and its current parsing position. If executed from inside a field
hook, the current parasing position will represent the *first* byte that the
field has been parsed from. By default, the search will start at the beginning
of that region and scan forward. If the direction is
``spicy::Direcction::Backward``, the search will start at the end of the region
and scan backward. In either case, a starting position can also be explicitly
given, but must lie inside the same region.
)",
        };
    }

    HILTI_OPERATOR(spicy, unit::Find);
};
HILTI_OPERATOR_IMPLEMENTATION(Find);

class ConnectFilter : public hilti::BuiltInMemberCall {
public:
    Signature signature(hilti::Builder* builder_) const final {
        auto builder = Builder(builder_);
        return {
            .kind = Kind::MemberCall,
            .self = {hilti::parameter::Kind::InOut, builder.typeUnit(hilti::type::Wildcard()), "<unit>"},
            .member = "connect_filter",
            .param0 =
                {
                    .name = "filter",
                    .type = {hilti::parameter::Kind::InOut,
                             builder.typeStrongReference(
                                 builder.qualifiedType(builder.typeUnit(hilti::type::Wildcard()),
                                                       hilti::Constness::Const))},
                },
            .result = {hilti::Const, builder.typeVoid()},
            .ns = "unit",
            .doc = R"(
Connects a separate filter unit to transform the unit's input transparently
before parsing. The filter unit will see the original input, and this unit will
receive everything the filter passes on through ``forward()``.

Filters can be connected only before a unit's parsing begins. The latest
possible point is from inside the target unit's ``%init`` hook.
)",
        };
    }

    HILTI_OPERATOR(spicy, unit::ConnectFilter);
};
HILTI_OPERATOR_IMPLEMENTATION(ConnectFilter);

class Forward : public hilti::BuiltInMemberCall {
public:
    Signature signature(hilti::Builder* builder_) const final {
        auto builder = Builder(builder_);
        return {
            .kind = Kind::MemberCall,
            .self = {hilti::parameter::Kind::InOut, builder.typeUnit(hilti::type::Wildcard()), "<unit>"},
            .member = "forward",
            .param0 =
                {
                    .name = "data",
                    .type = {hilti::parameter::Kind::In, builder.typeBytes()},
                },
            .result = {hilti::Const, builder.typeVoid()},
            .ns = "unit",
            .doc = R"(
If the unit is connected as a filter to another one, this method forwards
transformed input over to that other one to parse. If the unit is not connected,
this method will silently discard the data.
)",
        };
    }

    HILTI_OPERATOR(spicy, unit::Forward);
};
HILTI_OPERATOR_IMPLEMENTATION(Forward);

class ForwardEod : public hilti::BuiltInMemberCall {
public:
    Signature signature(hilti::Builder* builder_) const final {
        auto builder = Builder(builder_);
        return {
            .kind = Kind::MemberCall,
            .self = {hilti::parameter::Kind::InOut, builder.typeUnit(hilti::type::Wildcard()), "<unit>"},
            .member = "forward_eod",
            .result = {hilti::Const, builder.typeVoid()},
            .ns = "unit",
            .doc = R"(
If the unit is connected as a filter to another one, this method signals that
other one that end of its input has been reached. If the unit is not connected,
this method will not do anything.
)",
        };
    }

    HILTI_OPERATOR(spicy, unit::ForwardEod);
};
HILTI_OPERATOR_IMPLEMENTATION(ForwardEod);

class Backtrack : public hilti::BuiltInMemberCall {
public:
    Signature signature(hilti::Builder* builder_) const final {
        auto builder = Builder(builder_);
        return {
            .kind = Kind::MemberCall,
            .self = {hilti::parameter::Kind::In, builder.typeUnit(hilti::type::Wildcard()), "<unit>"},
            .member = "backtrack",
            .result = {hilti::Const, builder.typeVoid()},
            .ns = "unit",
            .doc = R"(
Aborts parsing at the current position and returns back to the most recent
``&try`` attribute. Turns into a parse error if there's no ``&try`` in scope.
)",
        };
    }

    HILTI_OPERATOR(spicy, unit::Backtrack);
};
HILTI_OPERATOR_IMPLEMENTATION(Backtrack);

class ContextConst : public hilti::BuiltInMemberCall {
public:
    Signature signature(hilti::Builder* builder_) const final {
        auto builder = Builder(builder_);
        return {
            .kind = Kind::MemberCall,
            .self = {hilti::parameter::Kind::In, builder.typeUnit(hilti::type::Wildcard()), "<unit>"},
            .member = "context",
            .result_doc = "<context type>&",
            .ns = "unit",
            .doc = R"(
Returns a reference to the ``%context`` instance associated with the unit.
)",
        };
    }

    QualifiedTypePtr result(hilti::Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return _contextResult(builder, operands);
    }

    HILTI_OPERATOR(spicy, unit::ContextConst);
};
HILTI_OPERATOR_IMPLEMENTATION(ContextConst);

class ContextNonConst : public hilti::BuiltInMemberCall {
public:
    Signature signature(hilti::Builder* builder_) const final {
        auto builder = Builder(builder_);
        return {
            .kind = Kind::MemberCall,
            .self = {hilti::parameter::Kind::InOut, builder.typeUnit(hilti::type::Wildcard()), "<unit>"},
            .member = "context",
            .result_doc = "<context type>&",
            .ns = "unit",
            .doc = R"(
Returns a reference to the ``%context`` instance associated with the unit.
)",
        };
    }

    QualifiedTypePtr result(hilti::Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return _contextResult(builder, operands);
    }

    HILTI_OPERATOR(spicy, unit::ContextNonConst);
};
HILTI_OPERATOR_IMPLEMENTATION(ContextNonConst);

} // namespace unit
} // namespace
