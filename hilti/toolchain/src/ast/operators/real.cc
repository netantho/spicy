// Copyright (c) 2021-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/builder/builder.h>
#include <hilti/ast/types/bool.h>
#include <hilti/ast/types/real.h>
#include <hilti/ast/types/string.h>
#include <hilti/ast/types/type.h>
#include <hilti/base/logger.h>

using namespace hilti;
using namespace hilti::operator_;

namespace {
namespace real {

class SignNeg : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::SignNeg,
            .op0 = {parameter::Kind::In, builder->typeReal()},
            .result = {Const, builder->typeReal()},
            .ns = "real",
            .doc = "Inverts the sign of the real.",
        };
    }

    HILTI_OPERATOR(real::SignNeg)
};
HILTI_OPERATOR_IMPLEMENTATION(SignNeg);
class Difference : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::Difference,
            .op0 = {parameter::Kind::In, builder->typeReal()},
            .op1 = {parameter::Kind::In, builder->typeReal()},
            .result = {Const, builder->typeReal()},
            .ns = "real",
            .doc = "Returns the difference between the two values.",
        };
    }

    HILTI_OPERATOR(real::Difference)
};
HILTI_OPERATOR_IMPLEMENTATION(Difference);

class DifferenceAssign : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::DifferenceAssign,
            .op0 = {parameter::Kind::In, builder->typeReal()},
            .op1 = {parameter::Kind::In, builder->typeReal()},
            .result = {Const, builder->typeReal()},
            .ns = "real",
            .doc = "Subtracts the second value from the first, assigning the new value.",
        };
    }

    HILTI_OPERATOR(real::DifferenceAssign)
};
HILTI_OPERATOR_IMPLEMENTATION(DifferenceAssign);

class Division : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::Division,
            .op0 = {parameter::Kind::In, builder->typeReal()},
            .op1 = {parameter::Kind::In, builder->typeReal()},
            .result = {Const, builder->typeReal()},
            .ns = "real",
            .doc = "Divides the first value by the second.",
        };
    }

    HILTI_OPERATOR(real::Division)
};
HILTI_OPERATOR_IMPLEMENTATION(Division);
class DivisionAssign : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::DivisionAssign,
            .op0 = {parameter::Kind::In, builder->typeReal()},
            .op1 = {parameter::Kind::In, builder->typeReal()},
            .result = {Const, builder->typeReal()},
            .ns = "real",
            .doc = "Divides the first value by the second, assigning the new value.",
        };
    }

    HILTI_OPERATOR(real::DivisionAssign)
};
HILTI_OPERATOR_IMPLEMENTATION(DivisionAssign);

class Equal : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::Equal,
            .op0 = {parameter::Kind::In, builder->typeReal()},
            .op1 = {parameter::Kind::In, builder->typeReal()},
            .result = {Const, builder->typeBool()},
            .ns = "real",
            .doc = "Compares the two reals.",
        };
    }

    HILTI_OPERATOR(real::Equal)
};
HILTI_OPERATOR_IMPLEMENTATION(Equal);
class Greater : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::Greater,
            .op0 = {parameter::Kind::In, builder->typeReal()},
            .op1 = {parameter::Kind::In, builder->typeReal()},
            .result = {Const, builder->typeBool()},
            .ns = "real",
            .doc = "Compares the two reals.",
        };
    }

    HILTI_OPERATOR(real::Greater)
};
HILTI_OPERATOR_IMPLEMENTATION(Greater);
class GreaterEqual : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::GreaterEqual,
            .op0 = {parameter::Kind::In, builder->typeReal()},
            .op1 = {parameter::Kind::In, builder->typeReal()},
            .result = {Const, builder->typeBool()},
            .ns = "real",
            .doc = "Compares the two reals.",
        };
    }

    HILTI_OPERATOR(real::GreaterEqual)
};
HILTI_OPERATOR_IMPLEMENTATION(GreaterEqual);
class Lower : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::Lower,
            .op0 = {parameter::Kind::In, builder->typeReal()},
            .op1 = {parameter::Kind::In, builder->typeReal()},
            .result = {Const, builder->typeBool()},
            .ns = "real",
            .doc = "Compares the two reals.",
        };
    }

    HILTI_OPERATOR(real::Lower)
};
HILTI_OPERATOR_IMPLEMENTATION(Lower);
class LowerEqual : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::LowerEqual,
            .op0 = {parameter::Kind::In, builder->typeReal()},
            .op1 = {parameter::Kind::In, builder->typeReal()},
            .result = {Const, builder->typeBool()},
            .ns = "real",
            .doc = "Compares the two reals.",
        };
    }

    HILTI_OPERATOR(real::LowerEqual)
};
HILTI_OPERATOR_IMPLEMENTATION(LowerEqual);
class Modulo : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::Modulo,
            .op0 = {parameter::Kind::In, builder->typeReal()},
            .op1 = {parameter::Kind::In, builder->typeReal()},
            .result = {Const, builder->typeReal()},
            .ns = "real",
            .doc = "Computes the modulus of the first real divided by the second.",
        };
    }

    HILTI_OPERATOR(real::Modulo)
};
HILTI_OPERATOR_IMPLEMENTATION(Modulo);

class Multiple : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::Multiple,
            .op0 = {parameter::Kind::In, builder->typeReal()},
            .op1 = {parameter::Kind::In, builder->typeReal()},
            .result = {Const, builder->typeReal()},
            .ns = "real",
            .doc = "Multiplies the first real by the second.",
        };
    }

    HILTI_OPERATOR(real::Multiple)
};
HILTI_OPERATOR_IMPLEMENTATION(Multiple);

class MultipleAssign : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::MultipleAssign,
            .op0 = {parameter::Kind::In, builder->typeReal()},
            .op1 = {parameter::Kind::In, builder->typeReal()},
            .result = {Const, builder->typeReal()},
            .ns = "real",
            .doc = "Multiplies the first value by the second, assigning the new value.",
        };
    }

    HILTI_OPERATOR(real::MultipleAssign)
};
HILTI_OPERATOR_IMPLEMENTATION(MultipleAssign);

class Power : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::Power,
            .op0 = {parameter::Kind::In, builder->typeReal()},
            .op1 = {parameter::Kind::In, builder->typeReal()},
            .result = {Const, builder->typeReal()},
            .ns = "real",
            .doc = "Computes the first real raised to the power of the second.",
        };
    }

    HILTI_OPERATOR(real::Power)
};
HILTI_OPERATOR_IMPLEMENTATION(Power);

class Sum : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::Sum,
            .op0 = {parameter::Kind::In, builder->typeReal()},
            .op1 = {parameter::Kind::In, builder->typeReal()},
            .result = {Const, builder->typeReal()},
            .ns = "real",
            .doc = "Returns the sum of the reals.",
        };
    }

    HILTI_OPERATOR(real::Sum)
};
HILTI_OPERATOR_IMPLEMENTATION(Sum);
class SumAssign : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::SumAssign,
            .op0 = {parameter::Kind::In, builder->typeReal()},
            .op1 = {parameter::Kind::In, builder->typeReal()},
            .result = {Const, builder->typeReal()},
            .ns = "real",
            .doc = "Adds the first real to the second, assigning the new value.",
        };
    }

    HILTI_OPERATOR(real::SumAssign)
};
HILTI_OPERATOR_IMPLEMENTATION(SumAssign);

class Unequal : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::Unequal,
            .op0 = {parameter::Kind::In, builder->typeReal()},
            .op1 = {parameter::Kind::In, builder->typeReal()},
            .result = {Const, builder->typeBool()},
            .ns = "real",
            .doc = "Compares the two reals.",
        };
    }

    HILTI_OPERATOR(real::Unequal)
};
HILTI_OPERATOR_IMPLEMENTATION(Unequal);

class CastToUnsignedInteger : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::Cast,
            .op0 = {parameter::Kind::In, builder->typeReal()},
            .op1 = {parameter::Kind::In,
                    builder->typeType(builder->qualifiedType(builder->typeUnsignedInteger(type::Wildcard()), Const))},
            .result_doc = "uint<*>",
            .ns = "real",
            .doc = "Converts the value to an unsigned integer type, accepting any loss of information.",
        };
    }

    QualifiedTypePtr result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return operands[1]->type()->type()->as<type::Type_>()->typeValue();
    }

    HILTI_OPERATOR(real::CastToUnsignedInteger)
};
HILTI_OPERATOR_IMPLEMENTATION(CastToUnsignedInteger);


class CastToSignedInteger : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::Cast,
            .op0 = {parameter::Kind::In, builder->typeReal()},
            .op1 = {parameter::Kind::In,
                    builder->typeType(builder->qualifiedType(builder->typeSignedInteger(type::Wildcard()), Const))},
            .result_doc = "int<*>",
            .ns = "real",
            .doc = "Converts the value to a signed integer type, accepting any loss of information.",
        };
    }

    QualifiedTypePtr result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return operands[1]->type()->type()->as<type::Type_>()->typeValue();
    }

    HILTI_OPERATOR(real::CastToSignedInteger)
};
HILTI_OPERATOR_IMPLEMENTATION(CastToSignedInteger);


class CastToTime : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::Cast,
            .op0 = {parameter::Kind::In, builder->typeReal()},
            .op1 = {parameter::Kind::In, builder->typeType(builder->qualifiedType(builder->typeTime(), Const))},
            .result = {Const, builder->typeTime()},
            .ns = "real",
            .doc = "Interprets the value as number of seconds since the UNIX epoch.",
        };
    }

    HILTI_OPERATOR(real::CastToTime)
};
HILTI_OPERATOR_IMPLEMENTATION(CastToTime);

class CastToInterval : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::Cast,
            .op0 = {parameter::Kind::In, builder->typeReal()},
            .op1 = {parameter::Kind::In, builder->typeType(builder->qualifiedType(builder->typeInterval(), Const))},
            .result = {Const, builder->typeInterval()},
            .ns = "real",
            .doc = "Interprets the value as number of seconds.",
        };
    }

    HILTI_OPERATOR(real::CastToInterval)
};
HILTI_OPERATOR_IMPLEMENTATION(CastToInterval);

} // namespace real
} // namespace
