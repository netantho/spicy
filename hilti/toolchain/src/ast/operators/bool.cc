// Copyright (c) 2021-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/builder/builder.h>
#include <hilti/ast/types/bool.h>
#include <hilti/ast/types/string.h>

using namespace hilti;
using namespace hilti::operator_;

namespace {
namespace bool_ {

class Equal : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::Equal,
            .op0 = {parameter::Kind::In, builder->typeBool()},
            .op1 = {parameter::Kind::In, builder->typeBool()},
            .result = {Const, builder->typeBool()},
            .ns = "bool",
            .doc = "Compares two boolean values.",
        };
    }

    HILTI_OPERATOR(bool_::Equal)
};
HILTI_OPERATOR_IMPLEMENTATION(Equal)

class Unequal : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::Unequal,
            .op0 = {parameter::Kind::In, builder->typeBool()},
            .op1 = {parameter::Kind::In, builder->typeBool()},
            .result = {Const, builder->typeBool()},
            .ns = "bool_",
            .doc = "Compares two boolean values.",
        };
    }

    HILTI_OPERATOR(bool_::Unequal)
};
HILTI_OPERATOR_IMPLEMENTATION(Unequal)

class BitAnd : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::BitAnd,
            .op0 = {parameter::Kind::In, builder->typeBool()},
            .op1 = {parameter::Kind::In, builder->typeBool()},
            .result = {Const, builder->typeBool()},
            .ns = "bool_",
            .doc = "Computes the bit-wise 'and' of the two boolean values.",
        };
    }

    HILTI_OPERATOR(bool_::BitAnd)
};
HILTI_OPERATOR_IMPLEMENTATION(BitAnd);

class BitOr : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::BitOr,
            .op0 = {parameter::Kind::In, builder->typeBool()},
            .op1 = {parameter::Kind::In, builder->typeBool()},
            .result = {Const, builder->typeBool()},
            .ns = "bool_",
            .doc = "Computes the bit-wise 'or' of the two boolean values.",
        };
    }

    HILTI_OPERATOR(bool_::BitOr)
};
HILTI_OPERATOR_IMPLEMENTATION(BitOr);

class BitXor : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::BitXor,
            .op0 = {parameter::Kind::In, builder->typeBool()},
            .op1 = {parameter::Kind::In, builder->typeBool()},
            .result = {Const, builder->typeBool()},
            .ns = "bool_",
            .doc = "Computes the bit-wise 'xor' of the two boolean values.",
        };
    }

    HILTI_OPERATOR(bool_::BitXor)
};
HILTI_OPERATOR_IMPLEMENTATION(BitXor);

} // namespace bool_
} // namespace
