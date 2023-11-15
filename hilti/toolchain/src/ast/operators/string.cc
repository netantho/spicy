// Copyright (c) 2021-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/builder/builder.h>

using namespace hilti;
using namespace hilti::operator_;

namespace {
namespace string {

class Equal : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::Equal,
            .op0 = {parameter::Kind::In, builder->typeString()},
            .op1 = {parameter::Kind::In, builder->typeString()},
            .result = {Const, builder->typeBool()},
            .ns = "string",
            .doc = "Compares two strings lexicographically.",
        };
    }

    HILTI_OPERATOR(hilti, string::Equal)
};
HILTI_OPERATOR_IMPLEMENTATION(Equal);

class Unequal : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::Unequal,
            .op0 = {parameter::Kind::In, builder->typeString()},
            .op1 = {parameter::Kind::In, builder->typeString()},
            .result = {Const, builder->typeBool()},
            .ns = "string",
            .doc = "Compares two strings lexicographically.",
        };
    }

    HILTI_OPERATOR(hilti, string::Unequal)
};
HILTI_OPERATOR_IMPLEMENTATION(Unequal);

class Size : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::Size,
            .op0 = {parameter::Kind::In, builder->typeString()},
            .result = {Const, builder->typeUnsignedInteger(64)},
            .ns = "string",
            .doc = "Returns the number of characters the string contains.",
        };
    }

    HILTI_OPERATOR(hilti, string::Size)
};
HILTI_OPERATOR_IMPLEMENTATION(Size);

class Sum : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::Sum,
            .op0 = {parameter::Kind::In, builder->typeString()},
            .op1 = {parameter::Kind::In, builder->typeString()},
            .result = {Const, builder->typeString()},
            .ns = "string",
            .doc = "X",
        };
    }

    HILTI_OPERATOR(hilti, string::Sum)
};
HILTI_OPERATOR_IMPLEMENTATION(Sum);

class Modulo : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return {.kind = Kind::Modulo,
                .op0 = {parameter::Kind::In, builder->typeString()},
                .op1 = {parameter::Kind::In, builder->typeAny()},
                .result = {Const, builder->typeString()},
                .ns = "string",
                .doc = "Renders a printf-style format string."};
    }

    HILTI_OPERATOR(hilti, string::Modulo)
};
HILTI_OPERATOR_IMPLEMENTATION(Modulo);

class Encode : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return {.kind = Kind::MemberCall,
                .self = {parameter::Kind::In, builder->typeString()},
                .member = "encode",
                .param0 = {.name = "charset",
                           .type = {parameter::Kind::In, builder->typeName("hilti::Charset")},
                           .default_ = builder->expressionName("hilti::Charset::UTF8")},
                .result = {Const, builder->typeBytes()},
                .ns = "string",
                .doc = "Compares two strings lexicographically."};
    };

    HILTI_OPERATOR(hilti, string::Encode);
};
HILTI_OPERATOR_IMPLEMENTATION(Encode);

} // namespace string
} // namespace
