// Copyright (c) 2021-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/builder/builder.h>
#include <hilti/ast/types/integer.h>
#include <hilti/ast/types/network.h>

using namespace hilti;
using namespace hilti::operator_;

namespace {
namespace network {

class Equal : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::Equal,
            .op0 = {parameter::Kind::In, builder->typeNetwork()},
            .op1 = {parameter::Kind::In, builder->typeNetwork()},
            .result = {Const, builder->typeBool()},
            .ns = "network",
            .doc = "Compares two network values.",
        };
    }

    HILTI_OPERATOR(network::Equal)
};
HILTI_OPERATOR_IMPLEMENTATION(Equal)

class Unequal : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::Unequal,
            .op0 = {parameter::Kind::In, builder->typeNetwork()},
            .op1 = {parameter::Kind::In, builder->typeNetwork()},
            .result = {Const, builder->typeBool()},
            .ns = "network",
            .doc = "Compares two network values.",
        };
    }

    HILTI_OPERATOR(network::Unequal)
};

HILTI_OPERATOR_IMPLEMENTATION(Unequal)
class In : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::In,
            .op0 = {parameter::Kind::In, builder->typeAddress()},
            .op1 = {parameter::Kind::In, builder->typeNetwork()},
            .result = {Const, builder->typeBool()},
            .ns = "network",
            .doc = "Returns true if the address is part of the network range.",
        };
    }

    HILTI_OPERATOR(network::In)
};
HILTI_OPERATOR_IMPLEMENTATION(In)

class Family : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::MemberCall,
            .self = {parameter::Kind::In, builder->typeNetwork()},
            .member = "family",
            .result = {Const, builder->typeName("hilti::AddressFamily")},
            .ns = "network",
            .doc = R"(
Returns the protocol family of the network, which can be IPv4 or IPv6.
)",
        };
    }

    HILTI_OPERATOR(network::Family);
};
HILTI_OPERATOR_IMPLEMENTATION(Family);

class Prefix : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::MemberCall,
            .self = {parameter::Kind::In, builder->typeNetwork()},
            .member = "prefix",
            .result = {Const, builder->typeAddress()},
            .ns = "network",
            .doc = R"(
Returns the network's prefix as a masked IP address.
)",
        };
    }

    HILTI_OPERATOR(network::Prefix);
};
HILTI_OPERATOR_IMPLEMENTATION(Prefix);

class Length : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::MemberCall,
            .self = {parameter::Kind::In, builder->typeNetwork()},
            .member = "length",
            .result = {Const, builder->typeSignedInteger(64)},
            .ns = "network",
            .doc = R"(
Returns the length of the network's prefix.
)",
        };
    }

    HILTI_OPERATOR(network::Length);
};
HILTI_OPERATOR_IMPLEMENTATION(Length);

} // namespace network
} // namespace
