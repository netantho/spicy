// Copyright (c) 2023 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/visitor-dispatcher.h>

#include <spicy/ast/all.h>

using namespace hilti;

HILTI_NODE_IMPLEMENTATION_0(spicy, Hook)
HILTI_NODE_IMPLEMENTATION_0(spicy, type::unit::Item)
HILTI_NODE_IMPLEMENTATION_0(spicy, type::unit::item::switch_::Case)
HILTI_NODE_IMPLEMENTATION_1(spicy, ctor::Unit, Ctor)
HILTI_NODE_IMPLEMENTATION_1(spicy, declaration::UnitHook, Declaration)
HILTI_NODE_IMPLEMENTATION_1(spicy, operator_::unit::MemberCall, ResolvedOperator)
HILTI_NODE_IMPLEMENTATION_1(spicy, statement::Confirm, Statement)
HILTI_NODE_IMPLEMENTATION_1(spicy, statement::Print, Statement)
HILTI_NODE_IMPLEMENTATION_1(spicy, statement::Reject, Statement)
HILTI_NODE_IMPLEMENTATION_1(spicy, statement::Stop, Statement)
HILTI_NODE_IMPLEMENTATION_1(spicy, type::Sink, UnqualifiedType)
HILTI_NODE_IMPLEMENTATION_1(spicy, type::Unit, UnqualifiedType)
HILTI_NODE_IMPLEMENTATION_1(spicy, type::unit::item::Field, type::unit::Item)
HILTI_NODE_IMPLEMENTATION_1(spicy, type::unit::item::Property, type::unit::Item)
HILTI_NODE_IMPLEMENTATION_1(spicy, type::unit::item::Sink, type::unit::Item)
HILTI_NODE_IMPLEMENTATION_1(spicy, type::unit::item::Switch, type::unit::Item)
HILTI_NODE_IMPLEMENTATION_1(spicy, type::unit::item::UnitHook, type::unit::Item)
HILTI_NODE_IMPLEMENTATION_1(spicy, type::unit::item::UnresolvedField, type::unit::Item)
HILTI_NODE_IMPLEMENTATION_1(spicy, type::unit::item::Variable, type::unit::Item)
