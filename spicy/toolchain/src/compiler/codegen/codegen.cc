// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <utility>

#include <hilti/ast/builder/builder.h>
#include <hilti/ast/ctors/coerced.h>
#include <hilti/ast/ctors/tuple.h>
#include <hilti/ast/declaration.h>
#include <hilti/ast/declarations/imported-module.h>
#include <hilti/ast/declarations/property.h>
#include <hilti/ast/declarations/type.h>
#include <hilti/ast/expressions/coerced.h>
#include <hilti/ast/expressions/ctor.h>
#include <hilti/ast/expressions/resolved-operator.h>
#include <hilti/ast/operators/function.h>
#include <hilti/ast/operators/struct.h>
#include <hilti/ast/types/bitfield.h>
#include <hilti/ast/types/integer.h>
#include <hilti/ast/types/reference.h>
#include <hilti/ast/types/regexp.h>
#include <hilti/base/logger.h>

#include <spicy/ast/visitor.h>
#include <spicy/compiler/detail/codegen/codegen.h>
#include <spicy/compiler/detail/codegen/grammar-builder.h>
#include <spicy/compiler/detail/codegen/grammar.h>

#include "ast/builder/builder.h"
#include "base/timing.h"
#include "compiler/driver.h"

using namespace spicy;
using namespace spicy::detail;
using namespace spicy::detail::codegen;

using hilti::util::fmt;

namespace spicy::logging::debug {
inline const hilti::logging::DebugStream CodeGen("spicy-codegen");
} // namespace spicy::logging::debug

namespace {

// Visitor that runs only once the 1st time AST transformation is triggered.
struct VisitorPass1 : public visitor::MutatingPreOrder {
    VisitorPass1(CodeGen* cg, hilti::declaration::Module* module)
        : visitor::MutatingPreOrder(builder(), logging::debug::CodeGen), cg(cg), module(module) {}

    CodeGen* cg;
    hilti::declaration::Module* module;
    ID module_id = ID("<no module>");

    void operator()(hilti::declaration::Type* n) final {
        // Replace unit type with compiled struct type.
        auto u = n->type()->tryAs<type::Unit>();
        if ( ! u )
            return;

        // Build the unit's grammar.
        if ( auto r = cg->grammarBuilder()->run(u); ! r ) {
            hilti::logger().error(r.error().description(), n->location());
            return;
        }

        auto ns = cg->compileUnit(u, false);
        auto attrs = builder()->attributeSet({builder()->attribute("&on-heap")});
        auto new_n = builder()->declarationType(n->id(), builder()->qualifiedType(ns, hilti::Constness::NonConst),
                                                attrs, n->linkage(), n->meta());
        replaceNode(n, new_n);
    }

    void operator()(spicy::ctor::Unit* n) final {
        // Replace unit ctor with an equivalent struct ctor.
        auto new_n = builder()->ctorStruct(n->fields(), n->meta());
        replaceNode(n, new_n);
    }
};

// Visitor that runs repeatedly over the AST until no further changes.
struct VisitorPass2 : public visitor::MutatingPreOrder {
    VisitorPass2(CodeGen* cg, hilti::declaration::Module* module)
        : visitor::MutatingPreOrder(builder(), logging::debug::CodeGen), cg(cg), module(module) {}

    CodeGen* cg;
    hilti::declaration::Module* module;
    ID module_id = ID("<no module>");

    ExpressionPtr argument(const ExpressionPtr& args, unsigned int i, std::optional<ExpressionPtr> def = {}) {
        auto ctor = args->as<hilti::expression::Ctor>()->ctor();

        if ( auto x = ctor->tryAs<hilti::ctor::Coerced>() )
            ctor = x->coercedCtor();

        auto value = ctor->as<hilti::ctor::Tuple>()->value();

        if ( i < value.size() )
            return ctor->as<hilti::ctor::Tuple>()->value()[i];

        if ( def )
            return *def;

        hilti::logger().internalError(fmt("missing argument %d", i));
    }

    void operator()(hilti::declaration::Property* n) final { cg->recordModuleProperty(*n); }

    void operator()(declaration::UnitHook* n) final {
        const auto& hook = n->hook();
        auto unit_type = hook->unitType();
        assert(unit_type);

        auto func = cg->compileHook(*unit_type, n->hook()->id(), {}, hook->isForEach(), hook->isDebug(),
                                    hook->ftype()->parameters(), hook->body(), hook->priority(), n->meta());

        replaceNode(n, std::move(func));
    }

    void operator()(hilti::expression::Name* n) final {
        // Re-resolve IDs (except function calls).
        if ( ! n->parent()->isA<hilti::operator_::function::Call>() )
            replaceNode(n, builder()->expressionName(n->id(), n->meta()));
    }

    void operator()(operator_::unit::Unset* n) final {
        const auto& id = n->op1()->as<hilti::expression::Member>()->id();
        replaceNode(n, builder()->unset(n->op0(), id, n->meta()));
    }

    void operator()(operator_::unit::MemberConst* n) final {
        const auto& id = n->op1()->as<hilti::expression::Member>()->id();
        replaceNode(n, builder()->member(n->op0(), id, n->meta()));
    }

    void operator()(operator_::unit::MemberNonConst* n) final {
        const auto& id = n->op1()->as<hilti::expression::Member>()->id();
        replaceNode(n, builder()->member(n->op0(), id, n->meta()));
    }

    void operator()(operator_::unit::TryMember* n) final {
        const auto& id = n->op1()->as<hilti::expression::Member>()->id();
        replaceNode(n, builder()->tryMember(n->op0(), id, n->meta()));
    }

    void operator()(operator_::unit::HasMember* n) final {
        const auto& id = n->op1()->as<hilti::expression::Member>()->id();
        replaceNode(n, builder()->hasMember(n->op0(), id, n->meta()));
    }

    void operator()(operator_::unit::MemberCall* n) final {
        const auto& id = n->op1()->as<hilti::expression::Member>()->id();
        const auto& args = n->op2()->as<hilti::expression::Ctor>()->ctor()->as<hilti::ctor::Tuple>();
        replaceNode(n, builder()->memberCall(n->op0(), id, args, n->meta()));
    }

    void operator()(operator_::unit::Offset* n) final { replaceNode(n, builder()->member(n->op0(), ID("__offset"))); }

    void operator()(operator_::unit::Position* n) final {
        auto begin = builder()->deref(builder()->member(n->op0(), ID("__begin")));
        auto offset = builder()->member(n->op0(), ID("__offset"));
        replaceNode(n, builder()->grouping(builder()->sum(begin, offset)));
    }

    void operator()(operator_::unit::Input* n) final {
        auto begin = builder()->deref(builder()->grouping(builder()->member(n->op0(), ID("__begin"))));
        replaceNode(n, begin);
    }

    void operator()(operator_::unit::SetInput* n) final {
        auto cur = builder()->member(n->op0(), ID("__position_update"));
        replaceNode(n, builder()->assign(cur, argument(n->op2(), 0)));
    }

    void operator()(operator_::unit::Find* n) final {
        auto begin = builder()->deref(builder()->member(n->op0(), ID("__begin")));
        auto offset = builder()->member(n->op0(), ID("__offset"));
        auto end = builder()->sum(begin, offset);
        auto needle = argument(n->op2(), 0);
        auto direction = argument(n->op2(), 1, builder()->id("spicy::Direction::Forward"));
        auto i = argument(n->op2(), 2, builder()->null());
        auto x = builder()->call("spicy_rt::unit_find", {begin, end, i, needle, direction});
        replaceNode(n, std::move(x));
    }

    void operator()(operator_::unit::ContextConst* n) final {
        auto x = builder()->member(n->op0(), ID("__context"));
        replaceNode(n, x);
    }

    void operator()(operator_::unit::ContextNonConst* n) final {
        auto x = builder()->member(n->op0(), ID("__context"));
        replaceNode(n, x);
    }

    void operator()(operator_::unit::Backtrack* n) final {
        auto x = builder()->call("spicy_rt::backtrack", {});
        replaceNode(n, std::move(x));
    }

    void operator()(spicy::ctor::Unit* n) final {
        // Replace unit ctor with an equivalent struct ctor.
        auto x = builder()->ctorStruct(n->fields(), n->meta());
        replaceNode(n, x);
    }

    void operator()(operator_::unit::ConnectFilter* n) final {
        auto x = builder()->call("spicy_rt::filter_connect", {n->op0(), argument(n->op2(), 0)});
        replaceNode(n, std::move(x));
    }

    void operator()(operator_::unit::Forward* n) final {
        auto x = builder()->call("spicy_rt::filter_forward", {n->op0(), argument(n->op2(), 0)});
        replaceNode(n, std::move(x));
    }

    void operator()(operator_::unit::ForwardEod* n) final {
        auto x = builder()->call("spicy_rt::filter_forward_eod", {n->op0()});
        replaceNode(n, std::move(x));
    }

    void operator()(operator_::sink::Close* n) final {
        auto x = builder()->memberCall(n->op0(), "close");
        replaceNode(n, std::move(x));
    }

    void operator()(operator_::sink::Connect* n) final {
        auto x = builder()->memberCall(n->op0(), "connect", {argument(n->op2(), 0)});
        replaceNode(n, std::move(x));
    }

    void operator()(operator_::sink::ConnectMIMETypeBytes* n) final {
        auto x = builder()->memberCall(n->op0(), "connect_mime_type", {argument(n->op2(), 0), builder()->scope()});
        replaceNode(n, std::move(x));
    }

    void operator()(operator_::sink::ConnectMIMETypeString* n) final {
        auto x = builder()->memberCall(n->op0(), "connect_mime_type", {argument(n->op2(), 0), builder()->scope()});
        replaceNode(n, std::move(x));
    }

    void operator()(operator_::sink::ConnectFilter* n) final {
        auto x = builder()->memberCall(n->op0(), "connect_filter", {argument(n->op2(), 0)});
        replaceNode(n, std::move(x));
    }

    void operator()(operator_::sink::Gap* n) final {
        auto x = builder()->memberCall(n->op0(), "gap", {argument(n->op2(), 0), argument(n->op2(), 1)});
        replaceNode(n, std::move(x));
    }

    void operator()(operator_::sink::SequenceNumber* n) final {
        auto x = builder()->memberCall(n->op0(), "sequence_number");
        replaceNode(n, std::move(x));
    }

    void operator()(operator_::sink::SetAutoTrim* n) final {
        auto x = builder()->memberCall(n->op0(), "set_auto_trim", {argument(n->op2(), 0)});
        replaceNode(n, std::move(x));
    }

    void operator()(operator_::sink::SetInitialSequenceNumber* n) final {
        auto x = builder()->memberCall(n->op0(), "set_initial_sequence_number", {argument(n->op2(), 0)});
        replaceNode(n, std::move(x));
    }

    void operator()(operator_::sink::SetPolicy* n) final {
        auto x = builder()->memberCall(n->op0(), "set_policy", {argument(n->op2(), 0)});
        replaceNode(n, std::move(x));
    }

    void operator()(operator_::sink::SizeValue* n) final {
        auto x = builder()->memberCall(n->op0(), "size");
        replaceNode(n, std::move(x));
    }

    void operator()(operator_::sink::SizeReference* n) final {
        auto x = builder()->memberCall(n->op0(), "size");
        replaceNode(n, std::move(x));
    }

    void operator()(operator_::sink::Skip* n) final {
        auto x = builder()->memberCall(n->op0(), "skip", {argument(n->op2(), 0)});
        replaceNode(n, std::move(x));
    }

    void operator()(operator_::sink::Trim* n) final {
        auto x = builder()->memberCall(n->op0(), "trim", {argument(n->op2(), 0)});
        replaceNode(n, std::move(x));
    }

    void operator()(operator_::sink::Write* n) final {
        auto x = builder()->memberCall(n->op0(), "write",
                                       {argument(n->op2(), 0), argument(n->op2(), 1, builder()->null()),
                                        argument(n->op2(), 2, builder()->null())});
        replaceNode(n, std::move(x));
    }

    void operator()(statement::Print* n) final {
        auto exprs = n->expressions();

        switch ( exprs.size() ) {
            case 0: {
                auto call = builder()->call("hilti::print", {builder()->string("")});
                replaceNode(n, builder()->statementExpression(call, n->location()));
                break;
            }

            case 1: {
                auto call = builder()->call("hilti::print", exprs);
                replaceNode(n, builder()->statementExpression(call, n->location()));
                break;
            }

            default: {
                auto call = builder()->call("hilti::printValues", {builder()->tuple(exprs)});
                replaceNode(n, builder()->statementExpression(call, n->location()));
                break;
            }
        }
    }

    void operator()(statement::Confirm* n) final {
        // TODO(bbannier): Add validation checking whether `self` is actually a valid identifier here.
        auto call = builder()->call("spicy_rt::confirm", {builder()->deref(builder()->id("self"))});
        replaceNode(n, builder()->statementExpression(call, n->location()));
    }

    void operator()(statement::Reject* n) final {
        // TODO(bbannier): Add validation checking whether `self` is actually a valid identifier here.
        auto call = builder()->call("spicy_rt::reject", {builder()->deref(builder()->id("self"))});
        replaceNode(n, builder()->statementExpression(call, n->location()));
    }

    void operator()(statement::Stop* n) final {
        auto b = builder()->newBlock();
        b->addAssign(builder()->id("__stop"), builder()->bool_(true), n->meta());
        b->addReturn(n->meta());
        replaceNode(n, b->block());
    }

    void operator()(type::Sink* n) final {
        // Strong reference (instead of value reference) so that copying unit
        // instances doesn't copy the sink.
        auto sink = builder()->typeStrongReference(
            builder()->qualifiedType(builder()->typeName("spicy_rt::Sink", n->meta()), hilti::Constness::Const));
        replaceNode(n, builder()->qualifiedType(sink, hilti::Constness::Const));
    }

    void operator()(type::Unit* n) final {
        // Replace usage of the the unit type with a reference to the compiled struct.
        if ( auto t = n->parent()->tryAs<hilti::declaration::Type>();
             ! t && ! n->parent(2)->tryAs<hilti::declaration::Type>() ) {
            assert(n->typeID());
            replaceNode(n, builder()->typeName(*n->typeID(), n->meta()));
        }
    }
};

// Visitor that runs once at the very end once the AST is pure HILTI.
struct VisitorPass3 : public visitor::MutatingPreOrder {
    VisitorPass3(CodeGen* cg, hilti::declaration::Module* module)
        : visitor::MutatingPreOrder(builder(), logging::debug::CodeGen), cg(cg), module(module) {}

    CodeGen* cg;
    hilti::declaration::Module* module;

    void operator()(hilti::ctor::Coerced* n) final {
        // Replace coercions with their final result, so that HILTI will not
        // see them (because if did, it wouldn't apply further HILTI-side
        // coercions to the result anymore).
        replaceNode(n, n->coercedCtor());
    }
};

} // anonymous namespace

bool CodeGen::compileModule(ModulePtr module) {
    _hilti_unit = driver()->lookupUnit(module->uid());
    assert(_hilti_unit);

    auto v1 = VisitorPass1(this, module.get());
    visitor::visit(v1, module);

    auto v2 = VisitorPass2(this, module.get());
    while ( true ) {
        visitor::visit(v2, module);

        if ( ! hilti::logger().errors() ) {
            if ( _new_decls.size() ) {
                for ( const auto& n : _new_decls )
                    module->add(builder()->context(), n);

                _new_decls.clear();
                continue; // modified, next round
            }
        }

        if ( ! v2.isModified() )
            break;
    }

    auto v3 = VisitorPass3(this, module.get());
    visitor::visit(v3, module);

    module->setProcessExtension(".hlt");
    _hilti_unit = nullptr;

    return v1.isModified() || v2.isModified() || v3.isModified();
}

bool CodeGen::compileAST(const ASTRootPtr& root) {
    hilti::util::timing::Collector _("spicy/compiler/codegen");

    // Find all the Spicy modules and transform them one by one.
    struct VisitorModule : public visitor::PreOrder {
        VisitorModule(CodeGen* cg, Builder* builder) : cg(cg), builder(builder) {}

        CodeGen* cg;
        Builder* builder;
        bool modified = false;

        void operator()(hilti::declaration::Module* n) final {
            modified = modified | cg->compileModule(n->as<hilti::declaration::Module>());
        }
    };

    return visitor::visit(VisitorModule(this, builder()), root, [](const auto& v) { return v.modified; });
}

NodeDerivedPtr<hilti::declaration::Function> CodeGen::compileHook(
    const type::Unit& unit, const ID& id, hilti::NodeDerivedPtr<type::unit::item::Field> field, bool foreach,
    bool debug, hilti::type::function::Parameters params, const StatementPtr& body, const ExpressionPtr& priority,
    const hilti::Meta& meta) {
    if ( debug && ! options().debug )
        return {};

    bool is_container = false;
    QualifiedTypePtr original_field_type;

    if ( field ) {
        if ( ! field->parseType()->type()->isA<hilti::type::Void>() && ! field->isSkip() )
            original_field_type = field->originalType();

        is_container = field->isContainer();
    }
    else {
        // Try to locate field by ID.
        if ( auto i = unit.itemByName(id.local()) ) {
            if ( auto f = i->tryAs<type::unit::item::Field>() ) {
                if ( ! f->parseType()->type()->isA<hilti::type::Void>() && ! f->isSkip() ) {
                    is_container = f->isContainer();
                    field = f;
                    original_field_type = f->originalType();
                }
            }
        }
    }

    if ( foreach ) {
        params.push_back(
            builder()->parameter("__dd", field->ddType()->type()->elementType()->type(), hilti::parameter::Kind::In));
        params.push_back(builder()->parameter("__stop", builder()->typeBool(), hilti::parameter::Kind::InOut));
    }
    else if ( original_field_type ) {
        params.push_back(builder()->parameter("__dd", field->itemType()->type(), hilti::parameter::Kind::In));

        // Pass on captures for fields of type regexp, which are the only
        // ones that have it (for vector of regexps, it wouldn't be clear what
        // to bind to).
        if ( original_field_type->type()->isA<hilti::type::RegExp>() && ! is_container )
            params.push_back(
                builder()->parameter("__captures", builder()->typeName("hilti::Captures"), hilti::parameter::Kind::In));
    }

    std::string hid;
    QualifiedTypePtr result;

    if ( id.local().str() == "0x25_print" ) {
        // Special-case: We simply translate this into HITLI's __str__ hook.
        auto string_ = builder()->qualifiedType(builder()->typeString(), hilti::Constness::Const);
        result = builder()->qualifiedType(builder()->typeOptional(string_), hilti::Constness::Const);
        hid = "__str__";
    }
    else {
        result = builder()->qualifiedType(builder()->typeVoid(), hilti::Constness::Const);
        hid = fmt("__on_%s%s", id.local(), (foreach ? "_foreach" : ""));
    }

    if ( ! id.namespace_().empty() )
        hid = fmt("%s::%s", id.namespace_(), hid);

    auto ft = builder()->typeFunction(result, params, hilti::type::function::Flavor::Hook, meta);

    AttributeSetPtr attrs = builder()->attributeSet();

    if ( priority )
        attrs->add(context(), builder()->attribute("&priority", priority));

    auto f = builder()->function(ID(hid), ft, body, hilti::function::CallingConvention::Standard, attrs, meta);
    return builder()->declarationFunction(f, hilti::declaration::Linkage::Struct, meta);
}

hilti::Unit* CodeGen::hiltiUnit() const {
    if ( ! _hilti_unit )
        hilti::logger().internalError("not compiling a HILTI unit");

    return _hilti_unit;
}
