auto ctorUnit(ctor::unit::Fields fields, QualifiedTypePtr t, const Meta& meta = {}) {
    return spicy::ctor::Unit::create(context(), fields, t, meta);
} // /Users/robin/work/spicy/node-rewrite/spicy/toolchain/include/spicy/ast/ctors/unit.h:52:5
auto ctorUnit(ctor::unit::Fields fields, const Meta& meta = {}) {
    return spicy::ctor::Unit::create(context(), fields, meta);
} // /Users/robin/work/spicy/node-rewrite/spicy/toolchain/include/spicy/ast/ctors/unit.h:47:5
auto declarationUnitHook(ID id, const HookPtr& hook, Meta meta = {}) {
    return spicy::declaration::UnitHook::create(context(), id, hook, meta);
} // /Users/robin/work/spicy/node-rewrite/spicy/toolchain/include/spicy/ast/declarations/unit-hook.h:21:5
auto hook(const hilti::declaration::Parameters& parameters, const StatementPtr& body, Engine engine,
          const AttributeSetPtr& attrs, const Meta& m = Meta()) {
    return spicy::Hook::create(context(), parameters, body, engine, attrs, m);
} // /Users/robin/work/spicy/node-rewrite/spicy/toolchain/include/spicy/ast/hook.h:70:5
auto statementConfirm(Meta meta = {}) {
    return spicy::statement::Confirm::create(context(), meta);
} // /Users/robin/work/spicy/node-rewrite/spicy/toolchain/include/spicy/ast/statements/confirm.h:16:5
auto statementPrint(Expressions expressions, Meta meta = {}) {
    return spicy::statement::Print::create(context(), expressions, meta);
} // /Users/robin/work/spicy/node-rewrite/spicy/toolchain/include/spicy/ast/statements/print.h:19:5
auto statementReject(Meta meta = {}) {
    return spicy::statement::Reject::create(context(), meta);
} // /Users/robin/work/spicy/node-rewrite/spicy/toolchain/include/spicy/ast/statements/reject.h:16:5
auto statementStop(Meta meta = {}) {
    return spicy::statement::Stop::create(context(), meta);
} // /Users/robin/work/spicy/node-rewrite/spicy/toolchain/include/spicy/ast/statements/stop.h:16:5
auto typeSink(const Meta& meta = {}) {
    return spicy::type::Sink::create(context(), meta);
} // /Users/robin/work/spicy/node-rewrite/spicy/toolchain/include/spicy/ast/types/sink.h:16:5
auto typeUnit(const hilti::declaration::Parameters& params, type::unit::Items items, AttributeSetPtr attrs,
              const Meta& meta = {}) {
    return spicy::type::Unit::create(context(), params, items, attrs, meta);
} // /Users/robin/work/spicy/node-rewrite/spicy/toolchain/include/spicy/ast/types/unit.h:101:5
auto typeUnit(hilti::type::Wildcard _, const Meta& meta = {}) {
    return spicy::type::Unit::create(context(), _, meta);
} // /Users/robin/work/spicy/node-rewrite/spicy/toolchain/include/spicy/ast/types/unit.h:114:5
auto typeUnitItemField(ID id, CtorPtr ctor, Engine engine, bool skip, Expressions args, ExpressionPtr repeat,
                       Expressions sinks, AttributeSetPtr attrs, ExpressionPtr cond, spicy::Hooks hooks,
                       const Meta& meta = {}) {
    return spicy::type::unit::item::Field::create(context(), id, ctor, engine, skip, args, repeat, sinks, attrs, cond,
                                                  hooks, meta);
} // /Users/robin/work/spicy/node-rewrite/spicy/toolchain/include/spicy/ast/types/unit-items/field.h:107:5
auto typeUnitItemField(ID id, const QualifiedTypePtr& type, Engine engine, bool skip, Expressions args,
                       ExpressionPtr repeat, Expressions sinks, AttributeSetPtr attrs, ExpressionPtr cond,
                       spicy::Hooks hooks, const Meta& meta = {}) {
    return spicy::type::unit::item::Field::create(context(), id, type, engine, skip, args, repeat, sinks, attrs, cond,
                                                  hooks, meta);
} // /Users/robin/work/spicy/node-rewrite/spicy/toolchain/include/spicy/ast/types/unit-items/field.h:100:5
auto typeUnitItemField(ID id, type::unit::ItemPtr item, Engine engine, bool skip, Expressions args,
                       ExpressionPtr repeat, Expressions sinks, AttributeSetPtr attrs, ExpressionPtr cond,
                       spicy::Hooks hooks, const Meta& meta = {}) {
    return spicy::type::unit::item::Field::create(context(), id, item, engine, skip, args, repeat, sinks, attrs, cond,
                                                  hooks, meta);
} // /Users/robin/work/spicy/node-rewrite/spicy/toolchain/include/spicy/ast/types/unit-items/field.h:114:5
auto typeUnitItemProperty(ID id, AttributeSetPtr attrs, bool inherited = false, const Meta& meta = {}) {
    return spicy::type::unit::item::Property::create(context(), id, attrs, inherited, meta);
} // /Users/robin/work/spicy/node-rewrite/spicy/toolchain/include/spicy/ast/types/unit-items/property.h:34:5
auto typeUnitItemProperty(ID id, ExpressionPtr expr, AttributeSetPtr attrs, bool inherited = false,
                          const Meta& meta = {}) {
    return spicy::type::unit::item::Property::create(context(), id, expr, attrs, inherited, meta);
} // /Users/robin/work/spicy/node-rewrite/spicy/toolchain/include/spicy/ast/types/unit-items/property.h:42:5
auto typeUnitItemSink(ID id, AttributeSetPtr attrs, const Meta& meta = {}) {
    return spicy::type::unit::item::Sink::create(context(), id, attrs, meta);
} // /Users/robin/work/spicy/node-rewrite/spicy/toolchain/include/spicy/ast/types/unit-items/sink.h:32:5
auto typeUnitItemSwitch(ExpressionPtr expr, type::unit::item::switch_::Cases cases, Engine engine, ExpressionPtr cond,
                        spicy::Hooks hooks, AttributeSetPtr attrs, const Meta& meta = {}) {
    return spicy::type::unit::item::Switch::create(context(), expr, cases, engine, cond, hooks, attrs, meta);
} // /Users/robin/work/spicy/node-rewrite/spicy/toolchain/include/spicy/ast/types/unit-items/switch.h:118:5
auto typeUnitItemSwitchCase(const Expressions& exprs, const type::unit::Items& items, const Meta& m = Meta()) {
    return spicy::type::unit::item::switch_::Case::create(context(), exprs, items, m);
} // /Users/robin/work/spicy/node-rewrite/spicy/toolchain/include/spicy/ast/types/unit-items/switch.h:53:5
auto typeUnitItemSwitchCase(const type::unit::Items& items, const Meta& m = Meta()) {
    return spicy::type::unit::item::switch_::Case::create(context(), items, m);
} // /Users/robin/work/spicy/node-rewrite/spicy/toolchain/include/spicy/ast/types/unit-items/switch.h:59:5
auto typeUnitItemSwitchCase(const type::unit::ItemPtr& field, const Meta& m = Meta()) {
    return spicy::type::unit::item::switch_::Case::create(context(), field, m);
} // /Users/robin/work/spicy/node-rewrite/spicy/toolchain/include/spicy/ast/types/unit-items/switch.h:64:5
auto typeUnitItemUnitHook(ID id, spicy::HookPtr hook, const Meta& meta = {}) {
    return spicy::type::unit::item::UnitHook::create(context(), id, hook, meta);
} // /Users/robin/work/spicy/node-rewrite/spicy/toolchain/include/spicy/ast/types/unit-items/unit-hook.h:33:5
auto typeUnitItemUnresolvedField(ID id, CtorPtr ctor, Engine engine, bool skip, Expressions args, ExpressionPtr repeat,
                                 Expressions sinks, AttributeSetPtr attrs, ExpressionPtr cond, spicy::Hooks hooks,
                                 const Meta& meta = {}) {
    return spicy::type::unit::item::UnresolvedField::create(context(), id, ctor, engine, skip, args, repeat, sinks,
                                                            attrs, cond, hooks, meta);
} // /Users/robin/work/spicy/node-rewrite/spicy/toolchain/include/spicy/ast/types/unit-items/unresolved-field.h:64:5
auto typeUnitItemUnresolvedField(ID id, ID unresolved_id, Engine engine, bool skip, Expressions args,
                                 ExpressionPtr repeat, Expressions sinks, AttributeSetPtr attrs, ExpressionPtr cond,
                                 spicy::Hooks hooks, const Meta& meta = {}) {
    return spicy::type::unit::item::UnresolvedField::create(context(), id, unresolved_id, engine, skip, args, repeat,
                                                            sinks, attrs, cond, hooks, meta);
} // /Users/robin/work/spicy/node-rewrite/spicy/toolchain/include/spicy/ast/types/unit-items/unresolved-field.h:78:5
auto typeUnitItemUnresolvedField(ID id, QualifiedTypePtr type, Engine engine, bool skip, Expressions args,
                                 ExpressionPtr repeat, Expressions sinks, AttributeSetPtr attrs, ExpressionPtr cond,
                                 spicy::Hooks hooks, const Meta& meta = {}) {
    return spicy::type::unit::item::UnresolvedField::create(context(), id, type, engine, skip, args, repeat, sinks,
                                                            attrs, cond, hooks, meta);
} // /Users/robin/work/spicy/node-rewrite/spicy/toolchain/include/spicy/ast/types/unit-items/unresolved-field.h:57:5
auto typeUnitItemUnresolvedField(ID id, type::unit::ItemPtr item, Engine engine, bool skip, Expressions args,
                                 ExpressionPtr repeat, Expressions sinks, AttributeSetPtr attrs, ExpressionPtr cond,
                                 spicy::Hooks hooks, const Meta& meta = {}) {
    return spicy::type::unit::item::UnresolvedField::create(context(), id, item, engine, skip, args, repeat, sinks,
                                                            attrs, cond, hooks, meta);
} // /Users/robin/work/spicy/node-rewrite/spicy/toolchain/include/spicy/ast/types/unit-items/unresolved-field.h:71:5
auto typeUnitItemVariable(ID id, QualifiedTypePtr type, ExpressionPtr default_, AttributeSetPtr attrs,
                          const Meta& meta = {}) {
    return spicy::type::unit::item::Variable::create(context(), id, type, default_, attrs, meta);
} // /Users/robin/work/spicy/node-rewrite/spicy/toolchain/include/spicy/ast/types/unit-items/variable.h:39:5
