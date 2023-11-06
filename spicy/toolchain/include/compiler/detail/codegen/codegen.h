// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

#include <hilti/ast/declarations/function.h>
#include <hilti/ast/declarations/property.h>
#include <hilti/ast/node.h>
#include <hilti/base/uniquer.h>
#include <hilti/compiler/driver.h>
#include <hilti/compiler/unit.h>

#include <spicy/ast/aliases.h>
#include <spicy/ast/builder/builder.h>
#include <spicy/ast/forward.h>
#include <spicy/compiler/detail/codegen/grammar-builder.h>
#include <spicy/compiler/detail/codegen/parser-builder.h>

namespace spicy::detail {

namespace codegen {
class GrammarBuilder;
class ParserBuilder;
} // namespace codegen

/**
 * Spicy's code generator. This is the main internal entry point for
 * generating HILTI code from Spicy source code. The Spicy AST reuses many
 * HILTI nodes. The code generator's task is to convert a mixed Spicy/HILTI
 * AST into a pure HILTI AST.
 */
class CodeGen {
public:
    CodeGen(Builder* builder) : _builder(builder), _gb(this), _pb(this) {}

    auto builder() const { return _builder; }
    auto context() const { return builder()->context(); }
    auto driver() const { return context()->driver(); }
    const auto& compilerContext() const { return driver()->context(); }
    const auto& options() const { return compilerContext()->options(); }

    /** Entry point for transformation from a Spicy AST to a HILTI AST. */
    bool compileAST(const ASTRootPtr& root);

    UnqualifiedTypePtr compileUnit(
        const type::UnitPtr& unit,
        bool declare_only = true); // Compiles a Unit type into its HILTI struct representation.

    NodeDerivedPtr<hilti::declaration::Function> compileHook(const type::Unit& unit, const ID& id,
                                                             hilti::NodeDerivedPtr<type::unit::item::Field> field,
                                                             bool foreach, bool debug,
                                                             hilti::type::function::Parameters params,
                                                             const hilti::StatementPtr& body,
                                                             const ExpressionPtr& priority, const hilti::Meta& meta);

    // These must be called only while a module is being compiled.
    codegen::ParserBuilder* parserBuilder() { return &_pb; }
    codegen::GrammarBuilder* grammarBuilder() { return &_gb; }
    hilti::Unit* hiltiUnit() const;       // will abort if not compiling a module.
    hilti::ModulePtr hiltiModule() const; // will abort if not compiling a module.
    auto uniquer() { return &_uniquer; }

    const auto& moduleProperties() const { return _properties; }
    void recordModuleProperty(hilti::declaration::Property p) { _properties.emplace_back(std::move(p)); }

    void addDeclaration(DeclarationPtr d) {
        _decls_added.insert(d->id());
        _new_decls.push_back(std::move(d));
    }

    bool haveAddedDeclaration(const ID& id) { return _decls_added.find(id) != _decls_added.end(); }

private:
    bool compileModule(ModulePtr module);

    Builder* _builder;
    codegen::GrammarBuilder _gb;
    codegen::ParserBuilder _pb;

    std::vector<hilti::declaration::Property> _properties;

    hilti::Unit* _hilti_unit = nullptr;
    Declarations _new_decls;
    std::unordered_set<ID> _decls_added;
    hilti::util::Uniquer<std::string> _uniquer;
};

} // namespace spicy::detail
