// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <utility>

#include <hilti/ast/declaration.h>

#include <spicy/ast/hook.h>

namespace spicy::declaration {

/** AST node for a declaration of an external (i.e., module-level) unit hook. */
class UnitHook : public Declaration {
public:
    auto hook() const { return child<Hook>(0); }

    std::string displayName() const final { return "unit hook"; }

    static auto create(ASTContext* ctx, ID id, const HookPtr& hook, Meta meta = {}) {
        return NodeDerivedPtr<UnitHook>(new UnitHook(ctx, {hook}, std::move(id), std::move(meta)));
    }

protected:
    UnitHook(ASTContext* ctx, Nodes children, ID id, Meta meta)
        : Declaration(ctx, std::move(children), std::move(id), hilti::declaration::Linkage::Private, std::move(meta)) {}

    HILTI_NODE(hilti, UnitHook)
};

} // namespace spicy::declaration
