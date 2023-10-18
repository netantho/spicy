// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/ctor.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/enum.h>

namespace hilti::ctor {

/** AST node for a enum constructor. */
class Enum : public Ctor {
public:
    auto value() const { return child<type::enum_::Label>(0); }

    QualifiedTypePtr type() const final { return child<QualifiedType>(1); }

    static auto create(ASTContext* ctx, const type::enum_::LabelPtr& label, const Meta& meta = {}) {
        return NodeDerivedPtr<Enum>(
            new Enum(ctx,
                     {label, QualifiedType::createExternal(ctx, std::weak_ptr<UnqualifiedType>(label->enumType()), true,
                                                           meta)},
                     meta));
    }

protected:
    Enum(ASTContext* ctx, Nodes children, Meta meta) : Ctor(ctx, std::move(children), std::move(meta)) {}

    HILTI_NODE(Enum)
};
} // namespace hilti::ctor
