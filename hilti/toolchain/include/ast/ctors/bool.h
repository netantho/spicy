// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/ctor.h>
#include <hilti/ast/types/bool.h>

namespace hilti::ctor {

/** AST node for a `bool` ctor. */
class Bool : public Ctor {
public:
    const auto& value() const { return _value; }

    QualifiedTypePtr type() const final { return child<QualifiedType>(0); }

    node::Properties properties() const final {
        auto p = node::Properties{{"value", _value}};
        return Ctor::properties() + p;
    }

    static auto create(ASTContext* ctx, bool v, const Meta& meta = {}) {
        return NodeDerivedPtr<Bool>(
            new Bool(ctx, {QualifiedType::create(ctx, type::Bool::create(ctx, meta), true)}, v, meta));
    }

protected:
    Bool(ASTContext* ctx, Nodes children, bool v, Meta meta)
        : Ctor(ctx, std::move(children), std::move(meta)), _value(v) {}

    HILTI_NODE(Bool)

private:
    bool _value;
};

} // namespace hilti::ctor
