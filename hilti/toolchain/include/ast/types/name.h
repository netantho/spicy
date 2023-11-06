// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <utility>

#include <hilti/ast/declarations/type.h>
#include <hilti/ast/type.h>

namespace hilti::type {

/** AST node for type referenced by Name. */
class Name : public UnqualifiedType {
public:
    auto id() const { return _id; }
    bool isBuiltIn() const { return _builtin; }
    const auto& resolvedType() const { return _resolved; }

    void setResolvedType(NodeDerivedPtr<declaration::Type> d) { _resolved = std::move(d); }

    std::string_view typeClass() const final { return "name"; }

    node::Properties properties() const final {
        auto p = node::Properties{{"id", _id},
                                  {"builtin", _builtin},
                                  {"resolved", (_resolved ? _resolved->canonicalID().str() : std::string("-"))}};
        return UnqualifiedType::properties() + p;
    }

    static auto create(ASTContext* ctx, const ID& id, const Meta& meta = {}) {
        return NodeDerivedPtr<Name>(new Name(ctx, id, false, meta));
    }

protected:
    Name(ASTContext* ctx, ID id, bool builtin, Meta meta)
        : UnqualifiedType(ctx, {}, std::move(meta)), _id(std::move(id)), _builtin(builtin) {}

    bool isResolved() const final { return _resolved && _resolved->type()->isResolved(); }

    HILTI_NODE(hilti, Name)

private:
    ID _id;
    bool _builtin;
    NodeDerivedPtr<declaration::Type> _resolved;
};

} // namespace hilti::type
