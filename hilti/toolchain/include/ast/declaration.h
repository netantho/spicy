// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <utility>

#include <hilti/ast/forward.h>
#include <hilti/ast/id.h>
#include <hilti/ast/node.h>

namespace hilti {

namespace declaration {

/** Linkage defining visibility/accessibility of a declaration. */
enum class Linkage {
    Init,    /// executes automatically at startup, not otherwise accessible
    PreInit, /// executes automatically at load time, even before the runtime library is fully set up
    Struct,  /// method inside a method
    Private, /// accessible only locally
    Public,  /// accessible across modules
};

namespace detail {
constexpr util::enum_::Value<Linkage> linkages[] = {
    {Linkage::Struct, "struct"}, {Linkage::Public, "public"},   {Linkage::Private, "private"},
    {Linkage::Init, "init"},     {Linkage::PreInit, "preinit"},
};
} // namespace detail

/** Returns the HILTI string representation corresponding to a linkage. */
constexpr auto to_string(Linkage f) { return util::enum_::to_string(f, detail::linkages); }

namespace linkage {
/**
 * Parses a HILTI string representation of a linkage.
 *
 * @exception `std::out_of_range` if the string does not map to a linkage
 */
constexpr auto from_string(const std::string_view& s) { return util::enum_::from_string<Linkage>(s, detail::linkages); }
} // namespace linkage
} // namespace declaration

/** Base class for implementing declaration nodes. */
class Declaration : public Node, public node::WithDocString {
public:
    ~Declaration() override;

    /** Returns the declaration's ID. */
    const auto& id() const { return _id; }

    /** Returns the declaration's linkage. */
    auto linkage() const { return _linkage; }

    /**
     * Returns the declaration's fully qualified ID once it has been set
     * during AST processing.
     */
    auto fullyQualifiedID() const { return _fqid; }

    /**
     * Returns the canonical ID associated with the declaration. Canonical IDs
     * are automatically computed during AST processing and guaranteed to be
     * globally unique within one instance of an AST context.
     */
    const auto& canonicalID() const { return _canonical_id; }

    /** Sets the declaration's linkage. */
    void setLinkage(declaration::Linkage linkage) { _linkage = linkage; }

    /**
     * Sets the declaration's fully qualified ID. Should be used only by the ID
     * assigner during AST processing.
     *
     * @param id fully qualified ID
     */
    void setFullyQualifiedID(const ID& id) { _fqid = id; }

    /**
     * Associates a canonical ID with the declaration. Should be used only by
     * the ID assigner during AST processing.
     *
     * @param id canonical ID, which must be globally unique for this declaration
     */
    void setCanonicalID(ID id) { _canonical_id = std::move(id); }

    /**
     * Returns a user-friendly descriptive name for the type of object the declaration
     * refers to (e.g., "local variable"). This is used in error messages.
     */
    virtual std::string displayName() const = 0;

    /** Implements the node interface. */
    node::Properties properties() const override {
        auto p = node::Properties{{"id", _id},
                                  {"linkage", declaration::to_string(_linkage)},
                                  {"fqid", _fqid},
                                  {"canonical-id", _canonical_id}};

        return Node::properties() + p;
    }

protected:
    Declaration(ASTContext* ctx, Nodes children, ID id, declaration::Linkage linkage, Meta meta = {})
        : Node(ctx, std::move(children), std::move(meta)), _id(std::move(id)), _linkage(linkage) {}

    std::string _render() const override;

    HILTI_NODE_BASE(hilti, Declaration);

private:
    ID _id;
    ID _fqid;
    ID _canonical_id;
    declaration::Linkage _linkage;
};

} // namespace hilti
