"""what_bug_this_catches: same-kind fallback or asserted geometry becomes source proof."""

import pytest
from test_models import ARTIFACT, RAW, domain_wires, region, resolved, wire

from changelog_advisor.shared.cited import (
    DOMAIN_KEYS,
    POINTER_ADAPTER,
    ArtifactRef,
    DuplicateResolverError,
    Registry,
    Resolution,
    ResolutionContext,
)


def context(required_scope=None):
    policy = ArtifactRef(artifact_id="policy-1", artifact_sha256=RAW, profile_id="policy/1")
    return ResolutionContext(
        namespace_id="namespace-1",
        access_policy_ref=policy,
        generation_policy_ref=policy,
        required_scope=required_scope,
    )


class StubResolver:
    """Synthetic protocol spy; never reads actual source."""

    def __init__(self, result=None):
        self.calls = []
        self.result = result or Resolution.model_validate(resolved())

    def resolve(self, pointer, context):
        self.calls.append((pointer, context))
        return self.result


def test_default_every_declared_domain_is_unsupported_without_calls():
    registry = Registry()
    assert registry.installed_domains == frozenset()
    assert len(DOMAIN_KEYS) == len(domain_wires()) == 12
    for data in domain_wires():
        result = registry.resolve(POINTER_ADAPTER.validate_python(data), context())
        assert result.status == "unsupported"
        assert result.scope is None and result.excerpt is None


def test_same_kind_does_not_fallback_and_duplicate_never_replaces_owner():
    registry, resolver = Registry(), StubResolver()
    key = ("file:line", "supplied_text", "line")
    registry.register(key, resolver)
    with pytest.raises(DuplicateResolverError):
        registry.register(key, StubResolver())
    for key in (("file:line",), ("file:line", "supplied_text", "row")):
        with pytest.raises(ValueError):
            registry.register(key, StubResolver())
    assert registry.resolve(POINTER_ADAPTER.validate_python(wire()), context()).status == "resolved"
    repo = next(data for data in domain_wires() if data["source_type"] == "repository_file")
    assert (
        registry.resolve(POINTER_ADAPTER.validate_python(repo), context()).status == "unsupported"
    )
    assert len(resolver.calls) == 1


@pytest.mark.parametrize(
    "key",
    [["file:line", "supplied_text", "line"], ("file:line", [], "line"), ("file:line", 1, "line")],
)
def test_registration_rejects_nonclosed_key_without_mutation(key):
    registry = Registry()
    with pytest.raises(ValueError):
        registry.register(key, StubResolver())
    assert not registry.installed_domains


def test_row_domains_coexist_but_pending_locators_cannot_resolve():
    registry = Registry()
    spies = []
    for kind, source, subtype in (
        ("row:id", "event_table", "row"),
        ("row:id", "metric_table", "metric"),
    ):
        spy = StubResolver()
        spies.append(spy)
        registry.register((kind, source, subtype), spy)
    assert len(registry.installed_domains) == 2
    for data in domain_wires():
        if data["source_type"] in ("event_table", "metric_table"):
            assert (
                registry.resolve(POINTER_ADAPTER.validate_python(data), context()).status
                == "unsupported"
            )
    assert all(not spy.calls for spy in spies)


@pytest.mark.parametrize("required_scope", ["spatial", "text_and_spatial"])
def test_spatial_requirement_rejects_text_and_model_asserted_geometry(required_scope):
    pointer = POINTER_ADAPTER.validate_python(
        wire("document_page", "region", "doc:page:bbox", region())
    )
    registry = Registry()
    resolver = StubResolver()
    registry.register(("doc:page:bbox", "document_page", "region"), resolver)
    assert registry.resolve(pointer, context(required_scope)).status == "unsupported"
    resolver.result = Resolution.model_validate(
        resolved(
            scope="asserted_spatial",
            provenance={
                "geometry_provenance": "model_claimed",
                "ocr_confidence": None,
            },
        )
    )
    assert registry.resolve(pointer, context(required_scope)).status == "unsupported"


@pytest.mark.parametrize(
    "field", ["checked_source_revision", "checked_source_sha256", "checked_artifact_sha256"]
)
def test_resolver_checked_bindings_cannot_retarget_evidence(field):
    value = "generation-2" if field.endswith("revision") else "f" * 64
    registry = Registry()
    registry.register(
        ("file:line", "supplied_text", "line"),
        StubResolver(Resolution.model_validate(resolved(**{field: value}))),
    )
    result = registry.resolve(POINTER_ADAPTER.validate_python(wire()), context())
    assert result.status == "invalid" and result.reason == "checked_identity_mismatch"


def test_unchecked_models_and_unsafe_resolver_error_never_escape_contract():
    registry, resolver = Registry(), StubResolver()
    registry.register(("file:line", "supplied_text", "line"), resolver)
    pointer = POINTER_ADAPTER.validate_python(wire())
    unsafe = pointer.model_copy(update={"source_sha256": "broken"})
    assert registry.resolve(unsafe, context()).status == "invalid"
    assert not resolver.calls

    class ErrorResolver:
        def resolve(self, pointer, context):
            raise RuntimeError("private-canary-source-body")

    registry = Registry()
    registry.register(("file:line", "supplied_text", "line"), ErrorResolver())
    result = registry.resolve(pointer, context())
    assert result.status == "invalid"
    assert "private-canary" not in result.model_dump_json()


def test_unknown_tag_version_and_extra_actions_do_not_dispatch():
    registry, resolver = Registry(), StubResolver()
    registry.register(("file:line", "supplied_text", "line"), resolver)
    assert (
        registry.resolve({**wire(), "source_type": "unregistered"}, context()).status
        == "unsupported"
    )
    assert registry.resolve({**wire(), "schema_version": 2}, context()).status == "unsupported"
    assert registry.resolve({**wire(), "execute": "anything"}, context()).status == "invalid"
    assert not resolver.calls


def test_redacted_log_requires_explicit_owner_scope_and_never_claims_raw_view():
    registry, resolver = Registry(), StubResolver()
    registry.register(("file:line", "configured_log", "line"), resolver)
    data = wire(
        "configured_log", locator={"line_start": 1, "line_end": 2, "view_kind": "redacted_result"}
    )
    data["source_revision"] = f"sha256:{RAW}"
    pointer = POINTER_ADAPTER.validate_python(data)
    assert registry.resolve(pointer, context()).status == "invalid"
    resolver.result = Resolution.model_validate(
        resolved(
            checked_source_revision=f"sha256:{RAW}",
            provenance={
                "owner_resolution_scope": "redacted_text",
                "view_kind": "redacted_result",
            },
        )
    )
    result = registry.resolve(pointer, context())
    assert result.status == "resolved" and result.scope == "text"
    assert result.checked_source_sha256 == RAW and result.checked_artifact_sha256 == ARTIFACT
