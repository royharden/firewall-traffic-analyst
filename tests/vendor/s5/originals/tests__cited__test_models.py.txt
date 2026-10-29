"""what_bug_this_catches: structural metadata silently becomes evidence or authority."""

import copy
import hashlib
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from changelog_advisor.shared.cited import DOMAIN_KEYS, POINTER_ADAPTER, Finding, SourceArtifact
from changelog_advisor.shared.cited.models import (
    ArtifactRef,
    Resolution,
    ResolutionProvenance,
)
from changelog_advisor.shared.cited.schema import encoded_schemas

RAW = "a" * 64
ARTIFACT = "b" * 64
PAGE = "c" * 64
QUERY = "d" * 64


def digest(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def wire(source_type="supplied_text", subtype="line", kind="file:line", locator=None):
    """Construct synthetic wire inputs; hashes are placeholders, not captured source proof."""
    return {
        "schema_version": 1,
        "kind": kind,
        "source_type": source_type,
        "locator_subtype": subtype,
        "source_id": "source-1",
        "source_sha256": RAW,
        "source_revision": "generation-1",
        "evidence_artifact_sha256": ARTIFACT,
        "provenance_ref": None,
        "locator": {"line_start": 1, "line_end": 2} if locator is None else locator,
    }


def region(**changes):
    result = {
        "document_id": "source-1",
        "page_id": "page-1",
        "page_index": 0,
        "page_sha256": PAGE,
        "page_digest_algorithm": "rgba8-source-grid-v1",
        "source_grid_profile": "retained-rgba8/1",
        "width_px": 100,
        "height_px": 80,
        "units": "px",
        "origin": "top-left",
        "bbox_px": None,
        "word_ids": None,
        "line_ids": ["line-1"],
        "excerpt_sha256": None,
        "transform_ref": None,
    }
    result.update(changes)
    return result


def snapshot():
    return {
        "repository_id": "source-1",
        "source_kind": "fixture_inventory",
        "snapshot_id": RAW,
        "inventory_sha256": RAW,
    }


def domain_wires():
    base = [
        wire(),
        wire(
            "configured_log",
            locator={"line_start": 1, "line_end": 2, "view_kind": "redacted_result"},
        ),
        wire(
            "repository_file",
            locator={
                **snapshot(),
                "path": "src/a.py",
                "line_start": 1,
                "line_end": 1,
                "definition_kind": "function",
            },
        ),
        wire(
            "code_existence_report",
            "report_item",
            "doc:section",
            {
                **snapshot(),
                "item_id": QUERY,
                "reference_id": QUERY,
                "query_sha256": PAGE,
                "coverage_sha256": ARTIFACT,
            },
        ),
        wire("supplied_text", "section", "doc:section", {"section_id": "release-1"}),
        wire("document_page", "region", "doc:page:bbox", region()),
        wire("screenshot_collection", "source_region", "doc:page:bbox", region()),
        wire(
            "product_catalog",
            "record_field",
            "row:id",
            {
                "dataset_id": "source-1",
                "record_id": "record-1",
                "field_id": "name",
                "quote": "  é Fixture NAME  ",
                "excerpt_sha256": digest("  é Fixture NAME  "),
            },
        ),
        {**wire("event_table", "row", "row:id"), "locator": None},
        {**wire("metric_table", "metric", "row:id"), "locator": None},
        wire("saved_web", "fragment", "url#fragment", {"fragment_id": "anchor-1"}),
        wire("advisory_record", "id", "advisory:id", {"advisory_id": "GHSA-fixture"}),
    ]
    for value in base:
        if value["source_type"] == "configured_log":
            value["source_revision"] = f"sha256:{RAW}"
        if value["source_type"] == "product_catalog":
            value["source_revision"] = f"rg1:{RAW}"
            field = {
                "algorithm": "product-record-field-evidence-v1",
                "dataset_id": "source-1",
                "record_id": "record-1",
                "source_sha256": RAW,
                "source_revision": f"rg1:{RAW}",
                "field_id": "name",
                "raw_value": value["locator"]["quote"],
            }
            value["evidence_artifact_sha256"] = digest(
                json.dumps(
                    field,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                    allow_nan=False,
                )
            )
        if value["source_type"] in ("repository_file", "code_existence_report"):
            value["source_revision"] = f"snapshot:fixture_inventory:{RAW}"
        if value["source_type"] == "repository_file":
            value["evidence_artifact_sha256"] = RAW
    return base


@pytest.mark.parametrize(
    "value", domain_wires(), ids=lambda value: value["source_type"] + "/" + value["locator_subtype"]
)
def test_full_domain_union_roundtrip_preserves_bindings(value):
    pointer = POINTER_ADAPTER.validate_python(value)
    restored = POINTER_ADAPTER.validate_json(POINTER_ADAPTER.dump_json(pointer))
    assert restored == pointer
    for name in ("source_id", "source_revision", "source_sha256", "evidence_artifact_sha256"):
        assert getattr(restored, name) == value[name]
    assert (pointer.kind, pointer.source_type, pointer.locator_subtype) in DOMAIN_KEYS


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema_version", True),
        ("schema_version", "1"),
        ("schema_version", 2),
        ("source_sha256", "not-a-digest"),
        ("source_sha256", "A" * 64),
        ("source_id", "C:\\private\\source"),
        ("source_id", "https://example.org/source"),
        ("source_id", "../source"),
        ("source_id", ""),
        ("kind", "file_line"),
        ("locator_subtype", "row"),
        ("source_type", "screenshot_page"),
        ("execute", "untrusted action"),
    ],
)
def test_closed_wire_rejects_coercion_aliases_and_paths(field, value):
    data = wire()
    data[field] = value
    with pytest.raises(ValidationError):
        POINTER_ADAPTER.validate_python(data)


@pytest.mark.parametrize(
    "locator",
    [
        {"line_start": True, "line_end": 2},
        {"line_start": "1", "line_end": 2},
        {"line_start": 0, "line_end": 2},
        {"line_start": 3, "line_end": 2},
        {"line_start": 1, "line_end": 2, "quote": "literal", "excerpt_sha256": RAW},
        {"line_start": 1, "line_end": 2, "quote": ""},
        {"line_start": 1, "line_end": 2, "quote": "literal"},
        {"line_start": 1, "line_end": 2, "fetch": "https://example.org"},
    ],
)
def test_invalid_quote_and_line_claims_reject(locator):
    with pytest.raises(ValidationError):
        POINTER_ADAPTER.validate_python(wire(locator=locator))


def test_literal_quote_digest_does_not_normalize_or_verify_semantics():
    quote = "é\r\n  Exact CASE"
    pointer = POINTER_ADAPTER.validate_python(
        wire(
            locator={
                "line_start": 1,
                "line_end": 2,
                "quote": quote,
                "excerpt_sha256": digest(quote),
            }
        )
    )
    assert pointer.locator.quote == quote
    claim = Finding(
        id="finding-1",
        text="An unverified semantic claim",
        verdict="partial",
        probability=1.0,
        evidence=[pointer],
    )
    assert claim.verdict == "partial"
    assert claim.method is None and claim.confidence is None
    with pytest.raises(ValidationError):
        Finding.model_validate({**claim.model_dump(), "verdict": "verified"})
    changed = wire(
        locator={
            "line_start": 1,
            "line_end": 2,
            "quote": quote.replace("\r\n", "\n"),
            "excerpt_sha256": digest(quote),
        }
    )
    with pytest.raises(ValidationError):
        POINTER_ADAPTER.validate_python(changed)


@pytest.mark.parametrize(
    "changes",
    [
        {"page_index": True},
        {"page_index": -1},
        {"page_index_base": 1},
        {"units": "norm"},
        {"origin": "bottom-left"},
        {"width_px": "100"},
        {"bbox_px": {"x0": 0, "y0": 0, "x1": float("nan"), "y1": 2}},
        {"bbox_px": {"x0": 0, "y0": 0, "x1": float("inf"), "y1": 2}},
        {"bbox_px": {"x0": 0, "y0": 0, "x1": 101, "y1": 2}},
        {"bbox_px": {"x0": 1, "y0": 0, "x1": 1, "y1": 2}},
        {"line_ids": []},
        {"line_ids": ["line-1", "line-1"]},
        {"line_ids": None},
        {"document_id": "different-document"},
    ],
)
def test_source_region_shape_rejects_ambiguous_or_impossible_bounds(changes):
    with pytest.raises(ValidationError):
        POINTER_ADAPTER.validate_python(
            wire("document_page", "region", "doc:page:bbox", region(**changes))
        )


def test_line_only_and_box_only_regions_preserve_distinct_nulls():
    line = POINTER_ADAPTER.validate_python(
        wire("document_page", "region", "doc:page:bbox", region())
    )
    assert line.locator.bbox_px is None and line.locator.excerpt_sha256 is None
    assert line.locator.line_ids == ("line-1",)
    box = POINTER_ADAPTER.validate_python(
        wire(
            "document_page",
            "region",
            "doc:page:bbox",
            region(line_ids=None, bbox_px={"x0": 0, "y0": 0, "x1": 10, "y1": 10}),
        )
    )
    assert box.locator.word_ids is None and box.locator.line_ids is None
    assert box.provenance_ref is None


@pytest.mark.parametrize("source_type", ["repository_file", "code_existence_report"])
@pytest.mark.parametrize(
    "mutation",
    [
        "fixture_as_git",
        "wrong_revision",
        "wrong_repo",
        "wrong_artifact_or_inventory",
        "wrong_item_or_path",
    ],
)
def test_snapshot_report_bindings_cannot_swap_generations(source_type, mutation):
    value = copy.deepcopy(
        next(item for item in domain_wires() if item["source_type"] == source_type)
    )
    if mutation == "fixture_as_git":
        value["locator"]["source_kind"] = "git_commit"
    elif mutation == "wrong_revision":
        value["source_revision"] = "snapshot:git_commit:" + "e" * 40
    elif mutation == "wrong_repo":
        value["source_id"] = "different-repository"
    elif mutation == "wrong_artifact_or_inventory":
        value["source_sha256"] = PAGE
    elif source_type == "repository_file":
        value["locator"]["path"] = "../escape.py"
    else:
        value["locator"]["item_id"] = RAW
    with pytest.raises(ValidationError):
        POINTER_ADAPTER.validate_python(value)


def test_log_offsets_and_omitted_body_remain_separate():
    data = wire(
        "configured_log",
        locator={
            "line_start": 3,
            "line_end": 4,
            "view_kind": "redacted_result",
            "source_byte_start": 50,
            "source_byte_end": 500,
            "artifact_byte_start": 2,
            "artifact_byte_end": 20,
        },
    )
    data["source_revision"] = f"sha256:{RAW}"
    pointer = POINTER_ADAPTER.validate_python(data)
    assert pointer.locator.quote is None and pointer.locator.excerpt_sha256 is None
    assert pointer.locator.source_byte_end != pointer.locator.artifact_byte_end
    data["locator"]["source_byte_end"] = None
    with pytest.raises(ValidationError):
        POINTER_ADAPTER.validate_python(data)


@pytest.mark.parametrize(
    "changes",
    [{"dataset_id": "another-dataset"}, {"field_id": "../private"}, {"field_id": "https://bad"}],
)
def test_product_namespace_and_field_are_not_path_authority(changes):
    data = copy.deepcopy(
        next(item for item in domain_wires() if item["source_type"] == "product_catalog")
    )
    data["locator"].update(changes)
    with pytest.raises(ValidationError):
        POINTER_ADAPTER.validate_python(data)


@pytest.mark.parametrize("value", [-0.1, 1.1, float("nan"), float("inf"), True, "0.9"])
def test_finding_probabilities_reject_nonfinite_and_coercion(value):
    with pytest.raises(ValidationError):
        Finding(id="finding-1", text="Claim", verdict="partial", probability=value, evidence=[])


@pytest.mark.parametrize("mutation", ["revision", "artifact", "empty", "partial", "unknown_field"])
def test_product_selected_profile_is_exact_nonempty_raw_field(mutation):
    data = copy.deepcopy(
        next(item for item in domain_wires() if item["source_type"] == "product_catalog")
    )
    if mutation == "revision":
        data["source_revision"] = "normalizer-generation-1"
    elif mutation == "artifact":
        data["evidence_artifact_sha256"] = RAW
    elif mutation == "empty":
        data["locator"]["quote"] = ""
        data["locator"]["excerpt_sha256"] = digest("")
    elif mutation == "partial":
        data["locator"]["quote"] = "Fixture"
        data["locator"]["excerpt_sha256"] = digest("Fixture")
    else:
        data["locator"]["field_id"] = "arbitrary_column"
    with pytest.raises(ValidationError):
        POINTER_ADAPTER.validate_python(data)


def test_log_raw_revision_cannot_use_redactor_or_index_epoch():
    data = copy.deepcopy(
        next(item for item in domain_wires() if item["source_type"] == "configured_log")
    )
    data["source_revision"] = "index-epoch-1"
    with pytest.raises(ValidationError):
        POINTER_ADAPTER.validate_python(data)


def test_model_construction_does_not_supply_human_or_source_authority():
    unsupported = Finding(id="finding-1", text="Unknown", verdict="unsupported", evidence=[])
    assert unsupported.probability is None
    for extra in ({"human_approved": True}, {"support_verified": True}, {"category": "api"}):
        with pytest.raises(ValidationError):
            Finding.model_validate({**unsupported.model_dump(), **extra})
    with pytest.raises(ValidationError):
        ArtifactRef(artifact_id="file:///private", artifact_sha256=RAW, profile_id="profile/1")


def resolved(**changes):
    data = {
        "status": "resolved",
        "checked_source_revision": "generation-1",
        "checked_source_sha256": RAW,
        "checked_artifact_sha256": ARTIFACT,
        "scope": "text",
        "reason": "occurrence_checked",
    }
    data.update(changes)
    return data


def test_resolution_scopes_preserve_assertion_and_unknown_confidence():
    asserted = Resolution.model_validate(
        resolved(
            scope="asserted_spatial",
            provenance={
                "geometry_provenance": "model_claimed",
                "ocr_confidence": None,
            },
        )
    )
    assert asserted.provenance.ocr_confidence is None
    for changes in (
        {"scope": "spatial", "provenance": asserted.provenance},
        {"checked_artifact_sha256": None},
        {"scope": None},
        {"excerpt": "invented", "excerpt_sha256": RAW},
        {"status": "missing"},
        {"support_verified": True},
    ):
        with pytest.raises(ValidationError):
            Resolution.model_validate(resolved(**changes))
    native = Resolution.model_validate(
        resolved(
            scope="spatial",
            provenance={
                "geometry_provenance": "native",
                "ocr_confidence": None,
            },
        )
    )
    assert native.excerpt is None
    assert ResolutionProvenance().ocr_confidence is None


def test_raw_empty_source_metadata_is_not_an_invented_quote():
    source = SourceArtifact(
        source_id="source-1",
        source_type="supplied_text",
        source_sha256=RAW,
        source_revision="generation-1",
        evidence_artifact_sha256=ARTIFACT,
        raw_byte_length=0,
    )
    assert source.line_map == () and source.canonical_text_sha256 is None
    with pytest.raises(ValidationError):
        SourceArtifact.model_validate({**source.model_dump(), "canonical_text_sha256": PAGE})
    mapped = {
        **source.model_dump(),
        "canonical_text_sha256": PAGE,
        "newline_policy": "crlf-to-lf",
        "line_map": [
            {"source_line": 2, "canonical_line": 1},
            {"source_line": 1, "canonical_line": 2},
        ],
    }
    with pytest.raises(ValidationError):
        SourceArtifact.model_validate(mapped)
    mapped["line_map"] = [
        {"source_line": 1, "canonical_line": 2},
        {"source_line": 2, "canonical_line": 1},
    ]
    with pytest.raises(ValidationError):
        SourceArtifact.model_validate(mapped)


def test_generated_schema_bytes_match_models_and_close_nested_objects():
    root = Path(__file__).resolve().parents[2]
    for name, text in encoded_schemas().items():
        assert (root / "schemas" / "cited" / name).read_text(encoding="utf-8") == text
        schema = json.loads(text)
        for definition in schema.get("$defs", {}).values():
            if definition.get("type") == "object":
                assert definition["additionalProperties"] is False
    assert len(json.loads(encoded_schemas()["pointer.schema.json"])["oneOf"]) == 12
