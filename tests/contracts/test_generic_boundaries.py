"""Generic structural scope checks, with independent declared-support identities."""

import hashlib
import json
from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from firewall_analyst.shared.rulesengine.fixtures import GoldEpisodeV1, GoldManifestV1
from firewall_analyst.shared.rulesengine.parsers import ParseIssue, SourceLine
from firewall_analyst.shared.rulesengine.schemas import (
    ClaimSupportContractV1,
    ClaimV1,
    EvidenceSupport,
    FlaggedGroupV1,
    InputLimitsV1,
    KeyPart,
    ParseSummaryV1,
    TimeWindow,
    TypedStatV1,
)

SOURCE = "a" * 64


def support(rows=("resource:1", "resource:2"), source=SOURCE):
    # Independent fixture convention: full SHA of sorted compact UTF-8 JSON row-ID array.
    digest = hashlib.sha256(json.dumps(sorted(rows), separators=(",", ":")).encode()).hexdigest()
    return EvidenceSupport(source_sha256=source, row_ids=rows, support_sha256=digest)


def stat(**changes):
    return TypedStatV1(
        **{
            "stat_id": "changes",
            "value": 2,
            "unit": "count",
            "support": support(),
            "known_count": 2,
            "unknown_count": 0,
            **changes,
        }
    )


def group(**changes):
    return FlaggedGroupV1(
        **{
            "group_id": "b" * 64,
            "rule_id": "resource_change",
            "rule_version": "1.0",
            "config_sha256": "c" * 64,
            "window": TimeWindow(start_us=0, end_us=10),
            "grouping_key": (KeyPart(name="module", value="demo"),),
            "support": support(),
            "stats": (stat(),),
            "category_from_rule": "resource_change",
            "severity_from_rule": 2,
            **changes,
        }
    )


def claim(**changes):
    return ClaimV1(
        **{
            "stat_ref": "changes",
            "value": 2,
            "unit": "count",
            "formatter": "integer",
            "support": support(),
            **changes,
        }
    )


def test_non_network_group_and_claim_construct_and_roundtrip():
    boundary = ClaimSupportContractV1(group=group(), claims=(claim(),))
    assert ClaimSupportContractV1.model_validate_json(boundary.model_dump_json()) == boundary
    assert boundary.group.category_from_rule == "resource_change"


@pytest.mark.parametrize("value", [float("nan"), float("inf"), True, "2"])
def test_numeric_statistics_reject_nonfinite_boolean_and_coercion(value):
    with pytest.raises(ValidationError):
        stat(value=value)


def test_unknown_stat_keeps_null_and_known_zero_remains_zero():
    assert stat(value=None, known_count=0, unknown_count=2).value is None
    assert stat(value=0).value == 0
    with pytest.raises(ValidationError, match="zero known support"):
        stat(value=None)
    with pytest.raises(ValidationError, match="counts must cover"):
        stat(known_count=1)


def test_support_requires_nonempty_unique_rows_and_exact_digest():
    with pytest.raises(ValidationError, match="at least 1"):
        support(())
    with pytest.raises(ValidationError, match="duplicate support"):
        support(("resource:1", "resource:1"))
    payload = support().model_dump()
    payload["support_sha256"] = "0" * 64
    with pytest.raises(ValidationError, match="digest mismatch"):
        EvidenceSupport(**payload)


def test_group_rejects_foreign_generation_or_row_scope():
    for changed, reason in (
        (stat(support=support(source="d" * 64)), "different generation"),
        (stat(support=support(("foreign:1", "foreign:2"))), "escapes group"),
    ):
        with pytest.raises(ValidationError, match=reason):
            group(stats=(changed,))
    with pytest.raises(ValidationError, match="duplicate statistic"):
        group(stats=(stat(), stat()))
    with pytest.raises(ValidationError, match="at least 1"):
        group(stats=())


@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        ({"stat_ref": "not_present"}, "declared statistic"),
        ({"unit": "bytes"}, "matching unit"),
        ({"support": support(source="d" * 64)}, "different generation"),
        ({"support": support(("foreign:1",))}, "escapes statistic"),
        ({"value": 999}, "contradicts the declared statistic"),
    ],
)
def test_claim_rejects_wrong_reference_unit_generation_scope_or_full_value(changes, reason):
    with pytest.raises(ValidationError, match=reason):
        ClaimSupportContractV1(group=group(), claims=(claim(**changes),))


def test_schema_is_not_a_recomputation_or_source_existence_checker():
    # Internally consistent invented numbers remain constructible; future WP05 must recompute.
    declared = group(stats=(stat(value=999),))
    assert ClaimSupportContractV1(group=declared, claims=(claim(value=999),))
    # Subset arithmetic also remains a future checker obligation, not invented by this schema.
    assert ClaimSupportContractV1(
        group=group(), claims=(claim(value=1, support=support(("resource:1",))),)
    )


def test_partial_and_suppressed_groups_require_explicit_reasons():
    with pytest.raises(ValidationError, match="context identity"):
        group(status="suppressed")
    with pytest.raises(ValidationError, match="quality reason"):
        group(status="partial")
    assert group(status="suppressed", matched_context_ids=("maintenance",))
    assert group(status="partial", quality_flags=("input_incomplete",))


def summary(**changes):
    return ParseSummaryV1(
        **{
            "state": "complete",
            "source_sha256": SOURCE,
            "original_rows": 0,
            "processed_rows": 0,
            "quarantined_rows": 0,
            "excluded_rows": 0,
            **changes,
        }
    )


def test_empty_complete_and_unknown_partial_counts_remain_distinct():
    assert summary().original_rows == 0
    partial = summary(
        state="partial", original_rows=None, excluded_rows=None, reason_codes=("row_limit",)
    )
    assert partial.original_rows is partial.excluded_rows is None
    for state in ("unsupported", "error"):
        assert summary(state=state, reason_codes=("schema_unavailable",)).state == state


@pytest.mark.parametrize(
    "changes",
    [
        {"state": "partial"},
        {"original_rows": None},
        {"source_sha256": None},
        {"excluded_rows": 1},
        {"processed_rows": 1},
        {"processed_rows": True},
        {
            "state": "partial",
            "original_rows": None,
            "source_sha256": None,
            "processed_rows": 1,
            "reason_codes": ("row_limit",),
        },
    ],
)
def test_inconsistent_parse_status_and_counter_claims_fail(changes):
    with pytest.raises(ValidationError):
        summary(**changes)


def test_hard_input_limit_has_no_fake_generation_or_counters():
    payload = dict(
        state="error",
        source_sha256=None,
        original_rows=None,
        processed_rows=None,
        quarantined_rows=None,
        excluded_rows=None,
        reason_codes=("input_limit",),
    )
    assert ParseSummaryV1(**payload).source_sha256 is None
    with pytest.raises(ValidationError, match="cannot invent row counts"):
        ParseSummaryV1(**{**payload, "processed_rows": 0})


def test_physical_source_lines_are_one_based_and_windows_are_nonempty():
    with pytest.raises(ValidationError):
        SourceLine(physical_line=0, text="synthetic")
    with pytest.raises(ValidationError):
        ParseIssue(physical_line=0, reason_code="bad_row")
    with pytest.raises(ValidationError, match="positive duration"):
        TimeWindow(start_us=10, end_us=10)
    with pytest.raises(ValidationError):
        InputLimitsV1(max_file_bytes=0)


def test_gold_seeds_and_freeze_timestamp_do_not_leak_or_overlap():
    payload = dict(
        generator_sha256=SOURCE,
        config_sha256="b" * 64,
        frozen_at_utc=datetime(2026, 10, 14, tzinfo=UTC),
        dev_seeds=(1, 2),
        heldout_seeds=(1001, 1002),
    )
    manifest = GoldManifestV1(**payload)
    assert GoldManifestV1.model_validate_json(manifest.model_dump_json()) == manifest
    for changes in (
        {"heldout_seeds": (2, 1001)},
        {"dev_seeds": (1, 1)},
        {"frozen_at_utc": datetime(2026, 10, 14)},
        {"frozen_at_utc": datetime(2026, 10, 14, tzinfo=timezone(timedelta(hours=1)))},
    ):
        with pytest.raises(ValidationError):
            GoldManifestV1(**{**payload, **changes})
    episode = GoldEpisodeV1(
        episode_id="slow_change",
        kind="expected_miss",
        pattern="resource_change",
        subject_key=(KeyPart(name="module", value="demo"),),
        window=TimeWindow(start_us=0, end_us=10),
        support=support(),
        expected_category="resource_change",
        expected_severity=2,
    )
    assert episode.kind == "expected_miss"  # No scorer or synthetic performance claim here.
