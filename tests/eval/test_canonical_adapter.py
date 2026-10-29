"""Fresh handwritten toy sources/references, never original S8 corpus or Gold."""

import hashlib
import sys
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pydantic
import pydantic_core
import pytest

from firewall_analyst.domain.evaluation.adapter import (
    ADAPTER_VERSION,
    STATISTIC_VERSION,
    DetectionAdapter,
)
from firewall_analyst.domain.evaluation.config import PublicEvaluationProfile
from firewall_analyst.domain.evaluation.methods import (
    RegisteredSource,
    SourceUnavailable,
    TrustedSourceCatalogue,
    local_method_configs,
    profile_digest,
)
from firewall_analyst.domain.evaluation.metrics import public_rows, report_rows
from firewall_analyst.domain.parsers import parse_zeek_file
from firewall_analyst.shared.evalkit.corpus import FrozenCorpusError, load_corpus
from firewall_analyst.shared.evalkit.identity import canonical_bytes, ordered_ids_digest
from firewall_analyst.shared.evalkit.models import (
    DomainLabels,
    GoldRecord,
    Manifest,
    PinnedReference,
    SourceArtifact,
    SourceRef,
    SplitEntry,
)
from firewall_analyst.shared.evalkit.runner import compare
from firewall_analyst.shared.rulesengine.fixtures import GoldEpisodeV1
from firewall_analyst.shared.rulesengine.schemas import (
    EvidenceSupport,
    KeyPart,
    TimeWindow,
    support_digest,
)

ROOT = Path(__file__).resolve().parents[2]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def toy(tmp_path, *, checks=None, active=None, destination="192.0.2.2"):
    """The family/provenance names below are explicit toy wire declarations, not experiments."""
    profile = PublicEvaluationProfile.model_validate_json(
        (ROOT / "config/evaluation-public-setup.v1.json").read_bytes()
    )
    ref = profile_digest(profile)
    entries, records, paths = [], [], []
    for index in range(2):
        path = tmp_path / f"hand-source-{index}.jsonl"
        raw = b"".join(
            canonical_bytes(
                {
                    "ts": index,
                    "id.orig_h": "192.0.2.1",
                    "id.resp_h": destination,
                    "id.orig_p": 40000 + index,
                    "id.resp_p": port,
                    "proto": "tcp",
                }
            )
            + b"\n"
            for port in range(16)
        )
        path.write_bytes(raw)
        parsed = parse_zeek_file(path, format="jsonl", internal_cidrs=profile.internal_cidrs)
        digest, handle = sha(raw), f"toy-source-{index}"
        check = checks[index] if checks else lambda p=path, h=digest: sha(p.read_bytes()) == h
        entries.append(RegisteredSource(handle, digest, parsed, check))
        paths.append(path)
        episodes = []
        for kind, rows in [("positive", parsed.records), ("benign", parsed.records[:1])]:
            ids = tuple(row.row_id for row in rows)
            episodes.append(
                GoldEpisodeV1(
                    episode_id=f"hand-{kind}-{index}",
                    kind=kind,
                    pattern="port_scan",
                    subject_key=(
                        KeyPart(name="src", value="192.0.2.1"),
                        KeyPart(name="protocol", value="tcp"),
                    ),
                    window=TimeWindow(start_us=index * 1_000_000, end_us=index * 1_000_000 + 1),
                    support=EvidenceSupport(
                        source_sha256=digest, row_ids=ids, support_sha256=support_digest(ids)
                    ),
                    expected_category="benign" if kind == "benign" else "port_scan",
                    expected_severity=1 if kind == "benign" else 3,
                )
            )
        records.append(
            GoldRecord(
                item_id=f"toy-unit-{index}",
                dataset="PRIVATE-DATASET",
                group_id=f"PRIVATE-FAMILY-{index}",
                split="dev",
                label_version="hand-authored-toy-1",
                source_ref=SourceRef(handle=handle, sha256=digest),
                input_sha256=digest,
                label_source="synthetic",
                label_provenance_ref="hand-code-declaration",
                domain_kind=ADAPTER_VERSION,
                label_payload=DomainLabels(
                    kind="domain_labels",
                    payload={
                        "adapter_version": ADAPTER_VERSION,
                        "episodes": [e.model_dump(mode="json") for e in episodes],
                        "public_profile_content_sha256": ref,
                    },
                ),
            )
        )
    catalogue = TrustedSourceCatalogue(tuple(entries))
    source_paths = []
    for directory in [
        "src/firewall_analyst/shared/rulesengine",
        "src/firewall_analyst/domain/rules",
        "src/firewall_analyst/domain/parsers",
    ]:
        source_paths.extend(sorted((ROOT / directory).glob("*.py")))
    source_paths += [
        ROOT / p
        for p in [
            "src/firewall_analyst/domain/evaluation/methods.py",
            "src/firewall_analyst/domain/evaluation/config.py",
            "src/firewall_analyst/domain/schemas.py",
            "src/firewall_analyst/baselines/proxies.py",
        ]
    ]
    closure = [(p.relative_to(ROOT).as_posix(), sha(p.read_bytes())) for p in source_paths]
    parser_closure = [
        row for row in closure if "parsers" in row[0] or row[0].endswith(("schemas.py", "rows.py"))
    ]
    execution_refs = {
        "source_closure": sha(canonical_bytes(closure)),
        "parser_closure": sha(canonical_bytes(parser_closure)),
        "runtime": sha(
            canonical_bytes(
                {
                    "python": sys.version,
                    "pydantic": pydantic.__version__,
                    "core": pydantic_core.__version__,
                }
            )
        ),
    }
    configs = local_method_configs(profile, catalogue, execution_refs)
    if active is not None:
        configs = {
            name: replace(config, runner=None) if name not in active else config
            for name, config in configs.items()
        }
    adapter = DetectionAdapter(profile, catalogue, configs)
    records = tuple(records)
    ids = tuple(r.item_id for r in records)
    wire = b"".join(canonical_bytes(r.model_dump(mode="json")) + b"\n" for r in records)
    (tmp_path / "hand-records.jsonl").write_bytes(wire)
    pin = PinnedReference(
        status="available", ref="hand-runtime-policy", sha256=sha(STATISTIC_VERSION.encode())
    )
    manifest = Manifest(
        manifest_id="hand-canonical-wire-only",
        parent_manifest_sha256=None,
        split_seed=None,
        partition_provenance="published_canonical",
        frozen_at="2026-10-15T00:00:00Z",
        scorer_version=STATISTIC_VERSION,
        comparator_config=pin,
        domain_adapter_ref=pin,
        experiment_refs={},
        splits=(
            SplitEntry(
                split="dev",
                items_file="hand-records.jsonl",
                item_count=2,
                ordered_item_ids=ids,
                items_sha256=sha(wire),
                ordered_ids_sha256=ordered_ids_digest(ids),
                group_ids=tuple(r.group_id for r in records),
            ),
        ),
        group_split_map={r.group_id: "dev" for r in records},
        group_members={r.group_id: (r.item_id,) for r in records},
        source_artifacts=(
            SourceArtifact(
                namespace="hand-authored-toy",
                status="available",
                sha256=sha(wire),
                count=2,
                member_ids=ids,
            ),
        ),
        publication_policy=adapter.public_projection_policy(),
        run_history_ref="toy-no-heldout-admission",
    )

    def lookup(record):
        return catalogue.source_view(record.source_ref.handle, record.input_sha256, ref)

    return SimpleNamespace(
        profile=profile,
        ref=ref,
        entries=entries,
        paths=paths,
        records=records,
        catalogue=catalogue,
        configs=configs,
        adapter=adapter,
        manifest=manifest,
        lookup=lookup,
    )


def actual_compare(t):
    return compare(t.configs, t.manifest, "dev", t.records, t.adapter, STATISTIC_VERSION, t.lookup)


def test_actual_canonical_compare_loader_fixed_axes_and_no_fake_model_predictions(tmp_path):
    t = toy(tmp_path)
    assert load_corpus(tmp_path, t.manifest, "dev", t.adapter) == t.records
    result = actual_compare(t)
    assert result.corpus_count == 2 and result.frozen_item_ids == ("toy-unit-0", "toy-unit-1")
    assert len(result.methods["rules_only"].outcomes) == 36
    assert all(row.correct is None for row in result.methods["rules_only"].outcomes)
    assert len(result.methods["rules_only"].actual_predictions) == 2
    for method in ["rules_plus_jev", "rules_plus_luna"]:
        assert result.methods[method].status == "not_run"
        assert result.methods[method].actual_predictions == result.methods[method].outcomes == ()
    rows = report_rows(result, t.adapter)
    assert len(rows) == 5 * 6 * 3 * 10
    assert len({(r.method, r.field, r.class_name, r.metric) for r in rows}) == 900
    primary = next(
        r
        for r in rows
        if (r.method, r.field, r.class_name, r.metric)
        == ("rules_only", "detection:1of2", "port_scan", "alert_recall")
    )
    assert primary.value == 1 and primary.corpus_N == primary.answered_N == 2
    proxy_na = next(
        r for r in rows if (r.method, r.class_name) == ("interval_cv_proxy", "port_scan")
    )
    assert (
        proxy_na.value is None
        and proxy_na.null_reason == "not_applicable"
        and proxy_na.eligible_N == 0
    )
    assert all(r.confusion_counts is None for r in rows)


def test_public_input_and_aggregate_never_include_private_reference_fields(tmp_path):
    t = toy(tmp_path)
    public = t.adapter.to_public_input(t.records[0], t.lookup(t.records[0]))
    encoded = canonical_bytes(public.model_dump(mode="json"))
    assert set(public.public_payload) == {"source_handle", "source_sha256", "profile_ref"}
    assert b"PRIVATE" not in encoded and b"episode" not in encoded and b"family" not in encoded
    reports = canonical_bytes(public_rows(actual_compare(t), t.adapter))
    for private in [
        b"PRIVATE",
        b"toy-source-",
        b"hand-positive-",
        b"row_id",
        b"supports",
        b"source_handle",
    ]:
        assert private not in reports


def test_changed_source_before_dispatch_retains_whole_requested_cohort_na(tmp_path):
    t = toy(tmp_path)
    t.paths[0].write_bytes(b"changed raw bytes")
    comparison = actual_compare(t)
    rows = report_rows(comparison, t.adapter)
    target = [r for r in rows if r.method == "rules_only" and r.class_name == "port_scan"]
    assert len(target) == 30 and all(r.corpus_N == 2 and r.stale_N == 1 for r in target)
    assert all(
        r.value is None and r.numerator is None and r.null_reason == "incomplete_cohort"
        for r in target
    )
    assert len(comparison.methods["rules_only"].actual_predictions) == 1


@pytest.mark.parametrize("cut_after,aborts", [(3, False), (4, True)])
def test_source_changes_during_or_after_method_not_successful_empty(tmp_path, cut_after, aborts):
    calls = [0]

    def current():
        calls[0] += 1
        return calls[0] <= cut_after

    t = toy(tmp_path, checks=(current, lambda: True), active=("rules_only",))
    if aborts:
        with pytest.raises(SourceUnavailable):
            actual_compare(t)
    else:
        result = actual_compare(t)
        assert result.methods["rules_only"].actual_predictions[0].status == "stale"
        assert all(
            r.value is None for r in report_rows(result, t.adapter) if r.method == "rules_only"
        )


def test_extra_private_public_input_key_and_changed_fixed_axis_are_rejected(tmp_path):
    t = toy(tmp_path)
    view = t.lookup(t.records[0])
    with pytest.raises(ValueError, match="closed_public"):
        t.adapter.to_public_input(
            t.records[0], replace(view, public_payload=view.public_payload | {"family": "secret"})
        )
    result = actual_compare(t)
    methods = result.methods.copy()
    methods["rules_only"] = replace(
        methods["rules_only"], outcomes=methods["rules_only"].outcomes[:-1]
    )
    with pytest.raises(ValueError, match="fixed_named_source_axes"):
        report_rows(replace(result, methods=methods), t.adapter)
    with pytest.raises(FrozenCorpusError):
        compare(
            t.configs,
            t.manifest,
            "dev",
            tuple(reversed(t.records)),
            t.adapter,
            STATISTIC_VERSION,
            t.lookup,
        )
