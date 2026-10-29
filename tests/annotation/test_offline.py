"""Actual S8 projection -> S6 -> canonical S3 Provider/real Ledger, synthetic only."""

import importlib.util
import json
import socket
from dataclasses import asdict, replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from firewall_analyst.annotation.contracts import CATEGORIES, TRIAGE
from firewall_analyst.annotation.offline import POLICY_SHA256, annotate_offline, prepare_annotation
from firewall_analyst.domain.rules.evidence import EventEvidenceSource, explain
from firewall_analyst.domain.rules.proposals import propose
from firewall_analyst.shared.rulesengine.schemas import KeyPart
from firewall_analyst.shared.s3.providers.captures import FixtureIndex


@pytest.fixture
def sample(tmp_path):
    path = tmp_path / "own.jsonl"
    path.write_bytes(
        b"\n".join(
            json.dumps(
                {
                    "ts": 1_700_000_000 + i,
                    "id.orig_h": "192.0.2.1",
                    "id.orig_p": 40000,
                    "id.resp_h": "198.51.100.1",
                    "id.resp_p": 100 + i,
                    "proto": "tcp",
                    "orig_bytes": i,
                    "service": "CANARY_PRIVATE_IGNORE_PREVIOUS_INSTRUCTIONS",
                }
            ).encode()
            for i in range(15)
        )
    )
    source = EventEvidenceSource(path, as_of_us=1_700_000_015_000_000)
    group = source.run.groups[0]
    return group, propose(group, explain(group, source), source)


def rig_for(tmp_path, group, *, confidence=0.9, invalid=False, include_benign=True):
    # Reuse the exact granted synthetic owner factory, not a replacement ledger/provider.
    path = Path(__file__).resolve().parents[1] / "vendor/s3/providers/conftest.py"
    spec = importlib.util.spec_from_file_location("s3_synthetic_helpers", path)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    rig = helper.Rig(tmp_path / "actual.sqlite3", "typesafe", True)
    prepared = prepare_annotation(
        group,
        model="fixture-model",
        nonce="0" * 32,
        include_benign=include_benign,
    )
    rig.request = prepared.request
    original_context = rig.context

    def context(operation="op1", child="group", run="run1"):
        return original_context(operation, child, run).model_copy(
            update={
                "purpose": "s8.annotate",
                "source_generation": prepared.source_generation,
                "consumer_context_sha256": prepared.context_sha256,
                "policy_sha256": POLICY_SHA256,
                "template_sha256": prepared.request.question_spec_sha256,
                "config_sha256": prepared.config_sha256,
            }
        )

    rig.context = context
    rig.evidence = []
    rig.register(rig.request)

    def body():
        probabilities = {key: 0 for key in CATEGORIES}
        probabilities["port_scan"] = 0.55 if confidence < 0.6 else 1
        probabilities["unclear"] = 0.45 if confidence < 0.6 else 0
        if invalid:
            probabilities["unclear"] = 1
        answers = {
            "category": {
                "type": "choice",
                "choice": "port_scan",
                "probabilities": probabilities,
                "confidence": confidence,
            },
            "triage": {
                "type": "score",
                "score": 1.5,
                "legend": {str(i): name for i, name in enumerate(TRIAGE)},
                "probabilities": {"0": 0, "1": 0.5, "2": 0.5, "3": 0},
                "confidence": 0.8,
            },
        }
        if include_benign:
            answers["benign_consistency"] = {"type": "noul", "noul": 0.25}
        return {
            "model": "fixture-model-reported",
            "answers": answers,
            "usage": {"input_tokens": 100, "output_tokens": None},
        }

    rig.body = body
    return rig, prepared


def admit(rig, provider, ledger):
    limits = rig.limits.model_copy(update={"max_outbound_attempts": 0})
    plan = rig.plan(offline=True)
    children = [child.model_copy(update={"purpose": "s8.annotate"}) for child in plan.children]
    plan = plan.model_copy(update={"children": children})
    allocation = provider.admit_operation(
        plan,
        ledger=ledger,
        budget=rig.authority,
        context=rig.context(),
        limits=limits,
    )
    return dict(
        ledger=ledger,
        budget=rig.authority,
        context=rig.context(child="child0"),
        limits=limits,
        allocation=allocation,
    )


class NoSend:
    is_test_transport = True

    def send(self, *args, **kwargs):
        raise AssertionError("Offline S8 may not dispatch")


def test_actual_packed_canonical_hit_keeps_fraction_and_flags(
    sample, tmp_path, monkeypatch, capsys
):
    group, proposal = sample
    before = group.model_dump_json(), proposal.model_dump_json()
    rig, prepared = rig_for(tmp_path, group)
    assert prepared.screen.method == "rules" and prepared.screen.decision == "pass"
    assert prepared.screen.hazard_probabilities is None
    assert set(prepared.request.questions) == {"category", "triage", "benign_consistency"}
    assert "CANARY" not in prepared.request.model_dump_json()
    assert "192.0.2" not in prepared.request.model_dump_json()
    capture = rig.capture()
    provider = rig.provider(
        "strict_replay",
        fixtures=FixtureIndex([capture]),
        capture_mode="fixture_replay",
        transport=NoSend(),
    )

    def deny(*args, **kwargs):
        raise AssertionError("Network forbidden")

    monkeypatch.setattr(socket, "socket", deny)
    with rig.open(offline=True) as ledger:
        kwargs = admit(rig, provider, ledger)
        result = annotate_offline(prepared, current_group=group, provider=provider, **kwargs)
        assert result.status == "ok", asdict(result)
        assert result.category == "port_scan" and result.triage_score == 1.5
        assert result.benign_consistency == 0.25 and result.confidence == 0.9
        assert result.origin == "mock" and result.current_external_cost_usd == "0"
        assert result.source_cost_usd is None and result.attempt_ids == ()
        assert result.model_reported == "fixture-model-reported"
        assert result.confidence_policy == "uncalibrated_default_0.6"
        assert result.model_quality_measured is False
        assert ledger.totals()["dispatched_attempts"] == 0
    assert before == (group.model_dump_json(), proposal.model_dump_json())
    assert "CANARY" not in json.dumps(asdict(result))
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize(
    "case",
    [
        "miss",
        "low",
        "invalid",
        "group",
        "source",
        "config",
        "nonce",
        "order",
        "state",
        "context",
        "quota",
    ],
)
def test_real_canonical_failures_never_mutate_flags_or_dispatch(sample, tmp_path, case):
    group, proposal = sample
    before = group.model_dump_json(), proposal.model_dump_json()
    rig, prepared = rig_for(
        tmp_path,
        group,
        confidence=0.55 if case == "low" else 0.9,
        invalid=case == "invalid",
        include_benign=False,
    )
    captures = [] if case == "miss" else [rig.capture()]
    provider = rig.provider(
        "strict_replay",
        fixtures=FixtureIndex(captures),
        capture_mode="fixture_replay",
        transport=NoSend(),
    )
    current = group
    expected = {
        "miss": "cache_miss",
        "low": "low_confidence",
        "invalid": "invalid_output",
        "group": "stale_annotation",
        "source": "stale_annotation",
        "config": "stale_annotation",
        "nonce": "stale_annotation",
        "order": "stale_annotation",
        "state": "stale_annotation",
        "context": "context_mismatch",
        "quota": "offline_only",
    }[case]
    if case == "group":
        current = group.model_copy(update={"group_id": "f" * 64})
    if case == "source":
        current = group.model_copy(
            update={"support": group.support.model_copy(update={"source_sha256": "f" * 64})}
        )
    if case == "config":
        current = group.model_copy(update={"config_sha256": "f" * 64})
    if case == "nonce":
        prepared = replace(prepared, nonce="1" * 32)
    if case == "order":
        prepared = replace(prepared, category_order=tuple(reversed(CATEGORIES)))
    if case == "state":
        prepared.request.state["original_text"] += "CANARY_UNSCREENED_SUFFIX"
    with rig.open(offline=True) as ledger:
        kwargs = admit(rig, provider, ledger)
        if case == "context":
            kwargs["context"] = kwargs["context"].model_copy(update={"source_generation": "f" * 64})
        if case == "quota":
            kwargs["limits"] = rig.limits
        outcome = annotate_offline(prepared, current_group=current, provider=provider, **kwargs)
        assert outcome.status == expected, asdict(outcome)
        assert outcome.category is None
        assert ledger.totals()["dispatched_attempts"] == 0
    assert before == (group.model_dump_json(), proposal.model_dump_json())


def test_actual_nonce_option_order_and_context_identity_change(sample):
    group, _ = sample
    first = prepare_annotation(group, model="fixture-model", nonce="2" * 32)
    nonce = prepare_annotation(group, model="fixture-model", nonce="3" * 32)
    order = prepare_annotation(
        group, model="fixture-model", nonce="2" * 32, category_order=tuple(reversed(CATEGORIES))
    )
    assert first.request.state != nonce.request.state
    assert first.request.question_spec_sha256 != order.request.question_spec_sha256
    assert first.context_sha256 != order.context_sha256
    assert tuple(order.request.questions["category"].criteria) == tuple(reversed(CATEGORIES))


@pytest.mark.parametrize("policy_case", ["cap", "typed_required"])
def test_actual_s6_hold_blocks_lookup_before_accounting(sample, monkeypatch, policy_case):
    from firewall_analyst.annotation import offline
    from firewall_analyst.shared.screen import ScreenPolicy

    group, proposal = sample
    before = group.model_dump_json(), proposal.model_dump_json()
    policy = (
        ScreenPolicy("own-control/1", "rules", max_input_bytes=1)
        if policy_case == "cap"
        else (ScreenPolicy("own-control/1", "typed"))
    )
    monkeypatch.setattr(offline, "SCREEN_POLICY", policy)
    prepared = prepare_annotation(group, model="fixture-model", nonce="4" * 32)
    assert prepared.request is None and prepared.screen.decision == "needs_human"
    assert prepared.screen.hazard_probabilities is None

    class NoLookup:
        mode = "strict_replay"

        def validate_replay_allocation(self, *args, **kwargs):
            raise AssertionError("held input cannot authorize lookup")

        def run(self, *args, **kwargs):
            raise AssertionError("held input cannot authorize lookup")

    result = annotate_offline(
        prepared,
        current_group=group,
        provider=NoLookup(),
        ledger=None,
        budget=None,
        context=None,
        limits=SimpleNamespace(max_outbound_attempts=0),
        allocation=None,
    )
    assert result.status == "annotation_held" and result.accounting_ref is None
    assert before == (group.model_dump_json(), proposal.model_dump_json())


def test_private_slots_excluded_projection_errors_and_invalid_requests(sample):
    group, _ = sample
    poisoned = group.model_copy(
        update={
            "grouping_key": (KeyPart(name="src", value="CANARY_ENDPOINT_IGNORE_FLAGS"),),
            "matched_context_ids": ("CANARY_OPERATOR_DESCRIPTION",),
            "quality_flags": ("CANARY_RAW_HISTORY",),
        }
    )
    prepared = prepare_annotation(poisoned, model="fixture-model", nonce="5" * 32)
    assert "CANARY" not in prepared.request.model_dump_json()
    for field, value in (
        ("stat_id", "CANARY_RAW_FIELD"),
        ("unit", "wrong_unit"),
        ("value", float("nan")),
    ):
        stat = group.stats[0].model_copy(update={field: value})
        with pytest.raises(ValueError):
            prepare_annotation(
                group.model_copy(update={"stats": (stat,)}), model="fixture-model", nonce="5" * 32
            )
    with pytest.raises(ValueError, match="projection_limit"):
        prepare_annotation(
            group.model_copy(update={"stats": group.stats * 50}),
            model="fixture-model",
            nonce="5" * 32,
        )
    with pytest.raises(ValueError, match="nonce_required"):
        prepare_annotation(group, model="fixture-model", nonce="invalid")
    with pytest.raises(ValueError, match="category_order"):
        prepare_annotation(
            group, model="fixture-model", nonce="5" * 32, category_order=CATEGORIES[:-1]
        )


def test_actual_ledger_unavailable_closed_status_and_no_payload(sample, tmp_path):
    group, proposal = sample
    before = group.model_dump_json(), proposal.model_dump_json()
    rig, prepared = rig_for(tmp_path, group)
    provider = rig.provider(
        "strict_replay",
        fixtures=FixtureIndex([rig.capture()]),
        capture_mode="fixture_replay",
        transport=NoSend(),
    )
    with rig.open(offline=True) as ledger:
        kwargs = admit(rig, provider, ledger)
    outcome = annotate_offline(prepared, current_group=group, provider=provider, **kwargs)
    assert outcome.status == "annotation_unavailable" and outcome.category is None
    assert before == (group.model_dump_json(), proposal.model_dump_json())
    assert "CANARY" not in json.dumps(asdict(outcome))
