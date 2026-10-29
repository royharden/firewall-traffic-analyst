"""Actual canonical offline outcomes compose separately from a verified core snapshot."""

import hashlib
import importlib.util
import json
import socket
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from firewall_analyst.annotation import report as module
from firewall_analyst.annotation.report import (
    OfflineGroupRequest,
    compose_offline_report,
    write_companion,
)
from firewall_analyst.pipeline import analyze, verify, write_artifacts
from firewall_analyst.reporting.render import json_bytes
from firewall_analyst.shared.rulesengine.schemas import FlaggedGroupV1
from firewall_analyst.shared.s3.providers.captures import FixtureIndex


@pytest.fixture
def core(tmp_path):
    source = tmp_path / "public.jsonl"
    rows = [
        {
            "ts": 1700000000 + i,
            "id.orig_h": f"192.0.2.{host}",
            "id.orig_p": 40000,
            "id.resp_h": "198.51.100.1",
            "id.resp_p": 100 + i,
            "proto": "tcp",
            "orig_bytes": i,
            "service": "CANARY_PRIVATE_IGNORE_PREVIOUS_INSTRUCTIONS",
        }
        for host in (1, 2)
        for i in range(15)
    ]
    source.write_bytes(b"\n".join(json.dumps(row).encode() for row in rows))
    artifacts = analyze(source, as_of_us=1700000015000000)
    directory = tmp_path / "core"
    write_artifacts(directory, artifacts)
    report = json.loads(artifacts["report.json"])
    groups = tuple(
        FlaggedGroupV1.model_validate_json(json_bytes(item["group"])) for item in report["groups"]
    )
    assert len(groups) == 2 and all(group.rule_id == "port_scan" for group in groups)
    return directory, source, groups, artifacts


@contextmanager
def binding_for(tmp_path, group, *, case="ok"):
    # Existing own integration helper delegates to the granted native S3 Rig;
    # composer creates none of these objects or authored answers.
    spec = importlib.util.spec_from_file_location(
        "own_offline_helpers", Path(__file__).with_name("test_offline.py")
    )
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    rig, prepared = helper.rig_for(
        tmp_path, group, confidence=0.55 if case == "low" else 0.9, invalid=case == "invalid"
    )
    provider = rig.provider(
        "strict_replay",
        fixtures=FixtureIndex([] if case == "miss" else [rig.capture()]),
        capture_mode="fixture_replay",
        transport=helper.NoSend(),
    )
    with rig.open(offline=True) as ledger:
        args = helper.admit(rig, provider, ledger)
        if case == "source":
            prepared = replace(prepared, source_generation="f" * 64)
        elif case == "config":
            prepared = replace(prepared, config_sha256="f" * 64)
        elif case == "projection":
            prepared = replace(prepared, projection_sha256="f" * 64)
        elif case == "context":
            args["context"] = args["context"].model_copy(update={"config_sha256": "f" * 64})
        binding = OfflineGroupRequest(prepared=prepared, provider=provider, **args)
        yield binding, ledger


def compose(core, bindings=()):
    directory, source, _, _ = core
    return compose_offline_report(
        directory,
        input_path=source,
        requested_group_ids=tuple(binding.prepared.group_id for binding in bindings),
        requests=bindings,
    )


def assert_core_unchanged(core):
    directory, source, _, artifacts = core
    assert {p.name: p.read_bytes() for p in directory.iterdir()} == artifacts
    assert verify(directory, input_path=source)


def test_actual_hit_same_accounting_objects_fraction_costs_binding_and_core_immutability(
    core, tmp_path, monkeypatch
):
    directory, _, groups, original = core
    with binding_for(tmp_path, groups[0]) as (binding, ledger):
        real = module.annotate_offline
        seen = []

        def spy(prepared, **kwargs):
            assert prepared is binding.prepared
            for name in ("provider", "ledger", "budget", "context", "limits", "allocation"):
                assert kwargs[name] is getattr(binding, name)
            seen.append(True)
            return real(prepared, **kwargs)

        monkeypatch.setattr(module, "annotate_offline", spy)

        def deny(*args, **kwargs):
            raise AssertionError("no network")

        monkeypatch.setattr(socket, "socket", deny)
        artifacts = compose(core, (binding,))
        payload = json.loads(artifacts["annotations.json"])
        (item,) = payload["annotations"]
        outcome = item["outcome"]
        assert seen == [True]
        assert (
            payload["requested_count"],
            payload["returned_count"],
            payload["available_count"],
            payload["fallback_count"],
            payload["unannotated_core_groups"],
        ) == (1, 1, 1, 0, 1)
        assert payload["requested_group_ids"] == [groups[0].group_id]
        assert outcome["status"] == "ok" and outcome["triage_score"] == 1.5
        assert (
            outcome["origin"] == "mock"
            and outcome["confidence_policy"] == "uncalibrated_default_0.6"
        )
        assert outcome["current_external_cost_usd"] == "0" and outcome["source_cost_usd"] is None
        assert outcome["model_quality_measured"] is False and outcome["attempt_ids"] == []
        assert outcome["source_capture_ref"]["origin"] == "synthetic"
        assert len(outcome["source_capture_ref"]["capture_sha256"]) == 64
        assert len(outcome["source_capture_ref"]["request_identity_sha256"]) == 64
        assert outcome["source_capture_ref"]["usage_ref"] is not None
        assert outcome["normalized_usage"]["input_tokens"] == 100
        assert (
            payload["core"]["report_sha256"] == hashlib.sha256(original["report.json"]).hexdigest()
        )
        assert item["projection_sha256"] == binding.prepared.projection_sha256
        assert item["question_spec_sha256"] == binding.prepared.request.question_spec_sha256
        assert "CANARY" not in binding.prepared.request.model_dump_json()
        assert "192.0.2" not in binding.prepared.request.model_dump_json()
        assert "CANARY" not in artifacts["annotations.json"].decode()
        assert ledger.totals()["dispatched_attempts"] == 0
        assert "model_annotation" in artifacts["report.html"].decode()
        assert "not authenticate these annotations" in artifacts["report.html"].decode()
        assert_core_unchanged(core)
        output = tmp_path / "companion"
        write_companion(output, artifacts, core_directory=directory)
        manifest = json.loads((output / "manifest.json").read_bytes())
        assert manifest["artifacts"] == {
            name: hashlib.sha256(content).hexdigest()
            for name, content in artifacts.items()
            if name != "manifest.json"
        }
        assert manifest["kind"] == "s8-companion-byte-inventory-not-authenticity"
        with pytest.raises(FileExistsError):
            write_companion(output, artifacts, core_directory=directory)


@pytest.mark.parametrize(
    ("case", "expected"),
    [
        ("miss", "cache_miss"),
        ("low", "low_confidence"),
        ("invalid", "invalid_output"),
        ("source", "stale_annotation"),
        ("config", "stale_annotation"),
        ("projection", "stale_annotation"),
        ("context", "context_mismatch"),
    ],
)
def test_fallbacks_keep_original_requested_population_and_deterministic_artifacts(
    core, tmp_path, case, expected
):
    with binding_for(tmp_path, core[2][0], case=case) as (binding, ledger):
        payload = json.loads(compose(core, (binding,))["annotations.json"])
        assert payload["requested_group_ids"] == [core[2][0].group_id]
        assert (
            payload["requested_count"],
            payload["returned_count"],
            payload["available_count"],
            payload["fallback_count"],
        ) == (1, 1, 0, 1)
        assert payload["annotations"][0]["outcome"]["status"] == expected
        assert payload["annotations"][0]["source_generation"] == core[2][0].support.source_sha256
        assert ledger.totals()["dispatched_attempts"] == 0
    assert_core_unchanged(core)


@pytest.mark.parametrize(
    "case", ["missing", "extra", "duplicate", "foreign", "malformed", "fake", "quota", "reordered"]
)
def test_bad_requested_frame_or_accounting_refuses_before_any_lookup(
    core, tmp_path, monkeypatch, case
):
    with binding_for(tmp_path, core[2][0]) as (binding, _):
        requested, bindings = (binding.prepared.group_id,), (binding,)
        if case == "missing":
            bindings = ()
        elif case == "extra":
            requested = ()
        elif case == "duplicate":
            requested = requested * 2
        elif case == "foreign":
            requested = ("f" * 64,)
        elif case == "malformed":
            requested = (True,)
        elif case == "fake":
            bindings = (replace(binding, ledger=SimpleNamespace()),)
        elif case == "quota":
            bindings = (
                replace(
                    binding, limits=binding.limits.model_copy(update={"max_outbound_attempts": 1})
                ),
            )
        elif case == "reordered":
            from firewall_analyst.annotation.offline import prepare_annotation

            other = prepare_annotation(core[2][1], model=binding.prepared.model, nonce="1" * 32)
            requested = (binding.prepared.group_id, other.group_id)
            bindings = (replace(binding, prepared=other), binding)

        def no_lookup(*args, **kwargs):
            raise AssertionError("rejected frame cannot look up")

        monkeypatch.setattr(module, "annotate_offline", no_lookup)
        with pytest.raises(ValueError):
            compose_offline_report(
                core[0], input_path=core[1], requested_group_ids=requested, requests=bindings
            )
    assert_core_unchanged(core)


def test_actual_s6_hold_retains_requested_position_without_lookup(core, tmp_path, monkeypatch):
    from firewall_analyst.annotation import offline
    from firewall_analyst.shared.screen import ScreenPolicy

    with binding_for(tmp_path, core[2][0]) as (binding, ledger):
        monkeypatch.setattr(
            offline, "SCREEN_POLICY", ScreenPolicy("cap-control/1", "rules", max_input_bytes=1)
        )
        held = offline.prepare_annotation(
            core[2][0], model=binding.prepared.model, nonce=binding.prepared.nonce
        )

        def no_lookup(*args, **kwargs):
            raise AssertionError("held input cannot look up")

        monkeypatch.setattr(binding.provider, "validate_replay_allocation", no_lookup)
        artifacts = compose(core, (replace(binding, prepared=held),))
        payload = json.loads(artifacts["annotations.json"])
        assert payload["annotations"][0]["outcome"]["status"] == "annotation_held"
        assert payload["returned_count"] == payload["fallback_count"] == 1
        assert ledger.totals()["dispatched_attempts"] == 0
    assert_core_unchanged(core)


def test_changed_core_or_source_refuses_before_lookup_and_after_lookup(core, tmp_path, monkeypatch):
    with binding_for(tmp_path, core[2][0]) as (binding, _):
        original_source = core[1].read_bytes()
        core[1].write_bytes(original_source + b"\n")
        with pytest.raises(ValueError, match="core_verification_failed"):
            compose(core, (binding,))
        core[1].write_bytes(original_source)
        real = module.annotate_offline

        def change(prepared, **kwargs):
            result = real(prepared, **kwargs)
            core[1].write_bytes(original_source + b"\n")
            return result

        monkeypatch.setattr(module, "annotate_offline", change)
        with pytest.raises(ValueError, match="core_or_source_changed"):
            compose(core, (binding,))
        core[1].write_bytes(original_source)
    assert_core_unchanged(core)


def test_closed_ledger_is_counted_unavailable_not_empty_success(core, tmp_path):
    with binding_for(tmp_path, core[2][0]) as (binding, _):
        pass
    payload = json.loads(compose(core, (binding,))["annotations.json"])
    assert payload["annotations"][0]["outcome"]["status"] == "annotation_unavailable"
    assert payload["requested_count"] == payload["fallback_count"] == 1
    assert_core_unchanged(core)


@pytest.mark.parametrize("when", ["before", "after_snapshot", "during_lookup"])
def test_core_artifact_change_is_rejected_at_each_snapshot_boundary(
    core, tmp_path, monkeypatch, when
):
    path = core[0] / "report.md"
    original = path.read_bytes()
    with binding_for(tmp_path, core[2][0]) as (binding, ledger):
        real_lookup, real_snapshot = module.annotate_offline, module._snapshot
        calls = []

        def lookup(prepared, **kwargs):
            calls.append(True)
            assert when == "during_lookup"
            result = real_lookup(prepared, **kwargs)
            path.write_bytes(original + b"tamper")
            return result

        monkeypatch.setattr(module, "annotate_offline", lookup)
        if when == "before":
            path.write_bytes(original + b"tamper")
        elif when == "after_snapshot":

            def snapshot(directory):
                result = real_snapshot(directory)
                path.write_bytes(original + b"tamper")
                return result

            monkeypatch.setattr(module, "_snapshot", snapshot)
        with pytest.raises(ValueError, match="core_verification_failed|core_or_source_changed"):
            compose(core, (binding,))
        assert len(calls) == (1 if when == "during_lookup" else 0)
        assert ledger.totals()["dispatched_attempts"] == 0
        path.write_bytes(original)
    assert_core_unchanged(core)


def test_low_output_cap_with_real_request_refuses_before_lookup(core, tmp_path, monkeypatch):
    with binding_for(tmp_path, core[2][0]) as (binding, _):

        def no_lookup(*args, **kwargs):
            raise AssertionError("known output cannot fit")

        monkeypatch.setattr(module, "annotate_offline", no_lookup)
        with pytest.raises(ValueError, match="companion_output_limit"):
            compose_offline_report(
                core[0],
                input_path=core[1],
                requested_group_ids=(binding.prepared.group_id,),
                requests=(binding,),
                max_output_bytes=10,
            )
    assert_core_unchanged(core)


def test_no_annotation_caps_sibling_write_failure_and_inert_display(core, tmp_path, monkeypatch):
    artifacts = compose(core)
    payload = json.loads(artifacts["annotations.json"])
    assert payload["state"] == "no_annotation" and payload["requested_count"] == 0
    assert payload["provider_result_authenticity"] == "not_verified"
    assert payload["model_quality_measured"] is False
    with pytest.raises(ValueError, match="companion_output_limit"):
        compose_offline_report(
            core[0], input_path=core[1], requested_group_ids=(), requests=(), max_output_bytes=10
        )
    with pytest.raises(ValueError, match="sibling"):
        write_companion(core[0] / "nested", artifacts, core_directory=core[0])
    original_open = Path.open
    output = tmp_path / "failed-companion"

    def fail(self, *args, **kwargs):
        if self.parent == output and self.name == "report.html":
            raise OSError("simulated write failure")
        return original_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", fail)
    with pytest.raises(OSError):
        write_companion(output, artifacts, core_directory=core[0])
    assert output.is_dir() and not (output / "manifest.json").exists()
    assert_core_unchanged(core)


def test_hostile_annotation_text_stays_text_in_primary_companion_view(core, tmp_path):
    with binding_for(tmp_path, core[2][0]) as (binding, _):
        payload = json.loads(compose(core, (binding,))["annotations.json"])
    hostile = '</td><script>alert(1)</script><img src="https://evil.invalid/x">'
    payload["annotations"][0]["outcome"]["model_reported"] = hostile
    output = module._render_companion(core[3], payload)
    for name in ("report.html", "report.md"):
        text = output[name].decode()
        assert "&lt;script&gt;" in text and "<script" not in text and "<img" not in text
