"""Real local method/currentness controls, no SDK/provider or corpus execution."""

import builtins
from dataclasses import replace

import pytest
from test_canonical_adapter import toy

from firewall_analyst.domain.evaluation.adapter import STATISTIC_VERSION, DetectionAdapter
from firewall_analyst.domain.evaluation.methods import (
    LocalMethodRunner,
    RegisteredSource,
    TrustedSourceCatalogue,
)
from firewall_analyst.shared.evalkit.corpus import FrozenCorpusError
from firewall_analyst.shared.evalkit.models import Prediction
from firewall_analyst.shared.evalkit.runner import compare


def test_actual_canonical_prediction_type_pinned_configuration_and_zero_model_state(tmp_path):
    t = toy(tmp_path)
    public = t.adapter.to_public_input(t.records[0], t.lookup(t.records[0]))
    runner = t.configs["rules_only"].runner
    prediction = runner.predict(public)
    assert type(prediction) is Prediction and prediction.status == "ok"
    assert prediction.config_sha256 == t.configs["rules_only"].config_sha256
    assert prediction.domain_payload["run_config_sha256"] != prediction.config_sha256
    assert (
        prediction.model is None
        and prediction.ledger_refs == ()
        and prediction.origin == "synthetic"
    )
    assert len(prediction.domain_payload["channels"]) == 7
    literal = next(
        c for c in prediction.domain_payload["channels"] if c["rule_id"] == "denied_then_allowed"
    )
    assert literal["status"] == "unsupported"
    assert t.configs["rules_plus_jev"].runner is t.configs["rules_plus_luna"].runner is None


def test_sdk_imports_blocked_while_real_local_prediction_still_executes(tmp_path, monkeypatch):
    t = toy(tmp_path)
    public = t.adapter.to_public_input(t.records[0], t.lookup(t.records[0]))
    original = builtins.__import__

    def guard(name, *args, **kwargs):
        if name.split(".")[0] in {"openai", "typesafe", "requests", "httpx"}:
            raise AssertionError("provider/network module forbidden in local method")
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guard)
    with pytest.raises(AssertionError):
        __import__("openai")
    assert t.configs["rules_only"].runner.predict(public).status == "ok"
    assert t.configs["interval_cv_proxy"].runner.predict(public).status == "ok"


@pytest.mark.parametrize(
    "change", [{"method": "wrong"}, {"config_sha256": "b" * 64}, {"origin": "live"}]
)
def test_actual_canonical_compare_rejects_wrong_identity_or_origin(tmp_path, change):
    t = toy(tmp_path)
    original = t.configs["rules_only"].runner

    class WrongRunner:
        def predict(self, public):
            return original.predict(public).model_copy(update=change)

    configs = t.configs | {"rules_only": replace(t.configs["rules_only"], runner=WrongRunner())}
    with pytest.raises(FrozenCorpusError, match="prediction_"):
        compare(configs, t.manifest, "dev", t.records, t.adapter, STATISTIC_VERSION, t.lookup)


def test_local_runner_exception_is_explicit_failure_full_cohort_not_zero_detection(tmp_path):
    t = toy(tmp_path)

    class FailingRunner:
        def predict(self, public):
            raise RuntimeError("hand-authored-private-error")

    configs = t.configs | {"rules_only": replace(t.configs["rules_only"], runner=FailingRunner())}
    adapter = DetectionAdapter(t.profile, t.catalogue, configs)
    result = compare(configs, t.manifest, "dev", t.records, adapter, STATISTIC_VERSION, t.lookup)
    assert result.methods["rules_only"].requested_item_ids == ("toy-unit-0", "toy-unit-1")
    assert all(
        r.status == "provider_error" and r.predicted is None and r.correct is None
        for r in result.methods["rules_only"].outcomes
    )
    from firewall_analyst.domain.evaluation.metrics import report_rows

    rows = [r for r in report_rows(result, adapter) if r.method == "rules_only"]
    assert all(
        r.value is None and r.error_N == 2 and r.null_reason == "incomplete_cohort" for r in rows
    )


@pytest.mark.parametrize(
    "handle", ["C:\\unregistered.jsonl", "../unregistered", "https://example.com/raw"]
)
def test_public_wire_accepts_no_path_or_url_authority(tmp_path, handle):
    t = toy(tmp_path)
    public = t.adapter.to_public_input(t.records[0], t.lookup(t.records[0]))
    bad = public.model_copy(
        update={"public_payload": public.public_payload | {"source_handle": handle}}
    )
    with pytest.raises(ValueError, match="closed_public"):
        t.configs["rules_only"].runner.predict(bad)


def test_registered_unavailable_and_stale_currentness_are_distinct(tmp_path):
    t = toy(tmp_path)
    assert (
        t.catalogue.source_view("missing", t.records[0].input_sha256, t.ref).status == "unavailable"
    )
    assert t.catalogue.source_view("toy-source-0", "b" * 64, t.ref).status == "stale"

    def broken():
        raise OSError("private-details")

    entry = replace(t.entries[0], check_current=broken)
    catalogue = TrustedSourceCatalogue((entry,))
    view = catalogue.source_view(entry.handle, entry.input_sha256, t.ref)
    assert view.status == "unavailable" and view.public_payload == {}


def test_incomplete_execution_reference_descriptor_and_duplicate_registration_refused(tmp_path):
    t = toy(tmp_path)
    with pytest.raises(ValueError, match="pinned_local"):
        LocalMethodRunner("rules_only", t.profile, t.catalogue, {"one-incomplete-ref": "a" * 64})
    with pytest.raises(ValueError, match="registration"):
        TrustedSourceCatalogue((t.entries[0], t.entries[0]))
    with pytest.raises(ValueError, match="registration"):
        TrustedSourceCatalogue(
            (
                RegisteredSource(
                    "../path", t.entries[0].input_sha256, t.entries[0].parsed, lambda: True
                ),
            )
        )


def test_real_incomplete_rule_channel_becomes_explicit_invalid_prediction(tmp_path):
    t = toy(tmp_path, destination="198.51.100.2")
    public = t.adapter.to_public_input(t.records[0], t.lookup(t.records[0]))
    prediction = t.configs["rules_only"].runner.predict(public)
    assert prediction.status == "invalid" and prediction.domain_payload is None
    assert prediction.issues == ("incomplete_or_invalid_local_source",)
