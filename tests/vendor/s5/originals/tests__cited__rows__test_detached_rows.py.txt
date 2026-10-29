"""what_bug_this_catches: optional row exports need owner app, source IO or cloned DTOs."""

import json
import shutil
import subprocess
import sys
from pathlib import Path


def test_actual_detached_row_closure_no_owner_source_or_network(tmp_path):
    root = Path(__file__).resolve().parents[3]
    package = tmp_path / "neutral_rows"
    package.mkdir()
    source = root / "src/changelog_advisor/shared/cited"
    for name in (
        "__init__.py",
        "models.py",
        "registry.py",
        "schema.py",
        "memory.py",
        "assessment.py",
        "rowcanonical.py",
        "rows.py",
        "rowproducers.py",
        "production.py",
    ):
        shutil.copyfile(source / name, package / name)
    shutil.copyfile(root / "LICENSE", tmp_path / "LICENSE")
    script = r"""
import sys, json, socket, subprocess, builtins, os
from pathlib import Path
from pydantic import BaseModel


class DependencyProbe(BaseModel):
    value: int


assert DependencyProbe(value=1).value == 1
owner = Path(sys.argv[2]).resolve()
sys.path = [p for p in sys.path if Path(p).resolve() not in (owner, owner / "src")]
sys.path.insert(0, sys.argv[1])
original_import = builtins.__import__


def guarded(name, *args, **kwargs):
    if name.startswith(
        (
            "changelog_advisor",
            "firewall_traffic_analyst",
            "content_strategy_agent",
            "openai",
            "typesafe",
        )
    ):
        raise AssertionError("owner or SDK import")
    return original_import(name, *args, **kwargs)


builtins.__import__ = guarded


def denied(*a, **kw):
    raise AssertionError("ungranted network/process/source IO")


socket.create_connection = denied
socket.socket.connect = denied
subprocess.Popen = denied
from neutral_rows import ArtifactRef, Registry, ResolutionContext, Finding
from neutral_rows.models import MetricSupport, MetricArtifact, PlatformSummary, SnapshotIdentity
from neutral_rows.rowcanonical import metric_bytes, digest
from neutral_rows.production import RequiredEvidenceFrame, assess_produced_evidence
from neutral_rows.rows import RowResolver, install_rows
from neutral_rows.rowproducers import produce_metric_rows
from neutral_rows.schema import encoded_schemas, encoded_row_schemas

Path.read_bytes = denied
Path.read_text = denied
builtins.open = denied
access = ArtifactRef(artifact_id="access", artifact_sha256="a" * 64, profile_id="access/1")
gen = ArtifactRef(artifact_id="generation", artifact_sha256="b" * 64, profile_id="generation/1")
required = ArtifactRef(artifact_id="required", artifact_sha256="c" * 64, profile_id="required/1")
identity = SnapshotIdentity(
    dataset_fingerprint="d" * 64, tag_provenance=(), config_json="{}", compute_version="metrics.v1"
)
sid = digest(metric_bytes(identity.model_dump(mode="json")))
row = MetricSupport(
    metric_id="metric",
    snapshot_id=sid,
    scope="x",
    definition="Literal supplied metric",
    value="0.5",
    unit="ratio",
    sample_size=5,
    excluded_size=0,
    computed_by="metrics.v1",
    status="ok",
    status_reason=None,
    n=5,
    N=5,
    cohort_semantics="rate_cohort",
    numerator="5",
    denominator="10",
    family="rate",
    dimension="topic",
    key="test",
    eligible_source_ids=tuple("p" + str(i) for i in range(5)),
    excluded_source_ids=(),
    windows=(),
)
summary = PlatformSummary(
    platform="x",
    rows=5,
    positive_impression_rows=5,
    missing_time_rows=0,
    eligible_hour_rows=5,
    missing_topic_rows=0,
    missing_format_rows=0,
)
artifact = MetricArtifact(
    algorithm="s9-metric-evidence.v1",
    namespace_id="namespace",
    dataset_id="s9-dataset-" + "1" * 32,
    dataset_fingerprint="d" * 64,
    snapshot_id=sid,
    snapshot_identity=identity,
    rows=(row,),
    platform_summary=(summary,),
)
frame = RequiredEvidenceFrame(
    request_id="request",
    namespace_id="namespace",
    authority_ref=required,
    required_reference_ids=("ref",),
)
batch = produce_metric_rows(artifact, frame, ("metric",), raw_identity_byte_length=1234)


class Backend:
    access_policy_ref = access
    generation_policy_ref = gen

    def decision(self, *a):
        return "allow"

    def current(self, *a):
        return batch.retained.generation

    def allow_historical(self, *a):
        return False

    def retained(self, *a):
        return batch.retained


class Authority:
    reference = required

    def original(self, *a):
        return frame


registry = Registry()
install_rows(registry, RowResolver(Backend()))
context = ResolutionContext(
    namespace_id="namespace",
    access_policy_ref=access,
    generation_policy_ref=gen,
    required_scope="text",
)
finding = Finding(
    id="f",
    text="Unconfirmed conditional observation",
    verdict="partial",
    evidence=(batch.outcomes[0].pointer,),
)
result = assess_produced_evidence(
    finding, batch.outcomes, registry, context, frame, authority=Authority()
)
assert result.required_count == result.resolved_count == 1 and result.finding.verdict == "partial"
assert len(encoded_schemas()) == len(encoded_row_schemas()) == 5
assert result.resolutions[0].excerpt_sha256 == batch.outcomes[0].pointer.locator.row_sha256
assert not any(
    n.startswith(("changelog_advisor", "firewall_traffic_analyst", "content_strategy_agent"))
    for n in sys.modules
)
print(
    json.dumps(
        dict(resolved=1, semantic="partial", owner_imports=0, network=0, source_IO=0, schema_sets=2)
    )
)
"""
    result = subprocess.run(
        [sys.executable, "-I", "-c", script, str(tmp_path), str(root)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == dict(
        resolved=1, semantic="partial", owner_imports=0, network=0, source_IO=0, schema_sets=2
    )
