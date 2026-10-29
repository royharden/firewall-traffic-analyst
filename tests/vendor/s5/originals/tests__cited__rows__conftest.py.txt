"""Synthetic structural controls, separate from all independent author data."""

import socket
from types import SimpleNamespace

import pytest

from changelog_advisor.shared.cited import ArtifactRef, Registry, ResolutionContext
from changelog_advisor.shared.cited.models import (
    MetricArtifact,
    MetricSupport,
    PlatformSummary,
    SnapshotIdentity,
)
from changelog_advisor.shared.cited.production import RequiredEvidenceFrame
from changelog_advisor.shared.cited.rowcanonical import digest, metric_bytes
from changelog_advisor.shared.cited.rowproducers import produce_metric_rows
from changelog_advisor.shared.cited.rows import RowResolver, install_rows


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def forbidden(*a, **k):
        raise AssertionError("row controls attempted network")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)


@pytest.fixture
def factory():
    access = ArtifactRef(artifact_id="access", artifact_sha256="a" * 64, profile_id="access/1")
    generation = ArtifactRef(
        artifact_id="generation", artifact_sha256="b" * 64, profile_id="generation/1"
    )
    required_ref = ArtifactRef(
        artifact_id="required", artifact_sha256="c" * 64, profile_id="required/1"
    )
    config = {
        "edition": "metric-config.v1",
        "input_contract": "csv.v2-bounded-counts",
        "clock": "posted-local",
        "minimum_n": 5,
        "trend_weeks": 4,
        "decimal_precision": 28,
        "canonical_places": 8,
        "rounding": "ROUND_HALF_EVEN",
        "length_measure": "NFC_unicode_code_points",
        "length_edges": {
            "x": [0, 70, 140, 210],
            "linkedin": [0, 140, 500, 1500],
            "other": [0, 140, 500, 1500],
        },
    }
    identity = SnapshotIdentity(
        dataset_fingerprint="d" * 64,
        tag_provenance=(),
        config_json=metric_bytes(config).decode(),
        compute_version="metrics.v1",
    )
    snapshot = digest(metric_bytes(identity.model_dump(mode="json")))

    def row(**updates):
        data = dict(
            schema_version=1,
            metric_id="rate:x:topic:testing",
            snapshot_id=snapshot,
            scope="x",
            definition="Exact rate over supplied positive-impression source cohort",
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
            key="testing",
            eligible_source_ids=tuple(f"post-{i}" for i in range(5)),
            excluded_source_ids=(),
            windows=(),
        )
        data.update(updates)
        return MetricSupport.model_validate(data)

    def artifact(rows=None, **updates):
        data = dict(
            algorithm="s9-metric-evidence.v1",
            namespace_id="namespace",
            dataset_id="s9-dataset-" + "1" * 32,
            dataset_fingerprint=identity.dataset_fingerprint,
            snapshot_id=snapshot,
            snapshot_identity=identity,
            rows=tuple(rows) if rows is not None else (row(),),
            platform_summary=(
                PlatformSummary(
                    platform="x",
                    rows=5000,
                    positive_impression_rows=5000,
                    missing_time_rows=0,
                    eligible_hour_rows=5000,
                    missing_topic_rows=0,
                    missing_format_rows=0,
                ),
            ),
        )
        data.update(updates)
        return MetricArtifact.model_validate(data)

    def frame(ids=("ref-1",)):
        return RequiredEvidenceFrame(
            request_id="request-1",
            namespace_id="namespace",
            authority_ref=required_ref,
            required_reference_ids=ids,
        )

    context = ResolutionContext(
        namespace_id="namespace",
        access_policy_ref=access,
        generation_policy_ref=generation,
        required_scope="text",
    )

    class Backend:
        access_policy_ref = access
        generation_policy_ref = generation

        def __init__(self, retained):
            self.saved = retained
            self.current_value = retained.generation
            self.decisions = ["allow"]
            self.decision_count = 0
            self.retained_count = 0
            self.historical = False

        def decision(self, *args):
            result = self.decisions[min(self.decision_count, len(self.decisions) - 1)]
            self.decision_count += 1
            return result

        def current(self, *args):
            return self.current_value

        def allow_historical(self, *args):
            return self.historical

        def retained(self, *args):
            self.retained_count += 1
            return self.saved

    class Authority:
        reference = required_ref

        def __init__(self, value):
            self.value = value

        def original(self, *args):
            return self.value

    def installed(batch, **kw):
        backend = Backend(batch.retained)
        registry = Registry()
        install_rows(registry, RowResolver(backend, **kw))
        return registry, backend

    def batch(**updates):
        obj = artifact(**updates)
        return produce_metric_rows(
            obj,
            frame(tuple("ref-" + str(i + 1) for i in range(len(obj.rows)))),
            tuple(r.metric_id for r in obj.rows),
            raw_identity_byte_length=1234,
        )

    return SimpleNamespace(
        row=row,
        artifact=artifact,
        frame=frame,
        context=context,
        identity=identity,
        snapshot=snapshot,
        config=config,
        access=access,
        generation=generation,
        required_ref=required_ref,
        Backend=Backend,
        Authority=Authority,
        installed=installed,
        batch=batch,
    )
