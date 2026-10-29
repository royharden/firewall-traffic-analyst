"""what_bug_this_catches: exported source schema accepts metadata runtime already rejects."""

import itertools

import pytest
from pydantic import ValidationError

from firewall_analyst.shared.cited.models import SourceArtifact, WireModel

ABSENT = object()
BASE = {
    "source_id": "synthetic-source",
    "source_type": "supplied_text",
    "source_sha256": "a" * 64,
    "source_revision": "synthetic-1",
    "evidence_artifact_sha256": "b" * 64,
    "raw_byte_length": 0,
}


def pair_cases():
    """Independent relation oracle; absent wire fields have existing null/empty defaults."""
    for digest, policy, mapping in itertools.product(
        (ABSENT, None, "c" * 64),
        (ABSENT, None, "identity", "crlf-to-lf"),
        (ABSENT, [], [{"source_line": 1, "canonical_line": 1}]),
    ):
        data = dict(BASE)
        for name, value in (
            ("canonical_text_sha256", digest),
            ("newline_policy", policy),
            ("line_map", mapping),
        ):
            if value is not ABSENT:
                data[name] = value
        has_digest = digest is not ABSENT and digest is not None
        has_policy = policy is not ABSENT and policy is not None
        nonempty_map = mapping is not ABSENT and bool(mapping)
        yield data, has_digest == has_policy and (not nonempty_map or has_digest)


@pytest.mark.parametrize(("data", "expected"), tuple(pair_cases()))
def test_existing_runtime_pair_and_map_rule_remains_closed(data, expected):
    if expected:
        result = SourceArtifact.model_validate(data)
        assert result.model_dump(mode="json")["source_sha256"] == BASE["source_sha256"]
    else:
        with pytest.raises(ValidationError):
            SourceArtifact.model_validate(data)


def test_source_schema_metadata_preserves_all_inherited_wire_settings():
    for name, value in WireModel.model_config.items():
        assert SourceArtifact.model_config[name] == value
    source = SourceArtifact.model_validate(BASE)
    with pytest.raises(ValidationError):
        source.raw_byte_length = 1
    with pytest.raises(ValidationError):
        SourceArtifact.model_validate({**BASE, "raw_byte_length": "0"})
    with pytest.raises(ValidationError):
        SourceArtifact.model_validate({**BASE, "unknown": 0})
