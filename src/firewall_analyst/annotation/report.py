"""Explicit zero-outbound companion; core recomputation never performs model lookup.

The caller owns every canonical accounting object and the original requested frame.
Companion hashes bind bytes, not provider authenticity, calibration or model quality.
"""

import hashlib
import json
import re
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from pathlib import Path

from ..pipeline import ARTIFACTS, MAX_OUTPUT, verify
from ..reporting.render import _table, _text, json_bytes
from ..shared.rulesengine.schemas import FlaggedGroupV1
from ..shared.s3.callledger import Ledger
from ..shared.s3.callledger.models import (
    Allocation,
    BudgetAuthority,
    CallContext,
    Limits,
    canonical_digest,
)
from ..shared.s3.providers import Provider
from .offline import POLICY_SHA256, PreparedAnnotation, annotate_offline

COMPANION_FILES = frozenset({"annotations.json", "report.html", "report.md"})
MAX_REQUESTS = 256
NOTICE = (
    "OFFLINE MODEL ANNOTATIONS — actual mock/replay origin is recorded below. "
    "Suggestions are separate from source-checked observations. Confidence is uncalibrated. "
    "Byte integrity does not establish provider authenticity, calibration or model quality."
)


@dataclass(frozen=True, repr=False)
class OfflineGroupRequest:
    prepared: PreparedAnnotation
    provider: Provider
    ledger: Ledger
    budget: BudgetAuthority
    context: CallContext
    limits: Limits
    allocation: Allocation


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _snapshot(directory: Path) -> dict[str, bytes]:
    root = directory.resolve(strict=True)
    result, size = {}, 0
    if directory.is_symlink():
        raise ValueError("unsafe_core")
    for name in sorted(ARTIFACTS | {"manifest.json"}):
        path = directory / name
        if path.is_symlink() or path.resolve(strict=True).parent != root:
            raise ValueError("unsafe_core")
        with path.open("rb") as stream:
            data = stream.read(MAX_OUTPUT + 1)
        size += len(data)
        if size > MAX_OUTPUT:
            raise ValueError("core_output_limit")
        result[name] = data
    return result


def _validate_request(binding: OfflineGroupRequest) -> None:
    if not isinstance(binding, OfflineGroupRequest) or any(
        not isinstance(value, expected)
        for value, expected in (
            (binding.prepared, PreparedAnnotation),
            (binding.provider, Provider),
            (binding.ledger, Ledger),
            (binding.budget, BudgetAuthority),
            (binding.context, CallContext),
            (binding.limits, Limits),
            (binding.allocation, Allocation),
        )
    ):
        raise ValueError("canonical_accounting_required")
    if (
        binding.provider.mode not in {"mock", "strict_replay"}
        or binding.limits.max_outbound_attempts
    ):
        raise ValueError("offline_only")


def _render_companion(core: dict[str, bytes], companion: dict) -> dict[str, bytes]:
    section = '<section aria-labelledby="model-annotations"><h2 id="model-annotations">'
    section += "Offline model annotations</h2><p>" + _text(NOTICE) + "</p>"
    section += _table(
        "Original requested population",
        ("Field", "Value"),
        [
            ("State", companion["state"]),
            ("Requested groups", companion["requested_count"]),
            ("Returned outcomes", companion["returned_count"]),
            ("Available suggestions", companion["available_count"]),
            ("Fallback/held/unavailable", companion["fallback_count"]),
            ("Other deterministic groups", companion["unannotated_core_groups"]),
            ("Original core report SHA256", companion["core"]["report_sha256"]),
            ("Original core manifest SHA256", companion["core"]["manifest_sha256"]),
        ],
    )
    for item in companion["annotations"]:
        outcome = item["outcome"]
        section += "<h3>model_annotation: " + _text(item["group_id"]) + "</h3>"
        section += _table(
            "Offline suggestion and accounting",
            ("Field", "Recorded value"),
            [
                ("Status", outcome["status"]),
                ("Actual origin", outcome["origin"]),
                ("Requested model", item["model_requested"]),
                ("Reported model", outcome["model_reported"]),
                ("Category suggestion", outcome["category"]),
                ("Fractional triage score", outcome["triage_score"]),
                ("Benign consistency suggestion", outcome["benign_consistency"]),
                ("Confidence", outcome["confidence"]),
                ("Confidence policy", outcome["confidence_policy"]),
                ("Current external cost USD", outcome["current_external_cost_usd"]),
                ("Original source cost USD", outcome["source_cost_usd"]),
                ("Current lookup latency ms", outcome["latency_ms"]),
                ("Original source latency ms", outcome["source_latency_ms"]),
                (
                    "Replay result normalized usage (not current model dispatch)",
                    json.dumps(outcome["normalized_usage"], sort_keys=True),
                ),
                (
                    "Original capture reference",
                    json.dumps(outcome["source_capture_ref"], sort_keys=True),
                ),
                ("Accounting reference", outcome["accounting_ref"]),
                (
                    "Screen method/decision",
                    f"{outcome['screen_method']}/{outcome['screen_decision']}",
                ),
                ("Screen reasons", ", ".join(outcome["screen_reason_codes"]) or "None recorded"),
                ("Model quality measured", outcome["model_quality_measured"]),
            ],
        )
    section += "<p>Exact per-request identities, usage and nulls are retained in annotations.json. "
    section += "Use fwa verify on the original core directory with its explicit input. "
    section += (
        "That verifies the deterministic core; it does not authenticate "
        "these annotations.</p></section>"
    )
    page = core["report.html"].decode("utf8")
    if page.count("</main>") != 1:
        raise ValueError("core_render_profile")
    return {
        "annotations.json": json_bytes(companion),
        "report.html": page.replace("</main>", section + "</main>").encode("utf8"),
        "report.md": core["report.md"] + b"\n" + section.encode("utf8") + b"\n",
    }


def compose_offline_report(
    core_directory: Path,
    *,
    input_path: Path,
    requested_group_ids: Sequence[str],
    requests: Sequence[OfflineGroupRequest],
    max_output_bytes: int = MAX_OUTPUT,
) -> dict[str, bytes]:
    """Return a separate bounded bundle. Never write/mutate the original core.

    Like core verification, this assumes caller-controlled local files, not a hostile
    concurrent filesystem service. Fresh source/core checks bracket actual lookups.
    """
    if type(max_output_bytes) is not int or not 1 <= max_output_bytes <= MAX_OUTPUT:
        raise ValueError("companion_output_limit")
    if len(requested_group_ids) > MAX_REQUESTS or len(requests) > MAX_REQUESTS:
        raise ValueError("annotation_request_limit")
    requested = tuple(requested_group_ids)
    if any(
        type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None
        for value in requested
    ) or len(set(requested)) != len(requested):
        raise ValueError("invalid_requested_population")
    if not verify(core_directory, input_path=input_path):
        raise ValueError("core_verification_failed")
    core = _snapshot(core_directory)
    report = json.loads(core["report.json"])
    groups = tuple(
        FlaggedGroupV1.model_validate_json(json_bytes(item["group"])) for item in report["groups"]
    )
    catalogue = {group.group_id: group for group in groups}
    if len(catalogue) != len(groups) or any(value not in catalogue for value in requested):
        raise ValueError("foreign_or_duplicate_core_group")
    for binding in requests:
        _validate_request(binding)
    if tuple(binding.prepared.group_id for binding in requests) != requested:
        raise ValueError("requested_population_mismatch")
    if not verify(core_directory, input_path=input_path) or _snapshot(core_directory) != core:
        raise ValueError("core_or_source_changed")
    companion = {
        "schema_version": 1,
        "kind": "s8-offline-annotation-companion-1",
        "state": "offline_annotations" if requested else "no_annotation",
        "core": {
            "source_sha256": report["parse"]["source_sha256"],
            "config_sha256": report["config_sha256"],
            "parser_profile_version": report["parser_profile_version"],
            "report_sha256": _hash(core["report.json"]),
            "manifest_sha256": _hash(core["manifest.json"]),
        },
        "requested_group_ids": requested,
        "requested_count": len(requested),
        "returned_count": 0,
        "available_count": 0,
        "fallback_count": 0,
        "unannotated_core_groups": len(groups) - len(requested),
        "annotations": [],
        "model_quality_measured": False,
        "verification_scope": (
            "companion byte integrity only; original core requires separate recomputation"
        ),
        "provider_result_authenticity": "not_verified",
        "notice": NOTICE,
    }
    accumulated = len(core["report.html"]) + len(core["report.md"])
    if accumulated > max_output_bytes:
        raise ValueError("companion_output_limit")
    for binding in requests:
        prepared = binding.prepared
        outcome = annotate_offline(
            prepared,
            current_group=catalogue[prepared.group_id],
            provider=binding.provider,
            ledger=binding.ledger,
            budget=binding.budget,
            context=binding.context,
            limits=binding.limits,
            allocation=binding.allocation,
        )
        item = {
            "group_id": prepared.group_id,
            "source_generation": catalogue[prepared.group_id].support.source_sha256,
            "config_sha256": catalogue[prepared.group_id].config_sha256,
            "prepared_source_generation": prepared.source_generation,
            "prepared_config_sha256": prepared.config_sha256,
            "model_requested": prepared.model,
            "projection_sha256": prepared.projection_sha256,
            "context_sha256": prepared.context_sha256,
            "annotation_policy_sha256": POLICY_SHA256,
            "screen_policy_sha256": prepared.screen.policy_sha256,
            "screen_input_sha256": prepared.screen.input_sha256,
            "question_spec_sha256": prepared.request.question_spec_sha256
            if prepared.request
            else None,
            "prepared_request_json_sha256": canonical_digest(
                prepared.request.model_dump(mode="json")
            )
            if prepared.request
            else None,
            "outcome": asdict(outcome),
        }
        accumulated += len(json_bytes(item))
        if accumulated > max_output_bytes:
            raise ValueError("companion_output_limit")
        companion["annotations"].append(item)
    companion["returned_count"] = len(companion["annotations"])
    companion["available_count"] = sum(
        item["outcome"]["status"] == "ok" for item in companion["annotations"]
    )
    companion["fallback_count"] = len(requested) - companion["available_count"]
    if not verify(core_directory, input_path=input_path) or _snapshot(core_directory) != core:
        raise ValueError("core_or_source_changed")
    artifacts = _render_companion(core, companion)
    artifacts["manifest.json"] = json_bytes(
        {
            "schema_version": 1,
            "kind": "s8-companion-byte-inventory-not-authenticity",
            "core_manifest_sha256": companion["core"]["manifest_sha256"],
            "artifacts": {name: _hash(data) for name, data in sorted(artifacts.items())},
        }
    )
    if sum(map(len, artifacts.values())) > max_output_bytes:
        raise ValueError("companion_output_limit")
    return artifacts


def write_companion(
    destination: Path, artifacts: dict[str, bytes], *, core_directory: Path
) -> None:
    """New sibling directory only; an incomplete write leaves no final manifest."""
    if destination.resolve().parent != core_directory.resolve(strict=True).parent:
        raise ValueError("companion_must_be_sibling")
    if set(artifacts) != COMPANION_FILES | {"manifest.json"} or any(
        type(value) is not bytes for value in artifacts.values()
    ):
        raise ValueError("companion_artifact_set")
    if sum(map(len, artifacts.values())) > MAX_OUTPUT:
        raise ValueError("companion_output_limit")
    destination.mkdir(exist_ok=False)
    for name in (*sorted(COMPANION_FILES), "manifest.json"):
        with (destination / name).open("xb") as stream:
            stream.write(artifacts[name])
