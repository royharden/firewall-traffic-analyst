"""Explicit-input, bounded local analysis and reproducible artifact verification.

An adjacent hash manifest detects damage; it is not a signature. Verification also
recomputes every artifact from the caller's source and the recorded typed settings.
No path from a report is opened as a source. Gold, providers and scoring are absent.
"""

import base64
import hashlib
import json
from pathlib import Path
from typing import TYPE_CHECKING

from pydantic import TypeAdapter

from .domain.citations import cite_support
from .domain.parsers import parse_zeek_file
from .domain.parsers.zeek import PARSER_PROFILE_VERSION
from .domain.rules.engine import detect
from .domain.rules.evidence import EventEvidenceSource, explain
from .domain.rules.policy import NetworkContextV1, RulePolicyV1
from .domain.rules.proposals import propose
from .reporting.render import json_bytes, render
from .shared.rulesengine.evidence import CheckedEvidence
from .shared.rulesengine.rows import SourceChanged, verified_scan
from .shared.rulesengine.schemas import InputLimitsV1

if TYPE_CHECKING:
    from .domain.evaluation.config import PublicEvaluationProfile

ARTIFACTS = frozenset(
    {"report.json", "report.md", "report.html", "proposed-rules.txt", "evidence.json"}
)
MAX_OUTPUT = 64 * 1024 * 1024


def _hash(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def analyze(
    path: Path,
    *,
    as_of_us: int,
    internal_cidrs: tuple[str, ...] = (),
    policy: RulePolicyV1 | None = None,
    contexts: tuple[NetworkContextV1, ...] = (),
    limits: InputLimitsV1 | None = None,
) -> dict[str, bytes]:
    """Build in memory; publish only a complete, bounded artifact set."""
    policy, limits = policy or RulePolicyV1(), limits or InputLimitsV1()
    policy = policy.model_copy(update={"max_groups": min(policy.max_groups, limits.max_groups)})
    if len(internal_cidrs) > 256 or len(contexts) > 256:
        raise ValueError("configuration_limit")
    parsed = parse_zeek_file(path, internal_cidrs=internal_cidrs, limits=limits)
    run = detect(parsed, as_of_us=as_of_us, policy=policy, contexts=contexts)
    group_reports, evidence_rows = [], []
    citations = None
    if parsed.evidence is not None:
        source = EventEvidenceSource(
            path,
            as_of_us=as_of_us,
            internal_cidrs=internal_cidrs,
            policy=policy,
            contexts=contexts,
            limits=limits,
            expected_sha256=parsed.summary.source_sha256,
        )
        # A second parse must be identical, including quarantines and channel state.
        if source.parsed.summary != parsed.summary or source.run != run:
            raise SourceChanged("source_changed")
        support = set()
        accumulated = 0
        for group in run.groups:
            checked = explain(group, source)
            group_reports.append(
                {
                    "group": group.model_dump(mode="json"),
                    "explanation": {
                        "state": checked.state,
                        "reason_codes": checked.reason_codes,
                        "sentences": [s.model_dump(mode="json") for s in checked.sentences],
                    },
                    "proposal": propose(group, checked, source).model_dump(mode="json"),
                }
            )
            accumulated += len(json_bytes(group_reports[-1]))
            if accumulated > min(limits.max_output_bytes, MAX_OUTPUT):
                raise ValueError("output_limit")
            support.update(group.support.row_ids)

        def collect(rows, digest):
            if digest != parsed.summary.source_sha256:
                raise SourceChanged("source_changed")
            result, size = [], 0
            for row in rows:
                row_id = f"{digest}:{row.number}"
                if row_id in support:
                    if row.raw is None:
                        raise ValueError("support_row_unavailable")
                    raw = base64.b64encode(row.raw).decode("ascii")
                    size += len(raw) + len(row_id) + 128
                    if size > min(limits.max_output_bytes, MAX_OUTPUT):
                        raise ValueError("output_limit")
                    result.append({"row_id": row_id, "raw_base64": raw})
            if {r["row_id"] for r in result} != support:
                raise ValueError("support_row_unavailable")
            return result

        evidence_rows, _ = verified_scan(
            path,
            collect,
            max_bytes=parsed.evidence.max_bytes,
            max_line_bytes=parsed.evidence.max_line_bytes,
        )
        source.validate_generation(parsed.summary.source_sha256)
        citations = cite_support(
            source, evidence_rows, internal_cidrs=internal_cidrs, limits=limits
        )
        unresolved = {
            entry["reference_id"]
            for entry in citations["entries"]
            if entry["resolution"]["status"] != "resolved"
        }
        for group, item in zip(run.groups, group_reports, strict=True):
            item["canonical_citation_status"] = (
                "unsupported" if unresolved.intersection(group.support.row_ids) else "resolved"
            )
            if item["canonical_citation_status"] == "unsupported":
                failed = CheckedEvidence(
                    group.group_id,
                    group.support.source_sha256,
                    "explanation_failed",
                    (),
                    ("canonical_required_evidence_unresolved",),
                )
                item["explanation"] = {
                    "state": failed.state,
                    "reason_codes": failed.reason_codes,
                    "sentences": [],
                }
                item["proposal"] = propose(group, failed, source).model_dump(mode="json")
    verified = sum(g["explanation"]["state"] == "verified" for g in group_reports)
    report = {
        "schema_version": 1,
        "stage": "local_deterministic",
        "parser_profile_version": PARSER_PROFILE_VERSION,
        "parse": parsed.summary.model_dump(mode="json"),
        "direction_status": parsed.direction_status,
        "channels": [channel.model_dump(mode="json") for channel in run.channels],
        "config_sha256": run.config_sha256,
        "settings": {
            "as_of_us": as_of_us,
            "internal_cidrs": list(internal_cidrs),
            "policy": policy.model_dump(mode="json"),
            "contexts": [context.model_dump(mode="json") for context in contexts],
            "limits": limits.model_dump(mode="json"),
        },
        "coverage": {
            "groups": len(group_reports),
            "verified_groups": verified,
            "verified_fraction": verified / len(group_reports) if group_reports else None,
            "meaning": "source-backed explanation coverage; not detection accuracy",
        },
        "groups": group_reports,
        "canonical_citations": {
            "profile": "s8-zeek-physical-row-v1",
            "required_rows": len(evidence_rows),
            "resolved_rows": sum(
                entry["resolution"] is not None and entry["resolution"]["status"] == "resolved"
                for entry in citations["entries"]
            )
            if citations
            else 0,
            "status": (
                "unsupported" if unresolved else "resolved" if evidence_rows else "not_applicable"
            )
            if citations
            else "not_applicable",
            "meaning": "literal physical row identity; not detection accuracy or claim truth",
        },
        "providers_available": False,
        "quality_evaluation": "not_run",
        "limitations": [
            "Flags are deterministic observations, not attack proof.",
            "No device changes are applied. Context suppressions remain in the report.",
            "Unsupported/partial channels and empty results do not establish benign traffic.",
            "Canonical S5 row checks establish literal identity, not semantic truth.",
        ],
    }
    artifacts = render(report)
    artifacts["evidence.json"] = json_bytes(
        {
            "source_sha256": parsed.summary.source_sha256,
            "rows": evidence_rows,
            "canonical_citations": citations,
        }
    )
    manifest = {
        "schema_version": 1,
        "kind": "local-artifacts-sha256-not-signature",
        "artifacts": {name: _hash(data) for name, data in sorted(artifacts.items())},
    }
    artifacts["manifest.json"] = json_bytes(manifest)
    if sum(map(len, artifacts.values())) > min(limits.max_output_bytes, MAX_OUTPUT):
        raise ValueError("output_limit")
    return artifacts


def analyze_public_profile(
    path: Path, profile: "PublicEvaluationProfile", *, limits: InputLimitsV1 | None = None
) -> tuple[dict[str, bytes], str]:
    """Materialize the explicit public profile into the existing artifact format.

    The initial source clock snapshot must match the completed analysis generation.
    Effective typed settings remain the report's durable truth; no profile path is
    retained or followed during verification. This performs no scoring or Gold IO.
    """
    from .domain.evaluation.config import PublicEvaluationProfile, public_settings

    if type(profile) is not PublicEvaluationProfile:
        raise ValueError("typed_public_profile_required")

    initial = parse_zeek_file(path, internal_cidrs=profile.internal_cidrs, limits=limits)
    settings = public_settings(initial, profile)
    artifacts = analyze(
        path,
        as_of_us=settings.as_of_us,
        internal_cidrs=settings.internal_cidrs,
        policy=settings.policy,
        contexts=settings.contexts,
        limits=limits,
    )
    report = json.loads(artifacts["report.json"])
    if report["parse"]["source_sha256"] != initial.summary.source_sha256:
        raise SourceChanged("source_changed_during_profile_derivation")
    return artifacts, settings.profile_sha256


def write_artifacts(destination: Path, artifacts: dict[str, bytes]) -> None:
    """A new directory only. Manifest is the last completion marker.

    A write failure leaves a visibly incomplete directory. Nothing is overwritten or
    silently deleted, including another process's files.
    """
    if set(artifacts) != ARTIFACTS | {"manifest.json"}:
        raise ValueError("artifact_set")
    if sum(map(len, artifacts.values())) > MAX_OUTPUT:
        raise ValueError("output_limit")
    destination.mkdir(parents=True, exist_ok=False)
    for name in sorted(ARTIFACTS):
        with (destination / name).open("xb") as stream:
            stream.write(artifacts[name])
    with (destination / "manifest.json").open("xb") as stream:
        stream.write(artifacts["manifest.json"])


def verify(destination: Path, *, input_path: Path) -> bool:
    """Explicit source path required. Treat all existing report bytes as untrusted."""
    try:
        names = ARTIFACTS | {"manifest.json"}
        # Do not follow an artifact symlink/junction into an arbitrary path.
        root = destination.resolve(strict=True)
        if destination.is_symlink() or any(
            (destination / name).is_symlink()
            or (destination / name).resolve(strict=True).parent != root
            for name in names
        ):
            return False
        data, size = {}, 0
        for name in names:
            file = destination / name
            if not file.is_file() or file.stat().st_size > MAX_OUTPUT:
                return False
            # Bounded read even if an untrusted file grows after stat.
            with file.open("rb") as stream:
                data[name] = stream.read(MAX_OUTPUT + 1)
            size += len(data[name])
            if size > MAX_OUTPUT:
                return False
        manifest = json.loads(data["manifest.json"])
        if manifest != {
            "schema_version": 1,
            "kind": "local-artifacts-sha256-not-signature",
            "artifacts": {name: _hash(data[name]) for name in sorted(ARTIFACTS)},
        }:
            return False
        report = json.loads(data["report.json"])
        if report["parse"]["state"] not in {"complete", "partial"}:
            return False
        if report["parse"]["source_sha256"] is None:
            return False
        settings = report["settings"]
        if set(settings) != {"as_of_us", "internal_cidrs", "policy", "contexts", "limits"}:
            return False
        if type(settings["as_of_us"]) is not int or settings["as_of_us"] < 0:
            return False
        cidrs = settings["internal_cidrs"]
        if not isinstance(settings["contexts"], list) or len(settings["contexts"]) > 256:
            return False
        if (
            not isinstance(cidrs, list)
            or len(cidrs) > 256
            or any(type(c) is not str for c in cidrs)
        ):
            return False
        expected = analyze(
            input_path,
            as_of_us=settings["as_of_us"],
            internal_cidrs=tuple(cidrs),
            policy=RulePolicyV1.model_validate_json(json_bytes(settings["policy"])),
            contexts=TypeAdapter(tuple[NetworkContextV1, ...]).validate_json(
                json_bytes(settings["contexts"])
            ),
            limits=InputLimitsV1.model_validate_json(json_bytes(settings["limits"])),
        )
        return data == expected
    except (OSError, ValueError, KeyError, TypeError, OverflowError):
        return False
