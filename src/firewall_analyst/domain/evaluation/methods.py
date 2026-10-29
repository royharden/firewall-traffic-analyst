"""Injected, registered local sources and actual deterministic method execution.

No source path is accepted on the public wire. The controller owns catalogue
registration, actual raw-byte currentness callbacks and source provenance.
"""

import hashlib
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from types import MappingProxyType

from ...baselines.proxies import distinct_port_bucket_proxy, interval_cv_proxy
from ...shared.evalkit.identity import canonical_bytes
from ...shared.evalkit.models import Prediction, PublicMethodInput, SourceRef
from ...shared.evalkit.runner import MethodConfig, SourceView
from ..parsers import ZeekFileResult
from ..rules import detect
from ..rules.engine import RULES
from .config import PublicEvaluationProfile, complete_records, public_settings

METHOD_PATTERNS = {
    "rules_only": RULES,
    "rules_plus_jev": RULES,
    "rules_plus_luna": RULES,
    "interval_cv_proxy": ("beaconing",),
    "distinct_port_bucket_proxy": ("port_scan",),
}
ACTIVE_METHODS = ("rules_only", "interval_cv_proxy", "distinct_port_bucket_proxy")
METHOD_VERSION = "s8-local-detection-1"
REQUIRED_EXECUTION_REFS = {"source_closure", "parser_closure", "runtime"}


def profile_digest(profile: PublicEvaluationProfile) -> str:
    return hashlib.sha256(canonical_bytes(profile.model_dump(mode="json"))).hexdigest()


@dataclass(frozen=True)
class RegisteredSource:
    handle: str
    input_sha256: str
    parsed: ZeekFileResult
    check_current: Callable[[], bool]


class SourceUnavailable(ValueError):
    @property
    def status(self) -> str:
        return (
            "unavailable"
            if str(self) in {"unregistered_source", "source_currentness_unavailable"}
            else "stale"
        )


class TrustedSourceCatalogue:
    """A controller-owned immutable registration map, not a filesystem resolver."""

    def __init__(self, entries: tuple[RegisteredSource, ...]):
        self._entries = {}
        for entry in entries:
            if (
                type(entry) is not RegisteredSource
                or type(entry.handle) is not str
                or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", entry.handle) is None
                or entry.handle in self._entries
                or not callable(entry.check_current)
                or type(entry.parsed) is not ZeekFileResult
                or type(entry.input_sha256) is not str
                or re.fullmatch(r"[0-9a-f]{64}", entry.input_sha256) is None
                or entry.parsed.summary.source_sha256 != entry.input_sha256
            ):
                raise ValueError("invalid_source_registration")
            self._entries[entry.handle] = entry
        self._entries = MappingProxyType(self._entries)

    def resolve(self, handle: str, expected_sha256: str) -> RegisteredSource:
        if type(handle) is not str or handle not in self._entries:
            raise SourceUnavailable("unregistered_source")
        entry = self._entries[handle]
        if entry.input_sha256 != expected_sha256:
            raise SourceUnavailable("source_generation_mismatch")
        try:
            current = entry.check_current()
        except Exception as exc:
            raise SourceUnavailable("source_currentness_unavailable") from exc
        if current is not True:
            raise SourceUnavailable("source_stale")
        return entry

    def source_view(self, handle: str, expected_sha256: str, profile_ref: str) -> SourceView:
        try:
            self.resolve(handle, expected_sha256)
        except SourceUnavailable as exc:
            return SourceView(exc.status, None, {})
        return SourceView(
            "available",
            expected_sha256,
            {"source_handle": handle, "source_sha256": expected_sha256, "profile_ref": profile_ref},
        )


def public_source_payload(payload: object, input_sha256: str, profile_ref: str) -> dict[str, str]:
    if (
        type(payload) is not dict
        or set(payload) != {"source_handle", "source_sha256", "profile_ref"}
        or any(type(v) is not str for v in payload.values())
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", payload["source_handle"]) is None
        or payload["source_sha256"] != input_sha256
        or payload["profile_ref"] != profile_ref
    ):
        raise ValueError("closed_public_source_payload_required")
    return payload.copy()


class LocalMethodRunner:
    def __init__(
        self,
        method: str,
        profile: PublicEvaluationProfile,
        catalogue: TrustedSourceCatalogue,
        execution_refs: Mapping[str, str],
    ):
        if (
            method not in ACTIVE_METHODS
            or not REQUIRED_EXECUTION_REFS <= execution_refs.keys()
            or any(
                type(k) is not str or type(v) is not str or re.fullmatch(r"[0-9a-f]{64}", v) is None
                for k, v in execution_refs.items()
            )
        ):
            raise ValueError("pinned_local_method_required")
        self.method = method
        self.profile = PublicEvaluationProfile.model_validate(profile.model_dump())
        self.profile_ref = profile_digest(self.profile)
        self.catalogue = catalogue
        self.config_sha256 = method_config_digest(method, self.profile_ref, execution_refs)

    def predict(self, public_input: PublicMethodInput) -> Prediction:
        if type(public_input) is not PublicMethodInput:
            raise ValueError("canonical_public_input_required")
        PublicMethodInput.model_validate(public_input.model_dump())
        payload = public_source_payload(
            public_input.public_payload, public_input.input_sha256, self.profile_ref
        )
        if public_input.public_config_refs != (self.profile_ref,):
            raise ValueError("public_profile_binding_changed")
        handle = payload["source_handle"]
        output, status, issues = None, "ok", ()
        try:
            entry = self.catalogue.resolve(handle, public_input.input_sha256)
            complete_records(entry.parsed)
            if self.method == "rules_only":
                settings = public_settings(entry.parsed, self.profile)
                run = detect(
                    entry.parsed,
                    as_of_us=settings.as_of_us,
                    policy=settings.policy,
                    contexts=settings.contexts,
                )
                if any(
                    channel.rule_id in RULES and channel.status != "complete"
                    for channel in run.channels
                ):
                    raise ValueError("incomplete_local_rule_channels")
                channels = [c.model_dump(mode="json") for c in run.channels]
                kind = "rules"
            else:
                function = (
                    interval_cv_proxy
                    if self.method == "interval_cv_proxy"
                    else distinct_port_bucket_proxy
                )
                run = function(entry.parsed)
                channels = []
                kind = "proxy"
            output = {
                "adapter_version": "s8-detection-adapter-1",
                "method_kind": kind,
                "source_sha256": public_input.input_sha256,
                "source_handle": handle,
                "profile_ref": self.profile_ref,
                "run_config_sha256": run.config_sha256,
                "applicable_patterns": list(METHOD_PATTERNS[self.method]),
                "groups": [g.model_dump(mode="json") for g in run.groups],
                "channels": channels,
            }
            self.catalogue.resolve(handle, public_input.input_sha256)
        except SourceUnavailable as exc:
            output, status, issues = None, exc.status, ("source_changed_or_unavailable",)
        except ValueError:
            output, status, issues = None, "invalid", ("incomplete_or_invalid_local_source",)
        return Prediction(
            item_id=public_input.item_id,
            method=self.method,
            method_version=METHOD_VERSION,
            config_sha256=self.config_sha256,
            model=None,
            origin="synthetic",
            status=status,
            domain_payload=output,
            machine_output=output,
            human_effective_output=None,
            human_provenance_ref=None,
            issues=issues,
            ledger_refs=(),
            source_refs=(SourceRef(handle=handle, sha256=public_input.input_sha256),),
        )


def method_config_digest(method: str, profile_ref: str, execution_refs: Mapping[str, str]) -> str:
    if (
        method not in METHOD_PATTERNS
        or not REQUIRED_EXECUTION_REFS <= execution_refs.keys()
        or any(
            type(k) is not str or type(v) is not str or re.fullmatch(r"[0-9a-f]{64}", v) is None
            for k, v in execution_refs.items()
        )
    ):
        raise ValueError("named_method_required")
    return hashlib.sha256(
        canonical_bytes(
            {
                "method": method,
                "version": METHOD_VERSION,
                "profile_ref": profile_ref,
                "execution_refs": dict(execution_refs),
                "patterns": METHOD_PATTERNS[method],
                "annotation_status": "not_run",
                "context_policy": "public_profile" if method.startswith("rules") else "none",
            }
        )
    ).hexdigest()


def local_method_configs(
    profile: PublicEvaluationProfile,
    catalogue: TrustedSourceCatalogue,
    execution_refs: Mapping[str, str],
) -> dict[str, MethodConfig]:
    result = {}
    for method in METHOD_PATTERNS:
        runner = (
            LocalMethodRunner(method, profile, catalogue, execution_refs)
            if method in ACTIVE_METHODS
            else None
        )
        digest = method_config_digest(method, profile_digest(profile), execution_refs)
        result[method] = MethodConfig(METHOD_VERSION, digest, "synthetic", runner)
    return result
