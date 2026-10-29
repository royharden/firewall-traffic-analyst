"""S8 consumer of canonical offline S3 and deterministic S6; no installed live mode.

All accounting objects are supplied explicitly by the trusted caller. This module
does not create a budget, ledger, capture store, price registry or provider client.
Annotation outcomes are separate values and cannot change flags or proposals.
"""

import hashlib
import re
import sqlite3
from dataclasses import dataclass
from decimal import Decimal

from ..shared.rulesengine.schemas import FlaggedGroupV1
from ..shared.s3.callledger import Ledger
from ..shared.s3.callledger.models import Allocation, BudgetAuthority, CallContext, Limits
from ..shared.s3.callledger.models import canonical_digest as digest
from ..shared.s3.providers import Provider
from ..shared.s3.providers.models import Result, TypedJudgmentRequest
from ..shared.screen import ScreenPolicy, UntrustedText, prepare_text, screen_rules, wrap_untrusted
from ..shared.screen.models import PreparedText, ScreenResult
from .contracts import CATEGORIES, TRIAGE, project

SCREEN_POLICY = ScreenPolicy("s8-computed-state/1", "rules", max_input_bytes=8192)
CATEGORY_CONFIDENCE = 0.6
POLICY_SHA256 = digest(
    {
        "profile": "s8-annotation/1",
        "screen_policy": SCREEN_POLICY.sha256,
        "confidence": CATEGORY_CONFIDENCE,
        "confidence_provenance": "uncalibrated_default",
        "detection_mutation": False,
    }
)


@dataclass(frozen=True)
class PreparedAnnotation:
    group_id: str
    source_generation: str
    config_sha256: str
    model: str
    nonce: str
    category_order: tuple[str, ...]
    include_benign: bool
    projection_sha256: str
    context_sha256: str
    screen: ScreenResult
    request: TypedJudgmentRequest | None


@dataclass(frozen=True)
class AnnotationOutcome:
    status: str
    category: str | None = None
    triage_score: float | None = None
    benign_consistency: float | None = None
    confidence: float | None = None
    confidence_policy: str = f"uncalibrated_default_{CATEGORY_CONFIDENCE}"
    origin: str | None = None
    model_reported: str | None = None
    accounting_ref: str | None = None
    attempt_ids: tuple[str, ...] = ()
    current_external_cost_usd: str | None = None
    source_cost_usd: str | None = None
    normalized_usage: dict[str, int | None] | None = None
    latency_ms: float | None = None
    source_latency_ms: float | None = None
    source_capture_ref: dict | None = None
    screen_method: str = "rules"
    screen_decision: str | None = None
    screen_reason_codes: tuple[str, ...] = ()
    model_quality_measured: bool = False


def prepare_annotation(
    group: FlaggedGroupV1,
    *,
    model: str,
    nonce: str,
    category_order: tuple[str, ...] = CATEGORIES,
    include_benign: bool = False,
) -> PreparedAnnotation:
    if re.fullmatch(r"[0-9a-f]{32}", nonce) is None:
        raise ValueError("nonce_required")
    if len(category_order) != len(CATEGORIES) or set(category_order) != set(CATEGORIES):
        raise ValueError("category_order")
    projection = project(group)
    projection_sha = hashlib.sha256(projection).hexdigest()
    source = UntrustedText(group.group_id, group.support.source_sha256, projection.decode())
    screened = screen_rules(source, SCREEN_POLICY)
    request = None
    if screened.decision == "pass" and screened.coverage == "complete":
        prepared = prepare_text(source, SCREEN_POLICY)
        if not isinstance(prepared, PreparedText):
            raise ValueError("inconsistent_screen")
        wrapped = wrap_untrusted(prepared, nonce_source=lambda count: nonce)
        questions = {
            "category": {
                "type": "choice",
                "instructions": "Suggest a category; never change flags.",
                "criteria": {name: name for name in category_order},
            },
            "triage": {
                "type": "score",
                "instructions": "Suggest review priority, not malicious-intent certainty.",
                "criteria": list(TRIAGE),
            },
        }
        if include_benign:
            questions["benign_consistency"] = {
                "type": "noul",
                "instructions": "Could these computed observations fit benign activity?",
            }
        request = TypedJudgmentRequest.model_validate(
            {
                "schema_version": 1,
                "kind": "typed_judgment",
                "model": model,
                "state": dict(wrapped.state),
                "questions": questions,
            }
        )
    context_sha = digest(
        {
            "profile": "s8-annotation-context/1",
            "group_id": group.group_id,
            "source_generation": group.support.source_sha256,
            "config_sha256": group.config_sha256,
            "projection_sha256": projection_sha,
            "screen_policy_sha256": SCREEN_POLICY.sha256,
            "question_spec_sha256": request.question_spec_sha256 if request else None,
        }
    )
    return PreparedAnnotation(
        group.group_id,
        group.support.source_sha256,
        group.config_sha256,
        model,
        nonce,
        category_order,
        include_benign,
        projection_sha,
        context_sha,
        screened,
        request,
    )


def _outcome(status, prepared, result: Result | None = None, **suggestion):
    values = dict(
        screen_method=prepared.screen.method,
        screen_decision=prepared.screen.decision,
        screen_reason_codes=prepared.screen.reason_codes,
    )
    if result is not None:
        values.update(
            origin=result.origin,
            model_reported=result.model_reported,
            accounting_ref=result.accounting_ref,
            attempt_ids=tuple(result.attempt_ids),
            current_external_cost_usd=result.current_external_cost_usd,
            source_cost_usd=result.source_capture.cost_usd if result.source_capture else None,
            normalized_usage=result.normalized_usage.model_dump(mode="json"),
            latency_ms=result.latency_ms,
            source_latency_ms=result.source_capture.latency_ms if result.source_capture else None,
            source_capture_ref=result.source_capture.model_dump(mode="json")
            if result.source_capture
            else None,
        )
    return AnnotationOutcome(status, **values, **suggestion)


def annotate_offline(
    prepared: PreparedAnnotation,
    *,
    current_group: FlaggedGroupV1,
    provider: Provider,
    ledger: Ledger,
    budget: BudgetAuthority,
    context: CallContext,
    limits: Limits,
    allocation: Allocation,
) -> AnnotationOutcome:
    """Actual canonical zero-dispatch lookup; explicit accounting cannot be bypassed."""
    if provider.mode not in {"mock", "strict_replay"} or limits.max_outbound_attempts != 0:
        return _outcome("offline_only", prepared)
    try:
        fresh = prepare_annotation(
            current_group,
            model=prepared.model,
            nonce=prepared.nonce,
            category_order=prepared.category_order,
            include_benign=prepared.include_benign,
        )
        if prepared != fresh:
            return _outcome("stale_annotation", prepared)
        if prepared.request is None or prepared.screen.decision != "pass":
            return _outcome("annotation_held", prepared)
        if (
            context.source_generation != prepared.source_generation
            or context.consumer_context_sha256 != prepared.context_sha256
            or context.config_sha256 != prepared.config_sha256
            or context.policy_sha256 != POLICY_SHA256
            or context.template_sha256 != prepared.request.question_spec_sha256
            or context.purpose != "s8.annotate"
        ):
            return _outcome("context_mismatch", prepared)
        kwargs = dict(
            purpose=context.purpose,
            ledger=ledger,
            budget=budget,
            context=context,
            limits=limits,
            allocation=allocation,
        )
        provider.validate_replay_allocation(prepared.request, **kwargs)
        result = provider.run(prepared.request, **kwargs)
        if result.status != "ok":
            return _outcome(result.status, prepared, result)
        if (
            result.typed is None
            or result.attempt_ids
            or result.current_external_cost_usd is None
            or Decimal(result.current_external_cost_usd) != 0
        ):
            return _outcome("invalid_output", prepared, result)
        category = result.typed.answers["category"]
        triage = result.typed.answers["triage"]
        if category.confidence < CATEGORY_CONFIDENCE:
            return _outcome("low_confidence", prepared, result, confidence=category.confidence)
        benign = result.typed.answers.get("benign_consistency")
        return _outcome(
            "ok",
            prepared,
            result,
            category=category.choice,
            triage_score=triage.score,
            benign_consistency=benign.noul if benign else None,
            confidence=category.confidence,
        )
    except (ValueError, TypeError, KeyError, ArithmeticError, OSError, sqlite3.Error):
        return _outcome("annotation_unavailable", prepared)


def policy_inventory() -> dict:
    """Generated public inventory; the CLI does not treat this as runtime overrides."""
    return {
        "schema_version": 1,
        "kind": "generated_policy_inventory_no_runtime_overrides",
        "mode": "disabled_by_default_canonical_offline_only",
        "category_confidence": CATEGORY_CONFIDENCE,
        "confidence_policy": "uncalibrated_default",
        "triage_levels": list(TRIAGE),
        "max_projection_utf8_bytes": SCREEN_POLICY.max_input_bytes,
        "screen_method": SCREEN_POLICY.required_method,
        "policy_sha256": POLICY_SHA256,
        "external_dispatches": 0,
        "canonical_s3_s6_offline_consumer": True,
        "live_adapters_available": False,
    }
