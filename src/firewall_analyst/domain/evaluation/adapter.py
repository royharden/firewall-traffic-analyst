"""Concrete S8 domain adapter using unchanged canonical S2 wire types.

Reference labels and family IDs stay scorer-private. This module loads no corpus,
chooses no split and grants no controller/heldout/source-authenticity authority.
"""

from typing import Annotated, Literal

from pydantic import Field

from ...baselines.proxies import ProxyRun
from ...shared.evalkit.identity import canonical_bytes
from ...shared.evalkit.models import (
    DomainLabels,
    GoldRecord,
    MetricSpec,
    Outcome,
    Prediction,
    PublicMethodInput,
    PublicProjectionPolicy,
)
from ...shared.evalkit.runner import MethodConfig, SourceView
from ...shared.rulesengine.fixtures import GoldEpisodeV1
from ...shared.rulesengine.schemas import BoundaryModel, FlaggedGroupV1, Sha256
from ..rules.engine import RULES, RuleChannelV1, RuleRun
from .config import PublicEvaluationProfile
from .matching import KEYS, THRESHOLDS, _key, score_proxy, score_rules
from .methods import METHOD_PATTERNS, TrustedSourceCatalogue, profile_digest, public_source_payload

ADAPTER_VERSION = "s8-detection-adapter-1"
STATISTIC_VERSION = "s8-domain-counts-1-f1-target-denominator"
RATIO_METRICS = ("alert_precision", "alert_recall", "alert_f1", "benign_episode_fpr")
RAW_METRICS = {
    "raw_tp": ("tp", "matched_positive_pairs"),
    "raw_fp_alerts": ("fp_alerts", "unmatched_flagged_alerts"),
    "raw_fn": ("fn", "missed_positive_episodes"),
    "raw_positive_episodes": ("positive_episodes", "positive_episodes"),
    "raw_benign_episodes": ("benign_episodes", "benign_episodes"),
    "raw_affected_benign": ("affected_benign", "affected_benign_episodes"),
}


def raw_statistic_version(metric: str) -> str:
    return "s8-raw-count-1." + RAW_METRICS[metric][1]


class EpisodeLabels(BoundaryModel):
    adapter_version: Literal["s8-detection-adapter-1"]
    episodes: Annotated[tuple[GoldEpisodeV1, ...], Field(max_length=256)]
    public_profile_content_sha256: Sha256


class DetectionPayload(BoundaryModel):
    adapter_version: Literal["s8-detection-adapter-1"]
    method_kind: Literal["rules", "proxy"]
    source_sha256: Sha256
    source_handle: str
    profile_ref: Sha256
    run_config_sha256: Sha256
    applicable_patterns: Annotated[tuple[str, ...], Field(min_length=1, max_length=6)]
    groups: Annotated[tuple[FlaggedGroupV1, ...], Field(max_length=10_000)]
    channels: Annotated[tuple[RuleChannelV1, ...], Field(max_length=7)]


def threshold_field(threshold: tuple[int, int]) -> str:
    return f"detection:{threshold[0]}of{threshold[1]}"


def private_labels(gold: GoldRecord, profile_ref: str) -> EpisodeLabels:
    if type(gold) is not GoldRecord or type(gold.label_payload) is not DomainLabels:
        raise ValueError("canonical_private_domain_labels_required")
    GoldRecord.model_validate(gold.model_dump())
    labels = EpisodeLabels.model_validate_json(canonical_bytes(gold.label_payload.payload))
    if (
        gold.domain_kind != ADAPTER_VERSION
        or labels.public_profile_content_sha256 != profile_ref
        or gold.source_ref.sha256 != gold.input_sha256
    ):
        raise ValueError("private_reference_profile_changed")
    seen = set()
    for episode in labels.episodes:
        _key(episode.pattern, episode.subject_key)
        if episode.episode_id in seen or episode.support.source_sha256 != gold.input_sha256:
            raise ValueError("duplicate_or_foreign_private_reference")
        seen.add(episode.episode_id)
    return labels


def metric_specs() -> tuple[MetricSpec, ...]:
    denominators = (
        "matched_positive_plus_unmatched_flagged_alerts",
        "all_positive_and_expected_miss",
        "two_tp_plus_fp_plus_fn",
        "all_applicable_benign_episodes",
    )
    ratios = tuple(
        MetricSpec(
            metric=metric,
            statistic_version=STATISTIC_VERSION,
            population="as_frozen",
            denominator_policy=denominator,
            zero_denominator_reason="zero_denominator",
            averaging="micro",
        )
        for metric, denominator in zip(RATIO_METRICS, denominators, strict=True)
    )
    return ratios + tuple(
        MetricSpec(
            metric=metric,
            statistic_version=raw_statistic_version(metric),
            population="as_frozen",
            denominator_policy="none_direct_validated_domain_count_sum",
            zero_denominator_reason="not_a_ratio",
            averaging="none",
        )
        for metric in RAW_METRICS
    )


class DetectionAdapter:
    def __init__(
        self,
        profile: PublicEvaluationProfile,
        catalogue: TrustedSourceCatalogue,
        configs: dict[str, MethodConfig],
        *,
        dataset_alias: str = "s8-synthetic",
    ):
        if set(configs) != set(METHOD_PATTERNS):
            raise ValueError("all_named_methods_required")
        self.profile_ref = profile_digest(profile)
        self.catalogue = catalogue
        self.configs = configs.copy()
        self.dataset_alias = dataset_alias

    def validate_gold(self, record: GoldRecord) -> None:
        private_labels(record, self.profile_ref)

    def to_public_input(self, record: GoldRecord, source_view: object) -> PublicMethodInput:
        self.validate_gold(record)
        if type(source_view) is not SourceView or source_view.status != "available":
            raise ValueError("available_trusted_source_view_required")
        payload = public_source_payload(
            source_view.public_payload, record.input_sha256, self.profile_ref
        )
        if source_view.input_sha256 != record.input_sha256:
            raise ValueError("source_view_generation_changed")
        self.catalogue.resolve(payload["source_handle"], record.input_sha256)
        return PublicMethodInput(
            item_id=record.item_id,
            input_sha256=record.input_sha256,
            public_payload=payload,
            public_config_refs=(self.profile_ref,),
        )

    def validate_prediction(self, prediction: Prediction) -> None:
        if type(prediction) is not Prediction or prediction.method not in self.configs:
            raise ValueError("canonical_named_prediction_required")
        Prediction.model_validate(prediction.model_dump())
        config = self.configs[prediction.method]
        if (prediction.method_version, prediction.config_sha256, prediction.origin) != (
            config.version,
            config.config_sha256,
            config.origin,
        ) or (
            prediction.model is not None
            or prediction.human_effective_output is not None
            or prediction.human_provenance_ref is not None
        ):
            raise ValueError("local_prediction_configuration_changed")
        if prediction.status != "ok":
            return
        if config.runner is None or prediction.domain_payload is None:
            raise ValueError("never_run_method_cannot_fabricate_prediction")
        payload = DetectionPayload.model_validate_json(canonical_bytes(prediction.domain_payload))
        expected_kind = "rules" if prediction.method == "rules_only" else "proxy"
        if expected_kind == "rules":
            channels = {channel.rule_id: channel for channel in payload.channels}
            if len(payload.channels) != 7 or set(channels) != {*RULES, "denied_then_allowed"}:
                raise ValueError("actual_rule_channel_inventory_required")
            if any(channels[rule].status != "complete" for rule in RULES):
                raise ValueError("incomplete_local_rule_channels")
            unsupported = channels["denied_then_allowed"]
            if unsupported.status != "unsupported" or unsupported.reason_codes != (
                "no_policy_action_in_selected_schema",
            ):
                raise ValueError("literal_policy_action_remains_unsupported")
        if (
            payload.method_kind != expected_kind
            or payload.profile_ref != self.profile_ref
            or payload.applicable_patterns != METHOD_PATTERNS[prediction.method]
            or (expected_kind == "proxy" and payload.channels)
            or prediction.machine_output != prediction.domain_payload
            or prediction.ledger_refs
            or len(prediction.source_refs) != 1
            or prediction.source_refs[0].handle != payload.source_handle
            or prediction.source_refs[0].sha256 != payload.source_sha256
        ):
            raise ValueError("local_prediction_payload_changed")

    def to_outcomes(
        self, machine: Prediction, gold: GoldRecord, policy: object
    ) -> tuple[Outcome, ...]:
        if policy != STATISTIC_VERSION:
            raise ValueError("pinned_s8_statistic_policy_required")
        labels = private_labels(gold, self.profile_ref)
        self.validate_prediction(machine)
        if machine.item_id != gold.item_id:
            raise ValueError("prediction_reference_identity_changed")
        payload = None
        entry = None
        if machine.status == "ok":
            payload = DetectionPayload.model_validate_json(canonical_bytes(machine.domain_payload))
            if payload.source_sha256 != gold.input_sha256:
                raise ValueError("prediction_reference_source_changed")
            # Any change here aborts comparison rather than emitting status-ok zero counts.
            entry = self.catalogue.resolve(payload.source_handle, gold.input_sha256)
        outcomes = []
        for threshold in THRESHOLDS:
            for pattern in RULES:
                applicable = pattern in METHOD_PATTERNS[machine.method]
                references = tuple(e for e in labels.episodes if e.pattern == pattern)
                expected = {
                    "positive_episodes": sum(e.kind != "benign" for e in references),
                    "benign_episodes": sum(e.kind == "benign" for e in references),
                }
                predicted = None
                if applicable and payload is not None:
                    if payload.method_kind == "rules":
                        run = RuleRun(payload.groups, payload.channels, payload.run_config_sha256)
                        counts = score_rules(
                            entry.parsed,
                            run,
                            labels.episodes,
                            applicable_patterns=(pattern,),
                            overlap_threshold=threshold,
                        )
                    else:
                        run = ProxyRun(
                            machine.method,
                            payload.applicable_patterns,
                            payload.run_config_sha256,
                            payload.groups,
                        )
                        counts = score_proxy(
                            entry.parsed, run, labels.episodes, overlap_threshold=threshold
                        )
                    predicted = {
                        "tp": counts.true_positive,
                        "fp_alerts": counts.false_positive_alerts,
                        "fn": counts.false_negative,
                        "affected_benign": counts.affected_benign_episodes,
                        **expected,
                    }
                outcomes.append(
                    Outcome.model_validate_json(
                        canonical_bytes(
                            {
                                "item_id": gold.item_id,
                                "group_id": gold.group_id,
                                "dataset": gold.dataset,
                                "split": gold.split,
                                "method": machine.method,
                                "field": threshold_field(threshold),
                                "class": pattern,
                                "eligibility": "eligible" if applicable else "ineligible",
                                "status": machine.status,
                                "correct": None,
                                "predicted": predicted,
                                "expected": expected,
                                "human_touched_prediction": False,
                                "evidence_origin": machine.origin,
                                "issues": list(machine.issues)
                                + ([] if applicable else ["not_applicable"]),
                                "ledger_refs": list(machine.ledger_refs),
                            }
                        )
                    )
                )
        return tuple(outcomes)

    def metric_specs(self) -> tuple[MetricSpec, ...]:
        return metric_specs()

    def public_projection_policy(self) -> PublicProjectionPolicy:
        values = {
            "dataset_alias": (self.dataset_alias,),
            "split": ("dev", "heldout"),
            "method": tuple(METHOD_PATTERNS),
            "config_ref": tuple(dict.fromkeys(c.config_sha256 for c in self.configs.values())),
            "field": tuple(threshold_field(t) for t in THRESHOLDS),
            "class": tuple(KEYS),
            "metric": (*RATIO_METRICS, *RAW_METRICS),
            "statistic_version": (
                STATISTIC_VERSION,
                *(raw_statistic_version(m) for m in RAW_METRICS),
            ),
            "null_reason": (
                "zero_denominator",
                "unsupported_class",
                "incomplete_cohort",
                "not_run",
                "not_applicable",
                "empty_cohort",
                "insufficient_independent_groups",
                "insufficient_support",
                "insufficient_valid_draws",
                "undefined_paired_statistic",
            ),
            "evidence_origin": ("synthetic", "agent_provisional", "not_run"),
        }
        return PublicProjectionPolicy(
            mode="aggregate_only",
            allowed_dimensions=tuple(values),
            allowed_value_sets=values,
            allowed_numeric_metrics=(
                "value",
                "numerator",
                "denominator",
                "corpus_N",
                "eligible_N",
                "answered_N",
                "comparable_N",
                "error_N",
                "abstention_N",
                "stale_N",
                "low",
                "high",
            ),
            synthetic_example_refs=(),
        )
