"""Private raw counts for one trusted source; no corpus, paths, rates or bootstrap.

This is a domain scorer, not a method runner. The caller must separately verify
current raw bytes, method execution/configuration and trusted reference provenance.
Pydantic validation and matching source digests alone do not establish those facts.
"""

import re
from dataclasses import dataclass

from ...baselines.proxies import ProxyRun
from ...shared.rulesengine.evaluation import OverlapEdge, maximum_overlap_assignment
from ...shared.rulesengine.fixtures import GoldEpisodeV1
from ...shared.rulesengine.schemas import FlaggedGroupV1, KeyPart
from ..parsers import ZeekFileResult
from ..rules.engine import RULES, RuleChannelV1, RuleRun
from .config import complete_records

PRIMARY_PATTERNS = RULES[:-1]
KEYS = {
    "port_scan": ("src", "protocol"),
    "host_sweep": ("src", "protocol", "dst_port"),
    **{name: ("src", "protocol", "dst_port", "dst") for name in RULES[2:]},
}
THRESHOLDS = ((1, 2), (1, 4), (3, 4))


@dataclass(frozen=True)
class DetectionCounts:
    """Scorer-private references; do not publish these IDs as aggregate metrics."""

    source_sha256: str
    config_sha256: str
    applicable_patterns: tuple[str, ...]
    overlap_threshold: tuple[int, int]
    positive_edges: tuple[OverlapEdge, ...]
    benign_edges: tuple[OverlapEdge, ...]
    assignment: tuple[OverlapEdge, ...]
    true_positive: int
    false_positive_alerts: int
    false_negative: int
    eligible_positive_episodes: int
    eligible_benign_episodes: int
    affected_benign_ids: tuple[str, ...]
    suppressed_audit_ids: tuple[str, ...]
    out_of_scope_group_ids: tuple[str, ...]

    @property
    def affected_benign_episodes(self) -> int:
        return len(self.affected_benign_ids)


def _key(pattern, parts):
    if (
        type(pattern) is not str
        or pattern not in KEYS
        or type(parts) is not tuple
        or any(type(part) is not KeyPart for part in parts)
        or tuple(part.name for part in parts) != KEYS[pattern]
    ):
        raise ValueError("closed_subject_key_required")
    result = []
    for part in parts:
        expected = int if part.name == "dst_port" else str
        if type(part.value) is not expected:
            raise ValueError("subject_primitive_type")
        if part.name == "dst_port" and not 0 <= part.value <= 65535:
            raise ValueError("subject_port_range")
        if part.name == "protocol" and part.value not in {"tcp", "udp"}:
            raise ValueError("subject_transport")
        result.append((part.name, part.value))
    return tuple(result)


def _support_mask(item, pattern, parts, row_map, row_indexes, size):
    expected = _key(pattern, parts)
    bitmap = bytearray((size + 7) // 8)
    for row_id in item.support.row_ids:
        row = row_map.get(row_id)
        if row is None or item.support.source_sha256 != row.input_sha256:
            raise ValueError("foreign_evaluation_support")
        if not item.window.start_us <= row.ts_us < item.window.end_us:
            raise ValueError("support_outside_window")
        actual = tuple(
            (name, str(getattr(row, name)) if name in {"src", "dst"} else getattr(row, name))
            for name, _value in expected
        )
        if actual != expected:
            raise ValueError("support_subject_mismatch")
        index = row_indexes[row_id]
        bitmap[index // 8] |= 1 << (index % 8)
    return int.from_bytes(bitmap, "little")


def score_rules(
    parsed: ZeekFileResult,
    run: RuleRun,
    episodes: tuple[GoldEpisodeV1, ...],
    *,
    applicable_patterns: tuple[str, ...] = PRIMARY_PATTERNS,
    overlap_threshold: tuple[int, int] = (1, 2),
) -> DetectionCounts:
    if type(run) is not RuleRun:
        raise ValueError("actual_rule_run_required")
    if type(applicable_patterns) is not tuple or any(
        type(pattern) is not str for pattern in applicable_patterns
    ):
        raise ValueError("closed_evaluation_configuration")
    if type(run.channels) is not tuple or any(
        type(channel) is not RuleChannelV1 for channel in run.channels
    ):
        raise ValueError("typed_evaluation_channels")
    for channel in run.channels:
        RuleChannelV1.model_validate(channel.model_dump())
    channels = {channel.rule_id: channel for channel in run.channels}
    if len(channels) != len(run.channels) or any(
        pattern not in channels or channels[pattern].status != "complete"
        for pattern in applicable_patterns
    ):
        raise ValueError("incomplete_evaluation_channels")
    return _score(
        parsed, run.groups, episodes, run.config_sha256, applicable_patterns, overlap_threshold
    )


def score_proxy(
    parsed: ZeekFileResult,
    run: ProxyRun,
    episodes: tuple[GoldEpisodeV1, ...],
    *,
    overlap_threshold: tuple[int, int] = (1, 2),
) -> DetectionCounts:
    if type(run) is not ProxyRun:
        raise ValueError("actual_proxy_run_required")
    expected = {"interval_cv_proxy": ("beaconing",), "distinct_port_bucket_proxy": ("port_scan",)}
    if run.method_id not in expected or run.applicable_patterns != expected[run.method_id]:
        raise ValueError("declared_proxy_applicability")
    if (
        run.context_policy != "none"
        or run.interpretation != "public_design_proxy_not_actual_product"
    ):
        raise ValueError("declared_proxy_scope")
    return _score(
        parsed, run.groups, episodes, run.config_sha256, run.applicable_patterns, overlap_threshold
    )


def _score(parsed, groups, episodes, config_sha, patterns, threshold):
    rows = complete_records(parsed)
    if (
        type(patterns) is not tuple
        or not patterns
        or len(set(patterns)) != len(patterns)
        or any(type(p) is not str or p not in RULES for p in patterns)
        or ("rejected_then_established" in patterns and len(patterns) != 1)
        or type(threshold) is not tuple
        or len(threshold) != 2
        or any(type(v) is not int for v in threshold)
        or threshold not in THRESHOLDS
        or type(config_sha) is not str
        or re.fullmatch(r"[0-9a-f]{64}", config_sha) is None
    ):
        raise ValueError("closed_evaluation_configuration")
    if type(groups) is not tuple or type(episodes) is not tuple:
        raise ValueError("closed_evaluation_inventory")
    if len(groups) > 10_000 or len(episodes) > 256:
        raise ValueError("evaluation_side_limit")
    row_map = {row.row_id: row for row in rows}
    indexes = {row.row_id: i for i, row in enumerate(rows)}
    seen, flagged, suppressed, excluded = set(), [], [], []
    for group in groups:
        if type(group) is not FlaggedGroupV1:
            raise ValueError("typed_prediction_required")
        _key(group.rule_id, group.grouping_key)
        FlaggedGroupV1.model_validate(group.model_dump())
        if group.group_id in seen or group.config_sha256 != config_sha:
            raise ValueError("duplicate_or_foreign_prediction")
        seen.add(group.group_id)
        if group.status == "partial" or set(group.quality_flags) & {"capture_loss", "incomplete"}:
            raise ValueError("partial_evaluation_prediction")
        mask = _support_mask(group, group.rule_id, group.grouping_key, row_map, indexes, len(rows))
        if group.rule_id not in patterns:
            excluded.append(group.group_id)
        elif group.status == "suppressed":
            suppressed.append(group.group_id)
        else:
            flagged.append((group, mask))
    if len(flagged) > 256:
        raise ValueError("evaluation_side_limit")
    seen, positives, benign = set(), [], []
    for episode in episodes:
        if type(episode) is not GoldEpisodeV1:
            raise ValueError("typed_episode_required")
        _key(episode.pattern, episode.subject_key)
        GoldEpisodeV1.model_validate(episode.model_dump())
        if episode.episode_id in seen:
            raise ValueError("duplicate_episode")
        seen.add(episode.episode_id)
        mask = _support_mask(
            episode, episode.pattern, episode.subject_key, row_map, indexes, len(rows)
        )
        if episode.pattern in patterns:
            (benign if episode.kind == "benign" else positives).append((episode, mask))

    def order(pair):
        return pair[0].window.start_us, pair[0].window.end_us

    flagged.sort(key=lambda pair: (*order(pair), pair[0].group_id))
    positives.sort(key=lambda pair: (*order(pair), pair[0].episode_id))
    benign.sort(key=lambda pair: (*order(pair), pair[0].episode_id))

    def edges(references):
        result = []
        for group, group_mask in flagged:
            for episode, episode_mask in references:
                if (
                    group.rule_id != episode.pattern
                    or _key(group.rule_id, group.grouping_key)
                    != _key(episode.pattern, episode.subject_key)
                    or max(group.window.start_us, episode.window.start_us)
                    >= min(group.window.end_us, episode.window.end_us)
                ):
                    continue
                overlap = (group_mask & episode_mask).bit_count()
                if (
                    overlap
                    and overlap * threshold[1] >= len(episode.support.row_ids) * threshold[0]
                ):
                    result.append(OverlapEdge(group.group_id, episode.episode_id, overlap))
        return tuple(result)

    positive_edges, benign_edges = edges(positives), edges(benign)
    assignment = maximum_overlap_assignment(
        tuple(group.group_id for group, _ in flagged),
        tuple(episode.episode_id for episode, _ in positives),
        positive_edges,
    )
    return DetectionCounts(
        parsed.summary.source_sha256,
        config_sha,
        patterns,
        threshold,
        positive_edges,
        benign_edges,
        assignment,
        len(assignment),
        len(flagged) - len(assignment),
        len(positives) - len(assignment),
        len(positives),
        len(benign),
        tuple(sorted({edge.right_id for edge in benign_edges})),
        tuple(sorted(suppressed)),
        tuple(sorted(excluded)),
    )
