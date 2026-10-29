"""Own Event/source adapter. This is not the unprovided S5 canonical Pointer seam."""

from collections.abc import Sequence
from pathlib import Path

from ...shared.rulesengine.aggregate import (
    byte_cv_stat,
    interval_stats,
    measured_stat,
    sum_stat,
)
from ...shared.rulesengine.evidence import (
    EvidenceSentenceV1,
    StatSpec,
    TemplateSpec,
    check_group,
)
from ...shared.rulesengine.rows import verified_scan
from ...shared.rulesengine.schemas import ClaimV1, EvidenceRef, FlaggedGroupV1, InputLimitsV1
from ..parsers import parse_zeek_file
from ..schemas import EventV1
from .engine import ESTABLISHED, detect
from .policy import NetworkContextV1, RulePolicyV1


class EventEvidenceSource:
    """Fresh two-pass parsed snapshot plus current-generation checks around each use.

    The actual source-derived group catalogue binds config, context, clock and complete
    support. A caller cannot turn a manually fabricated matching number into a flag.
    """

    def __init__(
        self,
        path: Path,
        *,
        as_of_us: int,
        internal_cidrs: tuple[str, ...] = (),
        policy: RulePolicyV1 | None = None,
        contexts: tuple[NetworkContextV1, ...] = (),
        limits: InputLimitsV1 | None = None,
        expected_sha256: str | None = None,
    ):
        self.parsed = parse_zeek_file(path, internal_cidrs=internal_cidrs, limits=limits)
        self.generation = self.parsed.evidence
        if self.generation is None or (
            expected_sha256 is not None and self.generation.source_sha256 != expected_sha256
        ):
            raise ValueError("source_unavailable_or_stale")
        self.run = detect(self.parsed, as_of_us=as_of_us, policy=policy, contexts=contexts)
        self._rows = {row.row_id: row for row in self.parsed.records}
        self._groups = {group.group_id: group for group in self.run.groups}

    def validate_generation(self, source_sha256: str) -> None:
        _, actual = verified_scan(
            self.generation.path,
            lambda rows, digest: None,
            max_bytes=self.generation.max_bytes,
            max_line_bytes=self.generation.max_line_bytes,
        )
        if source_sha256 != self.generation.source_sha256 or actual.source_sha256 != source_sha256:
            raise ValueError("source_changed")

    def resolve(self, refs: tuple[EvidenceRef, ...]) -> tuple[EventV1, ...]:
        if any(ref.source_sha256 != self.generation.source_sha256 for ref in refs):
            raise ValueError("foreign_generation")
        return tuple(self._rows[ref.row_id] for ref in refs)

    def validate_group(self, group: FlaggedGroupV1, rows: Sequence[EventV1]) -> None:
        if self._groups.get(group.group_id) != group:
            raise ValueError("group_not_in_source_catalogue")
        if tuple(row.row_id for row in rows) != group.support.row_ids:
            raise ValueError("support_mismatch")


def _count(stat_id, getter):
    return StatSpec(
        "count",
        lambda rows, support: measured_stat(stat_id, getter(rows), "count", support, len(rows)),
    )


def _sum(stat_id, attribute, unit):
    return StatSpec(
        unit,
        lambda rows, support: sum_stat(
            rows,
            getter=lambda row: getattr(row, attribute),
            support=support,
            stat_id=stat_id,
            unit=unit,
        ),
    )


def _interval(stat_id):
    unit = (
        "ratio"
        if stat_id == "interval_cv"
        else "count"
        if stat_id in {"positive_intervals", "equal_timestamps"}
        else "microseconds"
    )
    return StatSpec(
        unit,
        lambda rows, support: next(
            stat
            for stat in interval_stats(rows, timestamp=lambda row: row.ts_us, support=support)
            if stat.stat_id == stat_id
        ),
    )


def event_statistics() -> dict[str, StatSpec[EventV1]]:
    return {
        "row_count": _count("row_count", len),
        "distinct_destinations": _count(
            "distinct_destinations", lambda rows: len({row.dst for row in rows})
        ),
        "distinct_ports": _count(
            "distinct_ports", lambda rows: len({row.dst_port for row in rows})
        ),
        "orig_bytes_sum": _sum("orig_bytes_sum", "orig_bytes", "bytes"),
        "resp_bytes_sum": _sum("resp_bytes_sum", "resp_bytes", "bytes"),
        "duration_sum_us": _sum("duration_sum_us", "duration_us", "microseconds"),
        **{
            name: _interval(name)
            for name in (
                "span_us",
                "positive_intervals",
                "equal_timestamps",
                "interval_median_us",
                "interval_cv",
            )
        },
        "orig_bytes_cv": StatSpec(
            "ratio",
            lambda rows, support: byte_cv_stat(
                rows, getter=lambda row: row.orig_bytes, support=support
            ),
        ),
        "rejection_count": _count(
            "rejection_count", lambda rows: sum(row.conn_state == "REJ" for row in rows)
        ),
        "established_count": _count(
            "established_count", lambda rows: sum(row.conn_state in ESTABLISHED for row in rows)
        ),
    }


EVENT_TEMPLATES = {
    "observed.rows": TemplateSpec(
        ("row_count",), ("integer",), ("Observed supporting rows: ", ".")
    ),
    "observed.ports": TemplateSpec(
        ("distinct_ports",),
        ("integer",),
        ("Distinct destination ports in the supporting rows: ", "."),
    ),
    "observed.destinations": TemplateSpec(
        ("distinct_destinations",),
        ("integer",),
        ("Distinct destinations in the supporting rows: ", "."),
    ),
    "observed.origin_bytes": TemplateSpec(
        ("orig_bytes_sum",),
        ("integer",),
        ("Known origin bytes in the supporting rows: ", " bytes."),
    ),
    "observed.span": TemplateSpec(
        ("span_us",), ("integer",), ("Observed support time span: ", " microseconds.")
    ),
    "observed.interval_cv": TemplateSpec(
        ("interval_cv",), ("ratio_6",), ("Population CV of positive observed inter-arrivals: ", ".")
    ),
}


def observations(group: FlaggedGroupV1) -> tuple[EvidenceSentenceV1, ...]:
    stats = {stat.stat_id: stat for stat in group.stats}
    sentences = []
    for template_id, template in EVENT_TEMPLATES.items():
        stat = stats.get(template.stat_refs[0])
        if stat is None or stat.value is None:
            continue
        claim = ClaimV1(
            stat_ref=stat.stat_id,
            value=stat.value,
            unit=stat.unit,
            formatter=template.formatters[0],
            support=stat.support,
        )
        sentences.append(
            EvidenceSentenceV1(
                sentence_id=template_id,
                template_id=template_id,
                label_kind="observed_statistic",
                claims=(claim,),
                examples=(),
            )
        )
    return tuple(sentences)


def explain(group: FlaggedGroupV1, source: EventEvidenceSource):
    return check_group(
        group,
        observations(group),
        source=source,
        registry=event_statistics(),
        templates=EVENT_TEMPLATES,
    )
