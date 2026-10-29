"""Closed structural wire models. Validation is not source or semantic verification."""

import base64
import hashlib
import json
import re
import unicodedata
from decimal import Decimal
from functools import reduce
from operator import or_
from typing import Annotated, Literal, Self

from pydantic import (
    AfterValidator,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Discriminator,
    Field,
    Tag,
    TypeAdapter,
    model_validator,
)

from .rowcanonical import (
    EVENT_QUOTE_BYTES,
    POINTER_BYTES,
    ROW_BYTES,
    digest,
    event_bytes,
    metric_bytes,
)


def _version(value: object) -> object:
    if type(value) is not int:
        raise ValueError("schema_version must be integer 1")
    return value


def _logical_id(value: object) -> object:
    if isinstance(value, str) and (
        value.startswith(("/", "\\"))
        or "\\" in value
        or "://" in value
        or re.match(r"^[A-Za-z]:", value)
        or any(part in (".", "..") for part in value.split("/"))
        or any(ord(char) < 32 for char in value)
    ):
        raise ValueError("logical identifier cannot be a path or fetch URL")
    return value


def _array(value: object) -> object:
    # JSON arrays and Python lists get one explicit lossless immutable representation.
    return tuple(value) if type(value) is list else value


Version = Annotated[Literal[1], BeforeValidator(_version)]
Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$", min_length=64, max_length=64)]
LogicalID = Annotated[str, Field(min_length=1, max_length=256), BeforeValidator(_logical_id)]
Revision = Annotated[str, Field(min_length=1, max_length=512), BeforeValidator(_logical_id)]
Text = Annotated[str, Field(min_length=1, max_length=32768)]
PositiveInt = Annotated[int, Field(ge=1, le=2**53 - 1)]
NonnegativeInt = Annotated[int, Field(ge=0, le=2**53 - 1)]
Probability = Annotated[float, Field(ge=0, le=1, allow_inf_nan=False)]
Coordinate = Annotated[float, Field(ge=0, allow_inf_nan=False)]
IDs = Annotated[tuple[LogicalID, ...], BeforeValidator(_array), Field(max_length=10000)]
Scope = Literal["text", "spatial", "text_and_spatial", "asserted_spatial"]
Geometry = Literal["measured_ocr", "native", "model_claimed", "none"]


class WireModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        frozen=True,
        validate_default=True,
        revalidate_instances="always",
    )


class ArtifactRef(WireModel):
    """Logical reference only; no file opener or URL authority."""

    artifact_id: LogicalID
    artifact_sha256: Digest
    profile_id: LogicalID


class QuoteLocator(WireModel):
    quote: Text | None = None
    excerpt_sha256: Digest | None = None

    @model_validator(mode="after")
    def quote_binding(self) -> Self:
        if (self.quote is None) != (self.excerpt_sha256 is None):
            raise ValueError("quote and excerpt digest must both exist or both be null")
        if self.quote is not None:
            if hashlib.sha256(self.quote.encode("utf-8")).hexdigest() != self.excerpt_sha256:
                raise ValueError("literal UTF-8 quote digest mismatch")
        return self


class LineLocator(QuoteLocator):
    line_start: PositiveInt
    line_end: PositiveInt

    @model_validator(mode="after")
    def line_bounds(self) -> Self:
        if self.line_end < self.line_start:
            raise ValueError("line_end precedes line_start")
        return self


class LogLocator(LineLocator):
    view_kind: Literal["redacted_result"]
    source_byte_start: NonnegativeInt | None = None
    source_byte_end: NonnegativeInt | None = None
    byte_coordinate_space: Literal["source_physical"] = "source_physical"
    artifact_byte_start: NonnegativeInt | None = None
    artifact_byte_end: NonnegativeInt | None = None
    artifact_coordinate_space: Literal["redacted_artifact"] = "redacted_artifact"

    @model_validator(mode="after")
    def offset_pairs(self) -> Self:
        for start, end in (
            (self.source_byte_start, self.source_byte_end),
            (self.artifact_byte_start, self.artifact_byte_end),
        ):
            if (start is None) != (end is None) or (
                start is not None and end is not None and end < start
            ):
                raise ValueError("byte interval must be a complete ordered pair")
        return self


class SectionLocator(QuoteLocator):
    section_id: LogicalID


class FragmentLocator(QuoteLocator):
    fragment_id: LogicalID


class AdvisoryLocator(QuoteLocator):
    advisory_id: LogicalID


class BoxPx(WireModel):
    units: Literal["px"] = "px"
    x0: Coordinate
    y0: Coordinate
    x1: Coordinate
    y1: Coordinate

    @model_validator(mode="after")
    def nonempty_box(self) -> Self:
        if self.x0 >= self.x1 or self.y0 >= self.y1:
            raise ValueError("box must have positive area")
        return self


class RegionLocator(WireModel):
    document_id: LogicalID
    page_id: LogicalID
    page_index: NonnegativeInt
    page_sha256: Digest
    page_digest_algorithm: Literal["rgba8-source-grid-v1"]
    source_grid_profile: LogicalID
    width_px: PositiveInt
    height_px: PositiveInt
    units: Literal["px"] = "px"
    origin: Literal["top-left"] = "top-left"
    bbox_px: BoxPx | None = None
    word_ids: IDs | None = None
    line_ids: IDs | None = None
    excerpt_sha256: Digest | None = None
    transform_ref: ArtifactRef | None = None

    @model_validator(mode="after")
    def region_shape(self) -> Self:
        for ids in (self.word_ids, self.line_ids):
            if ids is not None and (not ids or len(set(ids)) != len(ids)):
                raise ValueError("word/line IDs must be nonempty and unique when present")
        if self.bbox_px is None and self.word_ids is None and self.line_ids is None:
            raise ValueError("region needs an actual box or declared word/line IDs")
        if self.bbox_px is not None and (
            self.bbox_px.x1 > self.width_px or self.bbox_px.y1 > self.height_px
        ):
            raise ValueError("box outside source dimensions")
        return self


class ProductLocator(QuoteLocator):
    dataset_id: LogicalID
    record_id: LogicalID
    field_id: Literal["id", "name", "brand", "size", "unit", "price", "category", "description"]
    quote: Text
    excerpt_sha256: Digest


class SnapshotLocator(WireModel):
    repository_id: LogicalID
    source_kind: Literal["git_commit", "fixture_inventory"]
    snapshot_id: Annotated[str, Field(min_length=40, max_length=64)]
    inventory_sha256: Digest

    @model_validator(mode="after")
    def snapshot_shape(self) -> Self:
        if self.source_kind == "git_commit":
            if re.fullmatch(r"[0-9a-f]{40}", self.snapshot_id) is None:
                raise ValueError("initial Git capture profile supports SHA1 only")
        elif self.snapshot_id != self.inventory_sha256:
            raise ValueError("fixture snapshot ID must equal raw inventory digest")
        return self


class RepositoryLocator(SnapshotLocator):
    path: Annotated[str, Field(min_length=1, max_length=4096)]
    line_start: PositiveInt
    line_end: PositiveInt
    definition_kind: Literal[
        "path", "module", "function", "class", "cli_flag", "http_route", "config_key"
    ]

    @model_validator(mode="after")
    def repository_bounds(self) -> Self:
        if (
            self.path.startswith("/")
            or "\\" in self.path
            or ":" in self.path
            or any(part in ("", ".", "..") for part in self.path.split("/"))
            or any(ord(char) < 32 for char in self.path)
            or len(self.path.encode("utf-8")) > 4096
            or self.line_end < self.line_start
        ):
            raise ValueError("invalid relative source path or line interval")
        return self


class CodeReportLocator(SnapshotLocator):
    item_id: Digest
    reference_id: Digest
    query_sha256: Digest
    coverage_sha256: Digest

    @model_validator(mode="after")
    def report_item_shape(self) -> Self:
        if self.item_id != self.reference_id:
            raise ValueError("initial report item ID equals reference ID")
        return self


class PointerBase(WireModel):
    schema_version: Version = 1
    source_id: LogicalID
    source_sha256: Digest
    source_revision: Revision
    evidence_artifact_sha256: Digest
    provenance_ref: ArtifactRef | None = None


class SuppliedLinePointer(PointerBase):
    kind: Literal["file:line"]
    source_type: Literal["supplied_text"]
    locator_subtype: Literal["line"]
    locator: LineLocator


class LogPointer(PointerBase):
    kind: Literal["file:line"]
    source_type: Literal["configured_log"]
    locator_subtype: Literal["line"]
    locator: LogLocator
    source_id: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{1,64}$", max_length=64)]

    @model_validator(mode="after")
    def raw_revision_binding(self) -> Self:
        if self.source_revision != f"sha256:{self.source_sha256}":
            raise ValueError("neutral log revision must bind original raw digest")
        return self


class RepositoryPointer(PointerBase):
    kind: Literal["file:line"]
    source_type: Literal["repository_file"]
    locator_subtype: Literal["line"]
    locator: RepositoryLocator

    @model_validator(mode="after")
    def snapshot_binding(self) -> Self:
        _check_snapshot(self, self.locator)
        if self.source_sha256 != self.evidence_artifact_sha256:
            raise ValueError("direct repository artifact equals original file-byte digest")
        return self


class CodeReportPointer(PointerBase):
    kind: Literal["doc:section"]
    source_type: Literal["code_existence_report"]
    locator_subtype: Literal["report_item"]
    locator: CodeReportLocator

    @model_validator(mode="after")
    def snapshot_binding(self) -> Self:
        _check_snapshot(self, self.locator)
        if self.source_sha256 != self.locator.inventory_sha256:
            raise ValueError("report raw source digest equals current raw inventory digest")
        return self


def _check_snapshot(pointer: PointerBase, locator: SnapshotLocator) -> None:
    expected = f"snapshot:{locator.source_kind}:{locator.snapshot_id}"
    if pointer.source_id != locator.repository_id or pointer.source_revision != expected:
        raise ValueError("repository/raw snapshot identity join mismatch")


class SectionPointer(PointerBase):
    kind: Literal["doc:section"]
    source_type: Literal["supplied_text"]
    locator_subtype: Literal["section"]
    locator: SectionLocator


class DocumentPointer(PointerBase):
    kind: Literal["doc:page:bbox"]
    source_type: Literal["document_page"]
    locator_subtype: Literal["region"]
    locator: RegionLocator

    @model_validator(mode="after")
    def document_binding(self) -> Self:
        if self.source_id != self.locator.document_id:
            raise ValueError("document source identity mismatch")
        return self


class ScreenshotPointer(PointerBase):
    kind: Literal["doc:page:bbox"]
    source_type: Literal["screenshot_collection"]
    locator_subtype: Literal["source_region"]
    locator: RegionLocator

    @model_validator(mode="after")
    def document_binding(self) -> Self:
        if self.source_id != self.locator.document_id:
            raise ValueError("document source identity mismatch")
        return self


class ProductPointer(PointerBase):
    kind: Literal["row:id"]
    source_type: Literal["product_catalog"]
    locator_subtype: Literal["record_field"]
    locator: ProductLocator

    @model_validator(mode="after")
    def dataset_binding(self) -> Self:
        if self.source_id != self.locator.dataset_id:
            raise ValueError("dataset source identity mismatch")
        if self.source_revision != f"rg1:{self.source_sha256}":
            raise ValueError("product raw revision must bind original raw-record digest")
        declared_field = {
            "algorithm": "product-record-field-evidence-v1",
            "dataset_id": self.locator.dataset_id,
            "record_id": self.locator.record_id,
            "source_sha256": self.source_sha256,
            "source_revision": self.source_revision,
            "field_id": self.locator.field_id,
            "raw_value": self.locator.quote,
        }
        preimage = json.dumps(
            declared_field,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        if hashlib.sha256(preimage).hexdigest() != self.evidence_artifact_sha256:
            raise ValueError("declared product field artifact preimage mismatch")
        return self


def _metric_identifier(value: str) -> str:
    if (
        unicodedata.normalize("NFC", value) != value
        or value.strip() != value
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
        or len(value.encode("utf8")) > 1024
    ):
        raise ValueError("invalid literal metric identifier")
    return value


def _decimal_string(value: str) -> str:
    if re.fullmatch(r"-?(0|[1-9][0-9]{0,31})(\.[0-9]{1,8})?", value) is None:
        raise ValueError("invalid canonical decimal string")
    if (value.startswith("-") and Decimal(value) == 0) or ("." in value and value.endswith("0")):
        raise ValueError("noncanonical decimal string")
    return value


def _integer_string(value: str) -> str:
    if re.fullmatch(r"-?(0|[1-9][0-9]{0,299})", value) is None or value == "-0":
        raise ValueError("invalid exact support integer")
    return value


MetricID = Annotated[str, Field(min_length=1, max_length=256), AfterValidator(_metric_identifier)]
MetricField = Annotated[str, Field(min_length=1, max_length=256)]
MetricIDs = Annotated[tuple[MetricID, ...], BeforeValidator(_array), Field(max_length=5000)]
DatasetID = Annotated[
    str, Field(pattern=r"^s9-dataset-[0-9a-f]{32}$", min_length=43, max_length=43)
]
CanonicalDecimal = Annotated[
    str,
    Field(min_length=1, max_length=43, pattern=r"^-?(0|[1-9][0-9]{0,31})(\.[0-9]{1,8})?$"),
    AfterValidator(_decimal_string),
]
SupportInteger = Annotated[
    str,
    Field(min_length=1, max_length=301, pattern=r"^-?(0|[1-9][0-9]{0,299})$"),
    AfterValidator(_integer_string),
]
Count = Annotated[int, Field(ge=0, le=5000)]
MetricStatus = Literal["ok", "insufficient_data", "unavailable"]
MetricReason = Literal[
    "minimum_eligible_n_5",
    "zero_eligible_impressions",
    "arithmetic_out_of_range",
    "missing_time",
    "no_positive_impressions",
]


def _sorted_ids(values):
    if tuple(sorted(set(values))) != values:
        raise ValueError("contributor IDs must be sorted and distinct")


class WindowSupport(WireModel):
    start_ordinal: Annotated[int, Field(ge=1, le=3652059)]
    end_ordinal: Annotated[int, Field(ge=1, le=3652059)]
    eligible_source_ids: MetricIDs
    cohort_source_ids: MetricIDs
    n: Count
    N: Count
    numerator: SupportInteger
    denominator: SupportInteger

    @model_validator(mode="after")
    def complete_window(self) -> Self:
        _sorted_ids(self.eligible_source_ids)
        _sorted_ids(self.cohort_source_ids)
        if (
            self.end_ordinal - self.start_ordinal != 27
            or self.n != len(self.eligible_source_ids)
            or self.N != len(self.cohort_source_ids)
            or not set(self.eligible_source_ids).issubset(self.cohort_source_ids)
            or int(self.denominator) < 0
        ):
            raise ValueError("window support identity/count mismatch")
        return self


class MetricSupport(WireModel):
    """Whole retained producer support. A valid record can exceed citation byte caps."""

    schema_version: Version = 1
    metric_id: MetricField
    snapshot_id: Digest
    scope: MetricField
    definition: Text
    value: CanonicalDecimal | None
    unit: Literal["ratio", "percentage_points"]
    sample_size: Count
    excluded_size: Count
    computed_by: MetricField
    status: MetricStatus
    status_reason: MetricReason | None
    n: Count
    N: Count
    cohort_semantics: Literal[
        "rate_cohort", "trend_union", "diagnostic_single", "availability_empty"
    ]
    numerator: SupportInteger
    denominator: SupportInteger
    family: MetricField
    dimension: MetricField
    key: Annotated[str, Field(min_length=1, max_length=256)]
    eligible_source_ids: MetricIDs
    excluded_source_ids: MetricIDs
    windows: Annotated[tuple[WindowSupport, ...], BeforeValidator(_array), Field(max_length=2)]

    @model_validator(mode="after")
    def complete_support(self) -> Self:
        _sorted_ids(self.eligible_source_ids)
        _sorted_ids(self.excluded_source_ids)
        eligible, excluded = set(self.eligible_source_ids), set(self.excluded_source_ids)
        if (
            eligible & excluded
            or self.n > self.N
            or self.n != self.sample_size
            or self.excluded_size != len(excluded)
            or int(self.denominator) < 0
        ):
            raise ValueError("metric support count mismatch")
        if self.status == "ok":
            if (
                self.value is None
                or not self.sample_size
                or self.status_reason is not None
                or int(self.denominator) == 0
            ):
                raise ValueError("ok support requires value, sample and no reason")
        elif self.status_reason is None or (
            self.status == "unavailable" and self.value is not None
        ):
            raise ValueError("uncitable support requires exact status/reason/value")
        if self.cohort_semantics == "trend_union":
            if len(self.windows) != 2 or self.unit != "percentage_points":
                raise ValueError("trend requires two ordered windows")
            recent, prior = self.windows
            cohorts = set(recent.cohort_source_ids) | set(prior.cohort_source_ids)
            if (
                prior.end_ordinal + 1 != recent.start_ordinal
                or set(recent.cohort_source_ids) & set(prior.cohort_source_ids)
                or eligible != set(recent.eligible_source_ids) | set(prior.eligible_source_ids)
                or excluded != cohorts - eligible
                or self.N != len(cohorts)
                or self.n != min(recent.n, prior.n)
                or int(self.numerator)
                != 100
                * (
                    int(recent.numerator) * int(prior.denominator)
                    - int(prior.numerator) * int(recent.denominator)
                )
                or int(self.denominator) != int(recent.denominator) * int(prior.denominator)
            ):
                raise ValueError("trend whole cohort/window support mismatch")
        else:
            if self.windows or self.unit != "ratio":
                raise ValueError("nontrend windows/unit mismatch")
            if self.cohort_semantics == "availability_empty":
                if self.n or self.N or eligible:
                    raise ValueError("availability cohort must be explicitly empty")
            elif self.n != len(eligible) or self.N != len(eligible | excluded):
                raise ValueError("whole cohort identity mismatch")
            if self.cohort_semantics == "diagnostic_single" and self.n > 1:
                raise ValueError("diagnostic has at most one contributor")
        metric_bytes(self.model_dump(mode="json"))
        return self


class TagProvenance(WireModel):
    schema_version: Version = 1
    source_id: MetricID
    field: Literal["topic", "format"]
    value: Annotated[str, Field(min_length=1, max_length=16384)]
    method: MetricID
    model: MetricID | None = None
    taxonomy_version: MetricID
    threshold: CanonicalDecimal | None = None

    @model_validator(mode="after")
    def canonical_tag(self) -> Self:
        if self.threshold is not None and not 0 <= Decimal(self.threshold) <= 1:
            raise ValueError("threshold outside probability interval")
        metric_bytes(self.model_dump(mode="json"))
        return self


class SnapshotIdentity(WireModel):
    schema_version: Version = 1
    identity_version: Literal["snapshot-identity.v1"] = "snapshot-identity.v1"
    dataset_fingerprint: Digest
    tag_provenance: Annotated[
        tuple[TagProvenance, ...], BeforeValidator(_array), Field(max_length=10000)
    ]
    config_json: Annotated[str, Field(min_length=2, max_length=32768)]
    compute_version: MetricID

    @model_validator(mode="after")
    def canonical_snapshot(self) -> Self:
        from .rowcanonical import decode_retained

        config = decode_retained(self.config_json.encode("utf8"), maximum=32768, metric=True)
        if type(config) is not dict:
            raise ValueError("snapshot config_json must encode an object")
        keys = tuple((tag.source_id, tag.field) for tag in self.tag_provenance)
        if keys != tuple(sorted(set(keys))):
            raise ValueError("tag provenance must be sorted, unique and complete")
        metric_bytes(self.model_dump(mode="json"))
        return self


class PlatformSummary(WireModel):
    platform: MetricField
    rows: Count
    positive_impression_rows: Count
    missing_time_rows: Count
    eligible_hour_rows: Count
    missing_topic_rows: Count
    missing_format_rows: Count

    @model_validator(mode="after")
    def subordinate_counts(self) -> Self:
        if (
            any(
                getattr(self, k) > self.rows
                for k in type(self).model_fields
                if k not in ("platform", "rows")
            )
            or self.eligible_hour_rows > self.positive_impression_rows
        ):
            raise ValueError("platform availability count mismatch")
        return self


class MetricArtifact(WireModel):
    algorithm: Literal["s9-metric-evidence.v1"]
    namespace_id: LogicalID
    dataset_id: DatasetID
    dataset_fingerprint: Digest
    snapshot_id: Digest
    snapshot_identity: SnapshotIdentity
    rows: Annotated[tuple[MetricSupport, ...], BeforeValidator(_array), Field(max_length=10000)]
    platform_summary: Annotated[
        tuple[PlatformSummary, ...], BeforeValidator(_array), Field(max_length=5000)
    ]

    @model_validator(mode="after")
    def complete_artifact(self) -> Self:
        if (
            self.dataset_fingerprint != self.snapshot_identity.dataset_fingerprint
            or self.snapshot_id
            != digest(metric_bytes(self.snapshot_identity.model_dump(mode="json")))
            or any(row.snapshot_id != self.snapshot_id for row in self.rows)
        ):
            raise ValueError("snapshot/raw generation mismatch")
        rowkeys = tuple(row.metric_id for row in self.rows)
        platforms = tuple(row.platform for row in self.platform_summary)
        if rowkeys != tuple(sorted(set(rowkeys))) or platforms != tuple(sorted(set(platforms))):
            raise ValueError("artifact rows/platforms must be sorted and distinct")
        if any(row.scope not in platforms for row in self.rows):
            raise ValueError("metric lacks retained platform availability")
        counts = {summary.platform: summary.rows for summary in self.platform_summary}
        if any(row.N > counts[row.scope] for row in self.rows):
            raise ValueError("metric cohort exceeds retained platform source count")
        return self


class EventLocator(QuoteLocator):
    profile_version: Literal["s8-zeek-physical-row-v1"]
    row_id: Annotated[str, Field(pattern=r"^[0-9a-f]{64}:[1-9][0-9]{0,7}$")]
    physical_line_number: Annotated[int, Field(ge=1, le=10000000)]
    processing_generation: Digest
    event_record_sha256: Digest
    quote: Text
    excerpt_sha256: Digest

    @model_validator(mode="after")
    def physical_row(self) -> Self:
        if "\n" in self.quote[:-1]:
            raise ValueError("event quote must be exactly one physical LF row")
        if len(self.quote.encode("utf8")) > EVENT_QUOTE_BYTES or self.row_id.rsplit(":", 1)[
            1
        ] != str(self.physical_line_number):
            raise ValueError("event physical row identity/byte bound mismatch")
        return self


class MetricLocator(WireModel):
    profile: Literal["s9-metric-row.v1"]
    dataset_id: DatasetID
    snapshot_id: Digest
    row_sha256: Digest
    metric_id: MetricField
    scope: MetricField
    expected: MetricSupport

    @model_validator(mode="after")
    def whole_expected_row(self) -> Self:
        raw = metric_bytes(self.expected.model_dump(mode="json"))
        if (
            len(raw) > ROW_BYTES
            or digest(raw) != self.row_sha256
            or self.expected.metric_id != self.metric_id
            or self.expected.scope != self.scope
            or self.expected.snapshot_id != self.snapshot_id
        ):
            raise ValueError("metric expected whole row binding mismatch")
        return self


class EventPointer(PointerBase):
    """Physical-row declaration; installed backend still checks access/currentness."""

    kind: Literal["row:id"]
    source_type: Literal["event_table"]
    locator_subtype: Literal["row"]
    locator: EventLocator | None

    @model_validator(mode="after")
    def raw_row_binding(self) -> Self:
        if self.locator is not None:
            if (
                self.source_revision != f"sha256:{self.source_sha256}"
                or self.locator.row_id
                != f"{self.source_sha256}:{self.locator.physical_line_number}"
            ):
                raise ValueError("event raw row generation mismatch")
            artifact = {
                "algorithm": "s8-zeek-physical-row-evidence-v1",
                "source_sha256": self.source_sha256,
                "source_revision": self.source_revision,
                "processing_generation": self.locator.processing_generation,
                "row_id": self.locator.row_id,
                "physical_line_number": self.locator.physical_line_number,
                "event_record_sha256": self.locator.event_record_sha256,
                "raw_line_base64": base64.b64encode(self.locator.quote.encode("utf8")).decode(
                    "ascii"
                ),
            }
            if digest(event_bytes(artifact)) != self.evidence_artifact_sha256:
                raise ValueError("event artifact preimage mismatch")
            wire = json.dumps(
                self.model_dump(mode="json"),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf8")
            if len(wire) > POINTER_BYTES:
                raise ValueError("event whole Pointer byte limit")
        return self


class MetricPointer(PointerBase):
    """Whole metric evidence declaration, never independent performance approval."""

    kind: Literal["row:id"]
    source_type: Literal["metric_table"]
    locator_subtype: Literal["metric"]
    locator: MetricLocator | None

    @model_validator(mode="after")
    def raw_dataset_binding(self) -> Self:
        if self.locator is not None:
            if (
                self.source_id != self.locator.dataset_id
                or self.source_revision != self.source_sha256
            ):
                raise ValueError("metric raw dataset generation mismatch")
            if len(metric_bytes(self.model_dump(mode="json"))) > POINTER_BYTES:
                raise ValueError("metric whole Pointer byte limit")
        return self


class FragmentPointer(PointerBase):
    kind: Literal["url#fragment"]
    source_type: Literal["saved_web"]
    locator_subtype: Literal["fragment"]
    locator: FragmentLocator


class AdvisoryPointer(PointerBase):
    kind: Literal["advisory:id"]
    source_type: Literal["advisory_record"]
    locator_subtype: Literal["id"]
    locator: AdvisoryLocator


def pointer_key(value: object) -> tuple[str, str, str] | None:
    if isinstance(value, dict):
        parts = tuple(value.get(key) for key in ("kind", "source_type", "locator_subtype"))
    elif isinstance(value, PointerBase):
        parts = tuple(
            getattr(value, key, None) for key in ("kind", "source_type", "locator_subtype")
        )
    else:
        return None
    return parts if all(type(part) is str for part in parts) else None


def _tag(value: object) -> str | None:
    key = pointer_key(value)
    return "|".join(key) if key else None


POINTER_MODELS = (
    SuppliedLinePointer,
    LogPointer,
    RepositoryPointer,
    CodeReportPointer,
    SectionPointer,
    DocumentPointer,
    ScreenshotPointer,
    ProductPointer,
    EventPointer,
    MetricPointer,
    FragmentPointer,
    AdvisoryPointer,
)
DOMAIN_KEYS = frozenset(
    tuple(
        model.model_fields[name].annotation.__args__[0]
        for name in ("kind", "source_type", "locator_subtype")
    )
    for model in POINTER_MODELS
)
_TAGGED_MODELS = tuple(
    Annotated[model, Tag("|".join(key))]
    for model in POINTER_MODELS
    for key in [
        tuple(
            model.model_fields[name].annotation.__args__[0]
            for name in ("kind", "source_type", "locator_subtype")
        )
    ]
)
# A runtime-built union uses type composition, not a tuple mistaken for one type.
Pointer = Annotated[reduce(or_, _TAGGED_MODELS), Discriminator(_tag)]
POINTER_ADAPTER = TypeAdapter(Pointer)


class LineMapping(WireModel):
    source_line: PositiveInt
    canonical_line: PositiveInt


class SourceArtifact(WireModel):
    """Declared source metadata, not an acquisition or normalization implementation."""

    # Export existing text_metadata constraints for structural-schema consumers.
    # Content identity and ordered/unique line mappings still require runtime validation.
    model_config = ConfigDict(
        json_schema_extra={
            "allOf": [
                {
                    "anyOf": [
                        {
                            "properties": {
                                "canonical_text_sha256": {"type": "null"},
                                "newline_policy": {"type": "null"},
                            }
                        },
                        {
                            "required": ["canonical_text_sha256", "newline_policy"],
                            "properties": {
                                "canonical_text_sha256": {"type": "string"},
                                "newline_policy": {"type": "string"},
                            },
                        },
                    ]
                },
                {
                    "if": {
                        "required": ["line_map"],
                        "properties": {"line_map": {"minItems": 1}},
                    },
                    "then": {
                        "required": ["canonical_text_sha256", "newline_policy"],
                        "properties": {
                            "canonical_text_sha256": {"type": "string"},
                            "newline_policy": {"type": "string"},
                        },
                    },
                },
            ]
        }
    )

    schema_version: Version = 1
    source_id: LogicalID
    source_type: LogicalID
    source_sha256: Digest
    source_revision: Revision
    evidence_artifact_sha256: Digest
    raw_byte_length: NonnegativeInt
    canonical_text_sha256: Digest | None = None
    newline_policy: Literal["identity", "crlf-to-lf"] | None = None
    line_map: Annotated[
        tuple[LineMapping, ...], BeforeValidator(_array), Field(max_length=10000)
    ] = ()

    @model_validator(mode="after")
    def text_metadata(self) -> Self:
        if (self.canonical_text_sha256 is None) != (self.newline_policy is None):
            raise ValueError("canonical digest and explicit newline policy belong together")
        if self.line_map and self.canonical_text_sha256 is None:
            raise ValueError("line map requires explicit canonical text identity")
        pairs = [(entry.source_line, entry.canonical_line) for entry in self.line_map]
        original = [pair[0] for pair in pairs]
        canonical = [pair[1] for pair in pairs]
        if original != sorted(set(original)) or canonical != sorted(set(canonical)):
            raise ValueError("line map must be ordered, unique and unambiguous")
        return self


class MethodRef(WireModel):
    method_id: LogicalID
    origin: Literal["deterministic", "typed", "generative", "synthetic_replay", "actual_replay"]
    policy_sha256: Digest
    model_requested: LogicalID | None = None
    model_reported: LogicalID | None = None


class Finding(WireModel):
    """Generic semantic claim; even a matching quote cannot certify its truth."""

    schema_version: Version = 1
    id: LogicalID
    text: Text
    verdict: Literal["partial", "unsupported"]
    probability: Probability | None = None
    confidence: Probability | None = None
    evidence: Annotated[tuple[Pointer, ...], BeforeValidator(_array), Field(max_length=128)]
    method: MethodRef | None = None


class Coverage(WireModel):
    status: Literal["complete", "partial", "unknown"]
    requested: NonnegativeInt | None = None
    returned: NonnegativeInt | None = None
    output_truncated: bool | None = None
    profile_ref: ArtifactRef | None = None


class RowProvenanceBase(WireModel):
    namespace_id: LogicalID
    source_id: LogicalID
    source_sha256: Digest
    artifact_sha256: Digest
    generation_mode: Literal["current", "retained_historical"]
    current: bool

    @model_validator(mode="after")
    def explicit_currentness(self) -> Self:
        if self.current != (self.generation_mode == "current"):
            raise ValueError("historical evidence cannot claim currentness")
        return self


class EventRowProvenance(RowProvenanceBase):
    profile: Literal["s8-zeek-physical-row-v1"]
    row_id: Annotated[str, Field(pattern=r"^[0-9a-f]{64}:[1-9][0-9]{0,7}$")]
    physical_line_number: Annotated[int, Field(ge=1, le=10000000)]
    event_record_sha256: Digest
    processing_generation: Digest
    parser_implementation_sha256: Digest
    parser_runtime_sha256: Digest
    parser_config_sha256: Digest
    event_schema_sha256: Digest


class MetricRowProvenance(RowProvenanceBase):
    profile: Literal["s9-metric-row.v1"]
    dataset_id: DatasetID
    snapshot_id: Digest
    row_sha256: Digest
    config_sha256: Digest
    tag_provenance_sha256: Digest
    compute_version: MetricID
    n: Count
    N: Count
    metric_status: MetricStatus
    metric_status_reason: MetricReason | None


class ResolutionProvenance(WireModel):
    geometry_provenance: Geometry | None = None
    ocr_confidence: Probability | None = None
    owner_resolution_scope: Literal["redacted_text"] | None = None
    view_kind: Literal["raw_source", "redacted_result"] | None = None
    coverage: Coverage | None = None
    profile_ref: ArtifactRef | None = None
    row: (
        Annotated[EventRowProvenance | MetricRowProvenance, Field(discriminator="profile")] | None
    ) = None


class Resolution(WireModel):
    status: Literal["resolved", "unsupported", "stale", "missing", "invalid"]
    checked_source_revision: Revision | None = None
    checked_source_sha256: Digest | None = None
    checked_artifact_sha256: Digest | None = None
    scope: Scope | None = None
    excerpt: Text | None = None
    excerpt_sha256: Digest | None = None
    reason: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{0,63}$", max_length=64)]
    provenance: ResolutionProvenance | None = None

    @model_validator(mode="after")
    def honest_scope(self) -> Self:
        if self.status != "resolved":
            if (
                self.scope is not None
                or self.excerpt is not None
                or self.excerpt_sha256 is not None
            ):
                raise ValueError("failed resolution cannot claim a successful excerpt or scope")
            return self
        if None in (
            self.checked_source_revision,
            self.checked_source_sha256,
            self.checked_artifact_sha256,
            self.scope,
        ):
            raise ValueError("resolved result needs all checked source/artifact bindings and scope")
        if (self.excerpt is None) != (self.excerpt_sha256 is None):
            raise ValueError("excerpt and literal digest must both exist or both be null")
        if self.excerpt is not None and (
            hashlib.sha256(self.excerpt.encode("utf-8")).hexdigest() != self.excerpt_sha256
        ):
            raise ValueError("resolved literal excerpt digest mismatch")
        geometry = self.provenance.geometry_provenance if self.provenance else None
        if self.scope in ("spatial", "text_and_spatial") and geometry not in (
            "native",
            "measured_ocr",
        ):
            raise ValueError("spatial scope requires native/measured provenance")
        if self.scope == "asserted_spatial" and geometry != "model_claimed":
            raise ValueError("asserted scope must retain model-claimed provenance")
        if self.scope in ("spatial", "asserted_spatial") and self.excerpt is not None:
            raise ValueError("spatial-only scope cannot claim a checked text excerpt")
        return self


class ResolutionContext(WireModel):
    """Caller-supplied policy references; structural shape does not grant access."""

    namespace_id: LogicalID
    access_policy_ref: ArtifactRef
    generation_policy_ref: ArtifactRef
    required_scope: Literal["text", "spatial", "text_and_spatial"] | None = None
    generation_mode: Literal["current", "retained_historical"] = "current"
