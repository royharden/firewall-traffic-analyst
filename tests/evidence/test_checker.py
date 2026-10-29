"""Independent arithmetic/source controls, including internally consistent false999."""

from dataclasses import dataclass

import pytest

from firewall_analyst.shared.rulesengine.aggregate import measured_stat, support_for
from firewall_analyst.shared.rulesengine.evidence import (
    EvidenceSentenceV1,
    StatSpec,
    TemplateSpec,
    check_group,
)
from firewall_analyst.shared.rulesengine.rules import identified_group
from firewall_analyst.shared.rulesengine.schemas import ClaimV1, EvidenceRef, KeyPart, TimeWindow


@dataclass(frozen=True)
class Row:
    row_id: str
    value: int
    source_sha256: str = "a" * 64


class Source:
    def __init__(self, rows):
        self.rows = {row.row_id: row for row in rows}
        self.valid = True
        self.checks = 0

    def validate_generation(self, digest):
        self.checks += 1
        if not self.valid or digest != "a" * 64:
            raise ValueError("stale")

    def resolve(self, refs):
        return tuple(self.rows[ref.row_id] for ref in refs)

    def validate_group(self, group, rows):
        if not rows:
            raise ValueError("empty")


@pytest.fixture
def setup():
    rows = (Row("resource:1", 2), Row("resource:2", 3), Row("resource:3", 7))
    support = support_for(rows, source_sha256="a" * 64, row_id=lambda row: row.row_id)
    stat = measured_stat("sum", 12, "count", support, 3)
    group = identified_group(
        rule_id="resource",
        rule_version="1",
        config_sha256="b" * 64,
        window=TimeWindow(start_us=0, end_us=10),
        grouping_key=(KeyPart(name="module", value="storage"),),
        support=support,
        stats=(stat,),
        category_from_rule="resource",
        severity_from_rule=2,
    )
    claim = ClaimV1(stat_ref="sum", value=12, unit="count", formatter="integer", support=support)
    sentence = EvidenceSentenceV1(
        sentence_id="one", template_id="sum", label_kind="observed_statistic", claims=(claim,)
    )
    source = Source(rows)
    registry = {
        "sum": StatSpec(
            "count",
            lambda rows, support: measured_stat(
                "sum", sum(row.value for row in rows), "count", support, len(rows)
            ),
        )
    }
    templates = {"sum": TemplateSpec(("sum",), ("integer",), ("Observed changes: ", "."))}
    return group, sentence, source, registry, templates


def check(setup, group=None, sentences=None):
    original, sentence, source, registry, templates = setup
    return check_group(
        group or original,
        (sentence,) if sentences is None else sentences,
        source=source,
        registry=registry,
        templates=templates,
    )


def test_recomputed_real_support_and_explicit_subset_are_checked(setup):
    group, sentence, *_ = setup
    result = check(setup)
    assert result.state == "verified" and result.sentences[0].text == "Observed changes: 12."
    subset = support_for(
        (Row("resource:2", 3),), source_sha256="a" * 64, row_id=lambda row: row.row_id
    )
    claim = sentence.claims[0].model_copy(update={"value": 3, "support": subset})
    selected = sentence.model_copy(update={"claims": (claim,)})
    subset_result = check(setup, sentences=(selected,))
    assert subset_result.state == "verified"
    assert subset_result.sentences[0].text == "Selected evidence subset: Observed changes: 3."


def test_internally_consistent_forged999_fails_actual_recomputation(setup):
    group, sentence, *_ = setup
    declared = group.stats[0].model_copy(update={"value": 999})
    forged = group.model_copy(update={"stats": (declared,)})
    claim = sentence.claims[0].model_copy(update={"value": 999})
    result = check(
        setup, group=forged, sentences=(sentence.model_copy(update={"claims": (claim,)}),)
    )
    assert result.state == "explanation_failed" and result.reason_codes == (
        "declared_statistic_mismatch",
    )


@pytest.mark.parametrize(
    "change",
    [
        {"value": 5},
        {"unit": "bytes"},
        {"stat_ref": "other"},
        {"formatter": "ratio_6"},
    ],
)
def test_correct_digits_cannot_mask_wrong_value_unit_stat_or_formatter(setup, change):
    _, sentence, *_ = setup
    altered = sentence.model_copy(
        update={"claims": (sentence.claims[0].model_copy(update=change),)}
    )
    assert check(setup, sentences=(altered,)).state == "explanation_failed"


def test_examples_are_not_full_aggregate_proof_and_outside_examples_reject(setup):
    _, sentence, *_ = setup
    wrong = sentence.model_copy(
        update={
            "claims": (sentence.claims[0].model_copy(update={"value": 5}),),
            "examples": (
                EvidenceRef(source_sha256="a" * 64, row_id="resource:1"),
                EvidenceRef(source_sha256="a" * 64, row_id="resource:2"),
            ),
        }
    )
    assert check(setup, sentences=(wrong,)).state == "explanation_failed"
    foreign = sentence.model_copy(
        update={"examples": (EvidenceRef(source_sha256="a" * 64, row_id="outside"),)}
    )
    assert check(setup, sentences=(foreign,)).state == "explanation_failed"


def test_missing_stale_and_changed_during_check_fail_closed(setup):
    _, _, source, _, _ = setup
    source.valid = False
    assert check(setup).reason_codes == ("source_or_scope_unavailable",)
    source.valid = True
    del source.rows["resource:2"]
    assert check(setup).state == "explanation_failed"


def test_generation_change_after_recomputation_clears_success(setup):
    _, _, source, _, _ = setup
    original = source.validate_generation

    def validate(digest):
        if source.checks == 1:
            source.valid = False
        original(digest)

    source.validate_generation = validate
    result = check(setup)
    assert result.reason_codes == ("source_changed",) and not result.sentences


def test_foreign_resolver_row_and_unsupported_stat_adapter_reject(setup):
    _, _, source, registry, _ = setup
    source.rows["resource:1"] = Row("resource:1", 2, "c" * 64)
    assert check(setup).state == "explanation_failed"
    source.rows["resource:1"] = Row("resource:1", 2)
    registry.clear()
    assert check(setup).reason_codes == ("unsupported_statistic",)


def test_no_vacuous_or_model_only_success_and_failed_sentence_can_drop(setup):
    _, sentence, *_ = setup
    assert check(setup, sentences=()).reason_codes == ("no_checked_observation",)
    model = sentence.model_copy(update={"label_kind": "model_annotation"})
    assert check(setup, sentences=(model,)).state == "explanation_failed"
    invalid = sentence.model_copy(update={"template_id": "unapproved"})
    result = check(setup, sentences=(invalid, sentence))
    assert result.state == "verified" and len(result.sentences) == 1
    assert result.reason_codes == ("unsupported_template",)


def test_adapter_cannot_change_unit_or_support_to_match_claim(setup):
    _, _, _, registry, _ = setup
    registry["sum"] = StatSpec(
        "count", lambda rows, support: measured_stat("sum", 12, "bytes", support, len(rows))
    )
    assert check(setup).reason_codes == ("invalid_statistic_adapter",)
