"""Sparse exact tuples, association preservation and no suppressed/partial proposals."""

from dataclasses import replace

import pytest

from firewall_analyst.domain.rules.proposals import observed_network_tuples
from firewall_analyst.domain.schemas import EventV1
from firewall_analyst.shared.rulesengine.aggregate import measured_stat, support_for
from firewall_analyst.shared.rulesengine.evidence import CheckedEvidence, CheckedSentenceV1
from firewall_analyst.shared.rulesengine.proposals import compact_integer_set, neutral_proposal
from firewall_analyst.shared.rulesengine.rules import identified_group
from firewall_analyst.shared.rulesengine.schemas import ClaimV1, KeyPart, TimeWindow


@pytest.mark.parametrize(
    "values,expected",
    [
        ((1, 3), ("1", "3")),
        ((3, 1, 2, 2, 5), ("1-3", "5")),
        ((0, 65535), ("0", "65535")),
        ((), ()),
    ],
)
def test_only_actual_contiguous_integers_compress(values, expected):
    assert compact_integer_set(values) == expected


def event(line, port, dst="198.51.100.1"):
    return EventV1(
        input_sha256="a" * 64,
        raw_line_number=line,
        row_id=f"{'a' * 64}:{line}",
        ts_us=line,
        src="192.0.2.1",
        dst=dst,
        protocol="tcp",
        src_port=40000,
        dst_port=port,
    )


def test_endpoint_associations_and_sparse_ports_never_expand_to_cross_product():
    tuples = observed_network_tuples((event(1, 80), event(2, 443), event(3, 8080, "198.51.100.2")))
    assert tuples == [
        {
            "src": "192.0.2.1",
            "src_port": 40000,
            "dst": "198.51.100.1",
            "protocol": "tcp",
            "dst_ports": "80,443",
        },
        {
            "src": "192.0.2.1",
            "src_port": 40000,
            "dst": "198.51.100.2",
            "protocol": "tcp",
            "dst_ports": "8080",
        },
    ]
    assert all("/" not in item["src"] and "/" not in item["dst"] for item in tuples)


@pytest.fixture
def inputs():
    rows = (event(1, 80), event(2, 443))
    support = support_for(rows, source_sha256="a" * 64, row_id=lambda row: row.row_id)
    stat = measured_stat("rows", 2, "count", support, 2)
    group = identified_group(
        rule_id="demo",
        rule_version="1",
        config_sha256="b" * 64,
        window=TimeWindow(start_us=0, end_us=10),
        grouping_key=(KeyPart(name="src", value="192.0.2.1"),),
        support=support,
        stats=(stat,),
        category_from_rule="demo",
        severity_from_rule=2,
    )
    claim = ClaimV1(stat_ref="rows", value=2, unit="count", formatter="integer", support=support)
    sentence = CheckedSentenceV1(
        sentence_id="one",
        template_id="rows",
        label_kind="observed_statistic",
        claims=(claim,),
        text="Observed rows: 2.",
    )
    checked = CheckedEvidence(group.group_id, "a" * 64, "verified", (sentence,), ())

    class Source:
        def validate_generation(self, digest):
            assert digest == "a" * 64

        def resolve(self, refs):
            return rows

        def validate_group(self, group, rows):
            pass

    return group, checked, Source()


@pytest.mark.parametrize("state", ["suppressed", "partial", "unclear", "failed"])
def test_unproposable_groups_are_investigation_only(inputs, state):
    group, checked, source = inputs
    if state == "failed":
        checked = replace(checked, state="explanation_failed")
    elif state == "unclear":
        group = group.model_copy(update={"category_from_rule": "unclear"})
    else:
        group = group.model_copy(update={"status": state})
    proposal = neutral_proposal(group, checked, source=source, project=observed_network_tuples)
    assert proposal.status == "investigate" and "no proposed rule" in proposal.text
    assert '"dst"' not in proposal.text


def test_projection_failure_or_size_limit_cannot_truncate_to_confident_proposal(inputs):
    group, checked, source = inputs
    for projection in (lambda rows: [], lambda rows: [{"value": "x" * 70000}]):
        result = neutral_proposal(group, checked, source=source, project=projection)
        assert result.status == "investigate"
