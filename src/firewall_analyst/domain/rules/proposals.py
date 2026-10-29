"""Exact directional endpoint tuples; no wildcard/CIDR expansion or device writer."""

from collections.abc import Sequence

from ...shared.rulesengine.evidence import CheckedEvidence
from ...shared.rulesengine.proposals import compact_integer_set, neutral_proposal
from ...shared.rulesengine.schemas import FlaggedGroupV1
from ..schemas import EventV1
from .evidence import EventEvidenceSource


def observed_network_tuples(rows: Sequence[EventV1]) -> list[dict[str, str | int]]:
    grouped = {}
    for row in rows:
        if row.protocol not in {"tcp", "udp"}:
            raise ValueError("unsupported_network_tuple")
        key = (str(row.src), row.src_port, str(row.dst), row.protocol)
        grouped.setdefault(key, set()).add(row.dst_port)
    return [
        {
            "src": src,
            "src_port": source_port,
            "dst": dst,
            "protocol": protocol,
            "dst_ports": ",".join(compact_integer_set(tuple(ports))),
        }
        for (src, source_port, dst, protocol), ports in grouped.items()
    ]


def propose(group: FlaggedGroupV1, checked: CheckedEvidence, source: EventEvidenceSource):
    return neutral_proposal(group, checked, source=source, project=observed_network_tuples)
