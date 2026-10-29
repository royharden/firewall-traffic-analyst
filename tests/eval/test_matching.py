"""Independent hand-sized assignment oracles; no planted corpus/Gold or metric runner."""

import itertools
import json
import random
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from firewall_analyst.shared.rulesengine.evaluation import OverlapEdge, maximum_overlap_assignment


def pairs(result):
    return {(edge.left_id, edge.right_id) for edge in result}


def test_global_assignment_beats_greedy_and_never_reuses_episode():
    result = maximum_overlap_assignment(
        ("p1", "p2"),
        ("e1", "e2"),
        (OverlapEdge("p1", "e1", 6), OverlapEdge("p1", "e2", 5), OverlapEdge("p2", "e1", 5)),
    )
    assert pairs(result) == {("p1", "e2"), ("p2", "e1")}
    assert sum(edge.overlap_rows for edge in result) == 10


def test_weight_first_then_cardinality_when_total_weight_ties():
    edges = [OverlapEdge("p1", "e1", 100), OverlapEdge("p1", "e2", 40), OverlapEdge("p2", "e1", 40)]
    assert pairs(maximum_overlap_assignment(("p1", "p2"), ("e1", "e2"), edges)) == {("p1", "e1")}
    edges[0] = OverlapEdge("p1", "e1", 80)
    assert pairs(maximum_overlap_assignment(("p1", "p2"), ("e1", "e2"), edges)) == {
        ("p1", "e2"),
        ("p2", "e1"),
    }


def test_stable_explicit_window_identity_order_and_input_edge_permutation():
    edges = tuple(OverlapEdge(left, right, 1) for left in ("late", "early") for right in ("b", "a"))
    expected = maximum_overlap_assignment(("early", "late"), ("a", "b"), edges)
    assert pairs(expected) == {("early", "a"), ("late", "b")}
    assert (
        maximum_overlap_assignment(("early", "late"), ("a", "b"), tuple(reversed(edges)))
        == expected
    )
    assert pairs(maximum_overlap_assignment(("early", "late"), ("b", "a"), edges)) == {
        ("early", "b"),
        ("late", "a"),
    }


def test_empty_unmatched_and_rectangular_inputs_have_no_ineligible_dummy_pairs():
    assert maximum_overlap_assignment((), (), ()) == ()
    assert maximum_overlap_assignment(("p",), (), ()) == ()
    assert maximum_overlap_assignment(("p",), ("e",), ()) == ()
    result = maximum_overlap_assignment(
        ("p1", "p2", "p3"),
        ("e",),
        (OverlapEdge("p2", "e", 2), OverlapEdge("p3", "e", 1)),
    )
    assert pairs(result) == {("p2", "e")}


@pytest.mark.parametrize("weight", [0, -1, True, 1.0, float("nan"), 250_001])
def test_invalid_weights_are_not_coerced_or_silently_dropped(weight):
    with pytest.raises(ValueError, match="assignment_weight"):
        maximum_overlap_assignment(("p",), ("e",), (OverlapEdge("p", "e", weight),))


def test_identity_edges_and_caps_fail_explicitly():
    for left, right, edges, reason in (
        (("p", "p"), ("e",), (), "duplicate_assignment_identity"),
        (("",), ("e",), (), "assignment_identity"),
        ((True,), ("e",), (), "assignment_identity"),
        (("p",), ("e",), (OverlapEdge("foreign", "e", 1),), "foreign_assignment_identity"),
        (
            ("p",),
            ("e",),
            (OverlapEdge("p", "e", 1), OverlapEdge("p", "e", 1)),
            "duplicate_assignment_edge",
        ),
    ):
        with pytest.raises(ValueError, match=reason):
            maximum_overlap_assignment(left, right, edges)
    with pytest.raises(ValueError, match="assignment_limit"):
        maximum_overlap_assignment(tuple(str(i) for i in range(257)), (), ())
    with pytest.raises(ValueError, match="assignment_limit"):
        maximum_overlap_assignment((), (), (), max_side=257)


def test_small_graphs_against_independent_exhaustive_oracle():
    rng = random.Random(90210)  # Algorithm controls only, unrelated to source-cohort seeds.
    left, right = ("a", "b", "c"), ("x", "y", "z")
    for _ in range(40):
        weights = {(a, b): rng.randrange(1, 8) for a in left for b in right if rng.random() < 0.6}
        edges = tuple(OverlapEdge(a, b, weight) for (a, b), weight in weights.items())
        answer = maximum_overlap_assignment(left, right, edges)
        rank = {key: index for index, key in enumerate(sorted(weights))}

        def objective(keys, *, weight_map=weights, rank_map=rank):
            return (
                sum(weight_map[key] for key in keys),
                len(keys),
                -sum(rank_map[key] for key in keys),
            )

        alternatives = []
        for assignment in itertools.product((None, *right), repeat=len(left)):
            selected = [(a, b) for a, b in zip(left, assignment, strict=True) if b is not None]
            if len({b for _, b in selected}) != len(selected) or any(
                k not in weights for k in selected
            ):
                continue
            alternatives.append(objective(selected))
        assert objective(pairs(answer)) == max(alternatives)


def test_detached_raw_matching_needs_no_owner_domain_or_network(tmp_path):
    from firewall_analyst.shared.rulesengine import evaluation

    shutil.copyfile(Path(evaluation.__file__), tmp_path / "portable_matching.py")
    script = r"""
import sys,builtins,socket,json
sys.path.insert(0,sys.argv[1])
original=builtins.__import__
def importing(name,*args,**kwargs):
    if name.startswith(('firewall_analyst','openai','typesafe','httpx','requests')):
        raise AssertionError('owner or network dependency forbidden')
    return original(name,*args,**kwargs)
builtins.__import__=importing
def deny(*args,**kwargs):raise AssertionError('network forbidden')
socket.socket=deny
socket.create_connection=deny
from portable_matching import OverlapEdge,maximum_overlap_assignment
edges=(OverlapEdge('p1','e1',6),OverlapEdge('p1','e2',5),OverlapEdge('p2','e1',5))
answer=maximum_overlap_assignment(('p1','p2'),('e1','e2'),edges)
assert sum(e.overlap_rows for e in answer)==10
assert not any(n.startswith(('firewall_analyst','openai','typesafe','httpx','requests'))
               for n in sys.modules)
print(json.dumps({'pairs':len(answer),'overlap_rows':10,'outbound':0}))
"""
    result = subprocess.run(
        [sys.executable, "-I", "-c", script, str(tmp_path)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {"pairs": 2, "overlap_rows": 10, "outbound": 0}
