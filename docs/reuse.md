# Reusing the generic observation core

The owned generic source lives in `src/firewall_analyst/shared/rulesengine`. It uses Python3.12 and Pydantic2 plus the standard library. Network fields and detectors stay in `domain`; providers, budgets, citation registries and screening are separate canonical packages. Import concrete submodules rather than expecting package-root convenience exports. The companion reuse-source-manifest.json inventories exact owned module bytes; it is a source inventory, not an independently accepted release bundle.

| Module | Exported purpose | Consumer obligations |
|---|---|---|
| schemas | Strict BoundaryModel, row/support/stat/group/claim contracts and support digest | Supply complete real support and generation identity; validation alone does not recompute claims |
| parsers | Physical source-line/parse-issue models and generic parser/rule protocols | Implement actual parsing and row semantics; protocols perform no I/O |
| rows | verified_scan, GenerationRows and closed source-change/limit errors | Explicit local source and bounds; no callback side effects before verification completes |
| windows | sliding_windows and bounded window batches | Inject timestamp, stable tie key and grouping key; consume completeness/cap state |
| aggregate | support_for, measured_stat and nullable reducers | Keep full row support and known/unknown coverage; do not invent missing zeros |
| rules | Candidate, merge_candidates and identified_group | Inject rule meaning, deterministic identity, row lookup and complete support |
| context | Generic bounded ContextV1 time matching | Inject domain selectors and rule applicability; retain suppressed audit |
| evidence | StatSpec, TemplateSpec, check_group and checked sentence models | Inject trusted source, exact statistic recomputation and allowed templates; examples are not aggregate proof |
| proposals | neutral_proposal and compact_integer_set | Inject exact observed-tuple projection; no wildcard broadening or execution |
| evaluation | OverlapEdge and maximum_overlap_assignment | Supply complete eligible edges and stable identity order; implement domain eligibility and canonical metrics separately |

`fixtures.py` holds strict synthetic fixture/episode contracts; its inventory entry does not export a generator, label reader or scoring implementation. Do not copy source/labels into a consumer's model input. `__init__.py` remains unchanged; copy the explicit module closure needed by a consumer and retain the repository MIT license.

## Executed unrelated-domain paths

The existing detached tests copy actual generic source into an unrelated temporary package and reject owner-package imports. A literal ResourceChange consumer parses two public resource changes, forms windows, computes support/statistics, merges a candidate, creates a group, recomputes a checked claim and produces neutral review text. Separate controls exercise time context/suppressed group semantics. The overlap helper also runs detached from owner/network dependencies and is checked against an independent exhaustive oracle on small abstract graphs.

```console
uv run --offline --no-sync pytest -q tests/evidence/test_portable.py tests/rules/test_detached.py tests/eval/test_matching.py
```

These checks demonstrate those actual generic paths. They do not establish a generic network parser, successful integration into an arbitrary app, complete consumer semantics or quality metrics. The ResourceChange source/projection remains consumer-owned. Keep the negative owner-import controls when moving the core, and independently check the new consumer's actual source resolution and denominator semantics.

For the foreign shared packages, retain each package's VENDORED.json/notice and its exact canonical source closure instead of recreating similarly named interfaces. S3 accounting objects must retain actual canonical class identity. S5 supplied-text resolution works in its installed scope; its event-table route remains unsupported. A new canonical publication requires explicit provenance and conformance adoption before use.
