# Explicit public profile analysis

The optional public profile is a convenience for the already declared source-observed clock, allowlists and context mapping. It runs local analysis, writes the existing six artifacts and performs no scoring, dataset/split selection, model request or experiment admission.

From the repository root:

```text
uv run --offline --frozen fwa analyze fixtures/demo/scan.jsonl --out out/public-profile-report --public-profile config/evaluation-public-setup.v1.json
uv run --offline --frozen fwa verify out/public-profile-report --input fixtures/demo/scan.jsonl
```

Choose a new output directory each time. The command keeps the ordinary `analyze` behavior when the profile flag is absent. A profile cannot be combined with `--as-of-us`, `--internal-cidr`, `--policy` or `--contexts`; conflicting inputs fail before output creation. Policy, context and profile JSON files are read as bounded snapshots, with a16MiB cap; invalid or oversized inputs fail without printing their contents or raw exceptions.

The profile path is explicit. Its public internal CIDRs classify directions, its permitted peers/services populate the typed rule policy, and its static declared roles become finite contexts over the observed source interval. Analysis time is maximum observed event time; empty complete inputs use zero/no instantiated contexts. The source must be complete, without quarantined/excluded rows or capture-loss/incomplete quality. Failure does not fall back to a different configuration. A source change between clock derivation and completed analysis prevents publication. Individual rule channels may still describe unsupported or unavailable capabilities honestly; source completeness does not create missing byte values or firewall policy actions.

The successful CLI response includes `public_profile_content_sha256`, the canonical typed profile-content digest. It is distinct from the original file-byte digest. The existing report stores the effective typed clock, CIDRs, rule policy, contexts and limits. It does not retain a profile filename or claim profile-file authenticity. Verification recomputes from the caller's explicit source and those recorded settings, so moving or changing the original profile file does not affect a valid historical report. Adjacent byte hashes are not signatures or proof of who supplied the configuration.

This option does not change the baseline policy file, original frozen source data, labels, thresholds or quality floors. It does not establish original-corpus detection accuracy or annotation quality, and does not authorize the excluded implementation lineage to run that corpus or heldout. See [evaluation-adapter.md](evaluation-adapter.md) for the new method policy and [canonical-evaluation.md](canonical-evaluation.md) for the separately admitted evaluation components.
