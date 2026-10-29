# Local CLI MVP

`local-cli-mvp/1` is a local Python/file workflow. It has no listener, cloud service,
device writer or live model request. MCP distribution and independent quality
evaluation remain deferred. Literal citations do not establish attack semantics.

Run from the repository root with Python 3.12 and the frozen dependencies:

```console
uv sync --frozen
uv run --offline --frozen python scripts/demo_local_mvp.py --out out/local-mvp-001
```

The destination must be new. The script creates 49 documentation-range synthetic
connections with repeated UIDs and CRLF physical rows. It runs the real CLI and
requires all five supported pattern names: port scan, host sweep, beaconing,
unusual outbound and large outbound. It also includes the separate
rejected-then-established diagnostic. Literal firewall-policy deny/allow remains
unsupported because Zeek connection states carry no policy action.

`normal/` holds the six artifacts: JSON, Markdown, standalone escaped HTML, full raw
row/canonical evidence, inert proposed-rule text and the last-written hash manifest.
The script verifies those artifacts from its explicit source, rejects conflicting
profile/manual options without creating their output, and checks that malformed
TSV headers produce an unsupported/error report with no groups. Finally it forges a
canonical row quote and recomputes the adjacent manifest: source recomputation must
still reject that report. `receipt.json` records actual CLI exits and artifact hashes.
This is a reproducible behavior demonstration, not a heldout detection experiment.

## Row citation boundary

The source-derived group support defines the complete ordered required row set
before production. `domain/citations.py` checks the supplied literal bytes against a
fresh bounded whole-file scan and binds the actual installed parser implementation,
Python/Pydantic runtime, effective parser configuration and Event schema. It uses
the vendored S5 producer, explicitly installed RowResolver/Registry and canonical
RequiredEvidenceFrame assessment. The backend serves only exact immutable retained
rows, allows only their explicit namespace/source and disallows historical access.
Whole-source generation checks surround the batch. No ambient resolver is installed.

Every original required row remains in the denominator, including canonical overflow
failure carriers without fake pointers. Unsupported citations downgrade affected
explanations and proposals to investigation text. Empty support is `not_applicable`;
it never passes as a resolved claim. An invalid produced citation or source mutation
refuses analysis. The adapter refuses more than 5,000 required physical rows or a
bounded output overflow rather than truncating proof. S5's own quote/Pointer/artifact
caps also apply; JSON escaping can exceed the Pointer limit for a parser-valid row.

`fwa verify` means exact recomputation under the installed producer/runtime and
recorded settings. It can reproduce a clearly downgraded report; `verified=true`
does not turn unsupported citations into resolved ones. The manifest is not a
signature. A runtime, schema or parser change can invalidate older reports.

Reports contain literal endpoint evidence: treat their access like the original
input. HTML has no script or remote asset. Proposed rules remain review text only.

Statistics tables keep numeric values and units on one line. On narrow screens,
scroll the table horizontally within its container to see all support columns;
the page itself stays within the viewport. This prevents a value such as `14000000`
from breaking into several visual lines. The source-rendered report was checked in
a real browser at 1440x1000 and 390x844, including keyboard disclosure and malformed
input states. These are author checks. Independent source/semantic checks passed,
but the independent browser attempt failed before collecting native observations;
required layout, scrolling and keyboard evidence remains blocked. No renderer defect
was established. The accepted historical wheel predates this change. A separate
current-renderer wheel passed fresh Windows installation, 15 focused citation/report
controls, the 49-row CLI journey and equality with four saved report artifacts.
Independent acceptance of the new wheel remains pending; installation does not
resolve the native browser evidence hold.

## Wheel installation

The wheel excludes `domain/seedgen`: reference-data construction is separate from
the distributable analyzer. Package selection follows [Hatch's documented exclusion
patterns](https://hatch.pypa.io/latest/config/build/#patterns). The source tree keeps
that code under its existing access rules; packaging does not grant access to it.

A Windows CPython 3.12.13 qualification built the wheel with Hatchling 1.32.4 and
installed it non-editably into a new virtual environment. Public runtime/test wheel
versions and SHA256 values matched `uv.lock`; build tooling had separate pinned
source, version and licence records. The installed console command, full 49-row
normal/refusal/tamper journey and eight citation controls passed while network and
original product-source reads were blocked. This establishes that bounded Windows
package path, not cross-platform, browser, heldout-quality or Bolt readiness.

Example Windows commands from the repository root:

```console
uv build --wheel --out-dir dist
uv venv --python 3.12 out/wheel-env
uv export --frozen --no-dev --no-emit-project --output-file out/runtime-requirements.txt
uv pip install --python out/wheel-env/Scripts/python.exe --require-hashes -r out/runtime-requirements.txt
uv pip install --python out/wheel-env/Scripts/python.exe --no-deps dist/firewall_traffic_analyst-0.0.0-py3-none-any.whl
out/wheel-env/Scripts/fwa.exe --json
```

Choose unused build/environment destinations. This example may acquire public build
dependencies; it does not fetch traffic data, model SDKs or provider credentials.
