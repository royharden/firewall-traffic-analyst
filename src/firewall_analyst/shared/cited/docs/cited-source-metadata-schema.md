# Source metadata schema

The generated SourceArtifact JSON Schema now expresses the pre-existing runtime
pair rule: canonical text digest and newline policy are both null/absent or both
present. A nonempty line map requires the pair. Missing fields retain the existing
null/empty defaults. This changes schema metadata only; field types, defaults,
serialization and runtime validators are unchanged.

The schema remains a structural check. It does not validate source bytes, hashes,
the ordered and unique relationship of line-map indices, provenance, access,
currentness or semantic support. Consumers still need actual runtime and content
validation. No ordinary input receives a repair or an invented canonical digest.

The original frozen fixture serialization and its failed intake stay unchanged.
A separately frozen metadata companion requires its own exact application grant
and experiment input/assembly hashes. Schema conformance does not authorize that
application or establish evaluation quality.
