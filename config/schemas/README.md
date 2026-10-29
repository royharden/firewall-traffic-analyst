# Generated owned shapes

Run `uv run python config/schemas/generate.py` after a model change, then commit the generated shapes and MANIFEST.json together. `--check` compares exact bytes and fails if a shape or manifest has drifted. Generation is deterministic under the committed dependency lock.

The eleven shapes describe owned model fields. Cross-field identity, support, counter, seed and unit relationships also require the Pydantic validators in the source models. These files do not enforce parsing/input resource limits or prove source existence, evidence recomputation, detection quality, downstream shared contracts or deployment.
