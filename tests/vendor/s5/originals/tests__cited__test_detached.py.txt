"""what_bug_this_catches: copied generic models secretly depend on the owner app/workspace."""

import json
import shutil
import subprocess
import sys
from pathlib import Path


def test_detached_models_and_protocols_are_inert_and_relocatable(tmp_path):
    root = Path(__file__).resolve().parents[2]
    namespace = tmp_path / "portable"
    namespace.mkdir()
    (namespace / "__init__.py").write_text("", encoding="utf-8")
    destination = namespace / "cited"
    destination.mkdir()
    source = root / "src" / "changelog_advisor" / "shared" / "cited"
    for filename in ("__init__.py", "models.py", "registry.py", "schema.py", "rowcanonical.py"):
        shutil.copyfile(source / filename, destination / filename)
    script = r"""
import sys, json, os, socket, subprocess
from pathlib import Path
from pydantic import BaseModel
owner = Path(sys.argv[2]).resolve()
sys.path = [path for path in sys.path if Path(path).resolve() not in (owner, owner / "src")]
sys.path.insert(0, sys.argv[1])
# Load the declared dependency's schema/plugin metadata before application effect guards.
# The owner application remains unimportable, and the copied module is still unimported.
class DependencyProbe(BaseModel):
    count: int
assert DependencyProbe(count=1).count == 1
def forbidden(*args, **kwargs):
    raise AssertionError("model import attempted external state/effect")
original_getenv = os.getenv
def guarded_getenv(name, *args):
    # Pydantic's own plugin configuration is a declared dependency, never a provider key.
    if name == "PYDANTIC_DISABLE_PLUGINS":
        return original_getenv(name, *args)
    return forbidden(name, *args)
os.getenv = guarded_getenv
socket.create_connection = forbidden
subprocess.run = forbidden
Path.read_text = forbidden
Path.read_bytes = forbidden
from portable.cited import ArtifactRef, Finding, Registry, ResolutionContext
from portable.cited.models import SuppliedLinePointer, LineLocator
from portable.cited.schema import encoded_schemas
raw, artifact = "a"*64, "b"*64
pointer = SuppliedLinePointer(kind="file:line",source_type="supplied_text",locator_subtype="line",
    source_id="source-1",source_sha256=raw,source_revision="generation-1",
    evidence_artifact_sha256=artifact,locator=LineLocator(line_start=1,line_end=2))
policy=ArtifactRef(artifact_id="policy-1",artifact_sha256=raw,profile_id="policy/1")
context=ResolutionContext(namespace_id="namespace-1",access_policy_ref=policy,generation_policy_ref=policy)
assert Registry().resolve(pointer, context).status == "unsupported"
claim=Finding(id="finding-1",text="Unverified",verdict="partial",evidence=[pointer])
assert claim.verdict=="partial"
assert not any(name.startswith("changelog_advisor") for name in sys.modules)
assert not any(name.startswith(("openai", "typesafe", "requests", "httpx")) for name in sys.modules)
assert len(encoded_schemas()) == 5
print(json.dumps({"model_origin":"detached", "default_resolution":"unsupported", "schemas":5}))
"""
    result = subprocess.run(
        [sys.executable, "-I", "-c", script, str(tmp_path), str(root)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {
        "model_origin": "detached",
        "default_resolution": "unsupported",
        "schemas": 5,
    }
