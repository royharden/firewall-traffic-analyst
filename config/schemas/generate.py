"""Deterministically generate owned JSON shapes; cross-field validators also remain required."""

import argparse
import hashlib
import json
from pathlib import Path

import pydantic

from firewall_analyst.domain.schemas import EventV1
from firewall_analyst.shared.rulesengine.fixtures import GoldEpisodeV1, GoldManifestV1
from firewall_analyst.shared.rulesengine.parsers import ParseIssue, RuleContext, SourceLine
from firewall_analyst.shared.rulesengine.schemas import (
    ClaimSupportContractV1,
    EvidenceRef,
    FlaggedGroupV1,
    InputLimitsV1,
    ParseSummaryV1,
)

MODELS = (
    EventV1,
    EvidenceRef,
    FlaggedGroupV1,
    ClaimSupportContractV1,
    ParseSummaryV1,
    InputLimitsV1,
    GoldEpisodeV1,
    GoldManifestV1,
    SourceLine,
    ParseIssue,
    RuleContext,
)


def schema_files() -> dict[str, str]:
    files = {
        f"{model.__name__}.json": json.dumps(model.model_json_schema(), indent=2, sort_keys=True)
        + "\n"
        for model in MODELS
    }
    manifest = {
        "pydantic": pydantic.__version__,
        "scope": "owned boundary shapes; cross-field Pydantic validators also required",
        "files": {name: hashlib.sha256(text.encode()).hexdigest() for name, text in files.items()},
    }
    files["MANIFEST.json"] = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    return files


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    for name, text in schema_files().items():
        path = root / name
        if args.check:
            if not path.is_file() or path.read_bytes() != text.encode():
                raise SystemExit(f"Generated schema drift: {name}")
        else:
            path.write_bytes(text.encode())
    print(f"owned schema files: {len(MODELS)} shapes + manifest")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
