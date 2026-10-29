"""Generate deterministic model schemas only when explicitly invoked."""

import argparse
import json
from pathlib import Path

from .models import POINTER_ADAPTER, Finding, Resolution, ResolutionContext, SourceArtifact


def schemas() -> dict[str, dict]:
    return {
        "pointer.schema.json": POINTER_ADAPTER.json_schema(),
        "finding.schema.json": Finding.model_json_schema(),
        "source.schema.json": SourceArtifact.model_json_schema(),
        "resolution.schema.json": Resolution.model_json_schema(),
        "resolution-context.schema.json": ResolutionContext.model_json_schema(),
    }


def encoded_schemas() -> dict[str, str]:
    return {
        name: json.dumps(schema, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
        for name, schema in schemas().items()
    }


def encoded_row_schemas() -> dict[str, str]:
    """Explicit optional row closure; old structural five-schema API stays stable."""
    from .models import MetricArtifact
    from .production import PRODUCTION_ADAPTER, RequiredEvidenceFrame
    from .rows import EventProcessingDescriptor, RowGeneration

    models = {
        "metric-artifact.schema.json": MetricArtifact.model_json_schema(),
        "event-processing.schema.json": EventProcessingDescriptor.model_json_schema(),
        "evidence-production.schema.json": PRODUCTION_ADAPTER.json_schema(),
        "required-evidence-frame.schema.json": RequiredEvidenceFrame.model_json_schema(),
        "row-generation.schema.json": RowGeneration.model_json_schema(),
    }
    return {
        name: json.dumps(schema, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
        for name, schema in models.items()
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Export structural cited model schemas")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--include-row-profiles", action="store_true")
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    selected = encoded_schemas()
    if args.include_row_profiles:
        selected.update(encoded_row_schemas())
    for name, text in selected.items():
        (args.out / name).write_text(text, encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main()
