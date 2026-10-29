"""Keyless explicit-input local analysis. Status itself performs no IO."""

import argparse
import json
import time
from pathlib import Path

from firewall_analyst import __version__

MAX_CONFIGURATION_BYTES = 16 * 1024 * 1024


def _configuration_bytes(path: Path, *, max_bytes: int = MAX_CONFIGURATION_BYTES) -> bytes:
    """One bounded local configuration snapshot; never echo source content/errors."""
    if type(max_bytes) is not int or not 0 < max_bytes <= MAX_CONFIGURATION_BYTES:
        raise ValueError("configuration_limit")
    if path.is_symlink() or not path.is_file() or path.stat().st_size > max_bytes:
        raise ValueError("configuration_file_or_limit")
    with path.open("rb") as stream:
        data = stream.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError("configuration_limit")
    return data


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Firewall Traffic Analyst (local deterministic)")
    parser.add_argument("--version", action="version", version=f"fwa {__version__}")
    parser.add_argument("--json", action="store_true", help="Print machine-readable stage status")
    commands = parser.add_subparsers(dest="command")
    analysis = commands.add_parser("analyze", help="Write local observations to a NEW directory")
    analysis.add_argument("input", type=Path)
    analysis.add_argument("--out", type=Path, required=True)
    analysis.add_argument("--internal-cidr", action="append", default=[])
    analysis.add_argument("--as-of-us", type=int, help="Explicit UTC microsecond clock")
    analysis.add_argument("--policy", type=Path, help="Explicit typed policy JSON")
    analysis.add_argument("--contexts", type=Path, help="Explicit typed context JSON array")
    analysis.add_argument(
        "--public-profile",
        type=Path,
        help="Explicit public profile; derive clock/contexts from complete source observations",
    )
    verification = commands.add_parser("verify", help="Recompute artifacts from explicit source")
    verification.add_argument("report_dir", type=Path)
    verification.add_argument("--input", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.command:
        from .pipeline import analyze, analyze_public_profile, verify, write_artifacts

        try:
            if args.command == "verify":
                valid = verify(args.report_dir, input_path=args.input)
                print(json.dumps({"verified": valid, "kind": "local_recomputation"}))
                return 0 if valid else 1
            from pydantic import TypeAdapter

            from .domain.rules.policy import NetworkContextV1, RulePolicyV1

            profile_ref = None
            if args.public_profile is not None:
                if (
                    args.as_of_us is not None
                    or args.internal_cidr
                    or args.policy is not None
                    or args.contexts is not None
                ):
                    raise ValueError("public_profile_conflicts_with_manual_settings")
                from .domain.evaluation.config import PublicEvaluationProfile

                profile = PublicEvaluationProfile.model_validate_json(
                    _configuration_bytes(args.public_profile)
                )
                artifacts, profile_ref = analyze_public_profile(args.input, profile)
            else:
                policy = (
                    RulePolicyV1.model_validate_json(_configuration_bytes(args.policy))
                    if args.policy
                    else None
                )
                contexts = (
                    TypeAdapter(tuple[NetworkContextV1, ...]).validate_json(
                        _configuration_bytes(args.contexts)
                    )
                    if args.contexts
                    else ()
                )
                artifacts = analyze(
                    args.input,
                    as_of_us=args.as_of_us if args.as_of_us is not None else time.time_ns() // 1000,
                    internal_cidrs=tuple(args.internal_cidr),
                    policy=policy,
                    contexts=contexts,
                )
            write_artifacts(args.out, artifacts)
            state = json.loads(artifacts["report.json"])["parse"]["state"]
            output = {"written": True, "parse_state": state, "providers_available": False}
            if profile_ref is not None:
                output["public_profile_content_sha256"] = profile_ref
            print(json.dumps(output))
            return 0 if state in {"complete", "partial"} else 2
        except (OSError, ValueError, TypeError, OverflowError):
            # Do not echo raw exceptions, source lines, paths or credentials.
            print(json.dumps({"written": False, "error": "local_analysis_failed"}))
            return 2
    status = {
        "package": "firewall-traffic-analyst",
        "version": __version__,
        "status": "local_deterministic",
        "contracts_available": True,
        "analysis_available": True,
        "offline_annotation_api_available": True,
        "public_profile_analysis_available": True,
        "evaluation_components_available": True,
        "providers_available": False,
        "live_providers_available": False,
        "message": (
            "Local Zeek parsing, deterministic flags, source-checked observations and reports. "
            "The explicit offline annotation API is available; live providers and quality "
            "evaluation are not available."
        ),
    }
    print(json.dumps(status, sort_keys=True) if args.json else status["message"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
