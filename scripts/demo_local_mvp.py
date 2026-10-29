"""Reproducible local CLI normal/refusal/tamper journey, using only public demo bytes."""

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path


def run(destination: Path) -> dict:
    root = Path(__file__).resolve().parents[1]
    # Exclusive ownership: an existing destination is never reused or cleaned.
    destination.mkdir(parents=True, exist_ok=False)
    source = destination / "supported-patterns.jsonl"

    def row(source_host, destination_host, port, seconds, **extra):
        return {
            "ts": 1_700_000_000 + seconds,
            "id.orig_h": source_host,
            "id.orig_p": 40000,
            "id.resp_h": destination_host,
            "id.resp_p": port,
            "proto": "tcp",
            "uid": "C12345678",
            **extra,
        }

    rows = [row("192.0.2.1", "198.51.100.1", 100 + i, i) for i in range(15)]
    rows += [row("192.0.2.2", f"198.51.100.{i + 1}", 443, i) for i in range(20)]
    rows += [row("192.0.2.3", "198.51.100.3", 443, 100 * i) for i in range(8)]
    rows += [row("192.0.2.4", "203.0.113.4", 4444, 20)]
    rows += [row("192.0.2.5", "198.51.100.5", 443, 20, orig_bytes=11 * 1024 * 1024)]
    rows += [
        row("192.0.2.6", "198.51.100.6", 443, 30 + i, conn_state="REJ" if i < 3 else "SF")
        for i in range(4)
    ]
    source.write_bytes(b"".join(json.dumps(item).encode() + b"\r\n" for item in rows))
    profile = root / "config/evaluation-public-setup.v1.json"

    def cli(name, arguments, expected):
        result = subprocess.run(
            [sys.executable, "-m", "firewall_analyst.cli", *map(str, arguments)],
            cwd=root,
            capture_output=True,
            timeout=120,
        )
        (destination / f"{name}.stdout").write_bytes(result.stdout)
        (destination / f"{name}.stderr").write_bytes(result.stderr)
        if result.returncode != expected:
            raise RuntimeError(f"demo_step_failed:{name}")
        return {
            "arguments": list(map(str, arguments)),
            "exit": result.returncode,
            "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
        }

    normal = destination / "normal"
    steps = [cli("analyze", ["analyze", source, "--out", normal, "--public-profile", profile], 0)]
    steps.append(cli("verify", ["verify", normal, "--input", source], 0))
    refused = destination / "refused"
    steps.append(
        cli(
            "refusal",
            ["analyze", source, "--out", refused, "--public-profile", profile, "--as-of-us", "0"],
            2,
        )
    )
    if refused.exists():
        raise RuntimeError("refusal_created_output")
    malformed = destination / "malformed.jsonl"
    malformed.write_bytes(b"#separator invalid\n#fields missing\n")
    degraded = destination / "malformed-report"
    steps.append(
        cli(
            "malformed",
            ["analyze", malformed, "--out", degraded, "--as-of-us", "1700000700000000"],
            2,
        )
    )
    bad_report = json.loads((degraded / "report.json").read_bytes())
    if bad_report["parse"]["state"] not in {"unsupported", "error"} or bad_report["groups"]:
        raise RuntimeError("malformed_input_not_downgraded")
    # Forge an adjacent manifest too: verification must recompute source-bound bytes.
    tampered = destination / "tampered"
    tampered.mkdir()
    for name in (
        "report.json",
        "report.md",
        "report.html",
        "evidence.json",
        "proposed-rules.txt",
        "manifest.json",
    ):
        (tampered / name).write_bytes((normal / name).read_bytes())
    evidence = json.loads((tampered / "evidence.json").read_bytes())
    entry = evidence["canonical_citations"]["entries"][0]
    entry["production"]["pointer"]["locator"]["quote"] = "forged physical row"
    raw = (json.dumps(evidence, sort_keys=True) + "\n").encode()
    (tampered / "evidence.json").write_bytes(raw)
    manifest = json.loads((tampered / "manifest.json").read_bytes())
    manifest["artifacts"]["evidence.json"] = hashlib.sha256(raw).hexdigest()
    (tampered / "manifest.json").write_text(json.dumps(manifest), encoding="utf8")
    steps.append(cli("tamper", ["verify", tampered, "--input", source], 1))
    report = json.loads((normal / "report.json").read_bytes())
    supported = {"port_scan", "host_sweep", "beaconing", "unusual_outbound", "large_outbound"}
    observed = {item["group"]["rule_id"] for item in report["groups"]}
    if not supported <= observed or report["canonical_citations"]["status"] != "resolved":
        raise RuntimeError("supported_pattern_or_citation_missing")
    if not any(
        item["rule_id"] == "denied_then_allowed" and item["status"] == "unsupported"
        for item in report["channels"]
    ):
        raise RuntimeError("unsupported_policy_action_hidden")
    receipt = {
        "profile": "local-cli-mvp/1",
        "steps": steps,
        "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "groups": len(report["groups"]),
        "citations": report["canonical_citations"],
        "normal_artifacts": {
            p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(normal.iterdir())
        },
        "refusal_output_absent": True,
        "tampered_citation_rejected": True,
        "malformed_input_downgraded": True,
        "observed_rules": sorted(observed),
        "quality_evaluation": "not_run",
        "external_effects": False,
    }
    (destination / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf8")
    return receipt


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    run(args.out.resolve())
    print(json.dumps({"demo_complete": True, "receipt": str(args.out / "receipt.json")}))
