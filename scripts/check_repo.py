"""Small repository guard: inspect Git-selected product files, never secret stores."""

import argparse
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATTERNS = {
    "provider_token": re.compile(rb"\bsk-[A-Za-z0-9_-]{20,}\b"),
    "github_token": re.compile(rb"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    "aws_access_id": re.compile(rb"\bAKIA[A-Z0-9]{16}\b"),
    "private_key": re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
}
PRIVATE_PARTS = {".creds", ".chatexports", ".thinking", ".agent-registry", ".agent-work"}


def hits(content: bytes) -> set[str]:
    return {label for label, pattern in PATTERNS.items() if pattern.search(content)}


def self_test() -> None:
    controls = {
        "provider_token": b"sk-" + b"A" * 24,
        "github_token": b"ghp_" + b"A" * 36,
        "aws_access_id": b"AKIA" + b"A" * 16,
        "private_key": b"-----BEGIN " + b"PRIVATE KEY-----",
    }
    for label, content in controls.items():
        if label not in hits(content):
            raise AssertionError(f"Missing positive control: {label}")
    if hits(b"OPENAI_API_KEY is a variable name, not a credential"):
        raise AssertionError("Variable-name negative control falsely matched")
    print(f"guard controls: {len(controls)} positive, 1 negative passed")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--staged", action="store_true", help="Scan index content for pre-commit")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    command = (
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z"]
        if args.staged
        else ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"]
    )
    raw = subprocess.run(command, cwd=ROOT, check=True, capture_output=True).stdout
    names = sorted(set(part.decode("utf-8") for part in raw.split(b"\0") if part))
    findings = []
    for name in names:
        relative = Path(name)
        if (
            relative.is_absolute()
            or ".." in relative.parts
            or PRIVATE_PARTS.intersection(relative.parts)
            or (relative.name.startswith(".env") and relative.name != ".env.example")
        ):
            findings.append((name, "private_or_unsafe_path"))
            continue
        target = ROOT / relative
        if target.is_symlink() or not target.resolve().is_relative_to(ROOT):
            findings.append((name, "linked_or_escaped_path"))
            continue
        if args.staged:
            content = subprocess.run(
                ["git", "show", f":{name}"], cwd=ROOT, check=True, capture_output=True
            ).stdout
        else:
            content = target.read_bytes()
        findings.extend((name, label) for label in sorted(hits(content)))
    for name, label in findings:
        print(f"blocked: {name} ({label})")  # Never print matched secret bytes.
    print(f"guard scan: {len(names)} files, {len(findings)} findings")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
