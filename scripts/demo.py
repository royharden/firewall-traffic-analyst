"""Keyless synthetic demo. Output must name a new directory; no hidden overwrite."""

import argparse
from pathlib import Path

from firewall_analyst.cli import main

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    raise SystemExit(
        main(
            [
                "analyze",
                str(Path(__file__).resolve().parents[1] / "fixtures/demo/scan.jsonl"),
                "--out",
                str(args.out),
                "--internal-cidr",
                "192.0.2.0/24",
                "--as-of-us",
                "1700000015000000",
            ]
        )
    )
