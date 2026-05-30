#!/usr/bin/env python3
"""
Run Tiber, OpenSSL, and OpenSSL (no HW extensions) AES-128-CBC benchmarks
and write throughput results (KB/s) to a CSV file.

Usage:
    python benchmark_compare.py [--output results.csv] [--tiber-bin path/to/tiber-bench] [--seconds N]
"""

import argparse
import csv
import os
import platform
import re
import subprocess
import sys
from pathlib import Path

BLOCK_SIZES: list[int] = [16, 64, 256, 1024, 8192, 16384]
# OPENSSL_armcap=0x0 disables ARM crypto extensions (AES-NI equivalent on ARM).
# On x86 use OPENSSL_ia32cap instead.
NO_HW_ENV: dict[str, str] = {"OPENSSL_armcap": "0x0"}


def run(label: str, cmd: list[str], extra_env: dict[str, str] | None = None) -> str:
    """Run *cmd*, stream its stdout to the terminal, and return the full output."""
    print(f"\n--- {label} ---", flush=True)
    env = {**os.environ, **(extra_env or {})}
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
    lines: list[str] = []
    assert proc.stdout is not None
    for line in proc.stdout:
        sys.stdout.write(line)
        sys.stdout.flush()
        lines.append(line)
    proc.wait()
    if proc.returncode != 0:
        assert proc.stderr is not None
        sys.stderr.write(proc.stderr.read())
        sys.exit(f"error: {' '.join(cmd)} exited with code {proc.returncode}")
    return "".join(lines)


def parse_throughputs(output: str) -> list[float]:
    """
    Extract the six KB/s throughput values from the AES-128-CBC results line.

    Matches values formatted as '617621.04k' or '617621.04' (k suffix optional).
    The line looks like:
        AES-128-CBC     617621.04k  1425610.54k  ...
    """
    for line in output.splitlines():
        if line.strip().startswith("AES-128-CBC") and not line.strip().startswith("AES-128-CBC ops"):
            values = re.findall(r"(\d+\.\d+)k?", line)
            if len(values) == len(BLOCK_SIZES):
                return [float(v) for v in values]
    raise ValueError(f"AES-128-CBC results line not found in output:\n{output}")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--tiber-bin",
        default=str(Path(__file__).parent.parent / "target" / "release" / "tiber-bench"),
        metavar="PATH",
        help="path to tiber-bench binary (default: target/release/tiber-bench)",
    )
    parser.add_argument(
        "--output",
        default="benchmark_results.csv",
        metavar="PATH",
        help="output CSV file (default: benchmark_results.csv)",
    )
    parser.add_argument(
        "--seconds",
        type=int,
        default=3,
        metavar="N",
        help="seconds to run each block size (default: 3)",
    )
    args = parser.parse_args()
    if not platform.machine().startswith("arm"):
        sys.exit(f"error: ARM platform required (OPENSSL_armcap); detected {platform.machine()}")
    tiber_bin = Path(args.tiber_bin)
    if not tiber_bin.exists():
        sys.exit(
            f"error: {tiber_bin} not found\n"
            "       run `cargo build --release --bin tiber-bench` first"
        )
    openssl_cmd = ["openssl", "speed", "-seconds", str(args.seconds), "-evp", "aes-128-cbc"]
    benchmarks: list[tuple[str, list[str], dict[str, str] | None]] = [
        ("tiber",          [str(tiber_bin), "--seconds", str(args.seconds)], None),
        ("openssl-no-ext", openssl_cmd,                                       NO_HW_ENV),
        ("openssl",        openssl_cmd,                                       None),
    ]
    header = ["implementation"] + [f"{s} bytes" for s in BLOCK_SIZES]
    rows: list[list[str]] = []
    throughput_map: dict[str, list[float]] = {}
    for label, cmd, extra_env in benchmarks:
        output = run(label, cmd, extra_env)
        throughputs = parse_throughputs(output)
        rows.append([label] + [f"{tp:.2f}" for tp in throughputs])
        throughput_map[label] = throughputs

    def ratio_row(label: str, a: str, b: str) -> list[str]:
        return [label] + [f"{ta / tb:.1f}x" for ta, tb in zip(throughput_map[a], throughput_map[b])]

    rows.append(ratio_row("openssl-no-ext / tiber", "openssl-no-ext", "tiber"))
    rows.append(ratio_row("openssl / tiber",        "openssl",        "tiber"))
    with open(args.output, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(rows)
    print(f"\nResults written to {args.output}")


if __name__ == "__main__":
    main()
