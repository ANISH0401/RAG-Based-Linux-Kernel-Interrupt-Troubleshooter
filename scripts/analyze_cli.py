#!/usr/bin/env python3
"""Command-line interface for InterruptGPT.

Examples
--------
    python scripts/analyze_cli.py --dmesg datasets/sample_logs/dmesg_shared_irq.log \
        --interrupts datasets/sample_logs/interrupts_shared.txt

    python scripts/analyze_cli.py --dmesg dmesg.log --out report.md
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.core.models import AnalysisRequest  # noqa: E402
from app.core.pipeline import run_analysis  # noqa: E402
from app.llm.providers import build_provider  # noqa: E402
from app.rag.retriever import get_knowledge_base  # noqa: E402

SEVERITY_COLOR = {"critical": "\033[31m", "warning": "\033[33m", "info": "\033[32m"}
RESET = "\033[0m"


def read_file(path: str | None) -> str:
    if not path:
        return ""
    return Path(path).read_text(encoding="utf-8", errors="replace")


def main() -> int:
    ap = argparse.ArgumentParser(description="Analyze Linux interrupt logs.")
    ap.add_argument("--dmesg", help="Path to a dmesg/journalctl capture.")
    ap.add_argument("--interrupts", help="Path to a /proc/interrupts capture.")
    ap.add_argument("--question", help="Optional question to answer.")
    ap.add_argument("--out", help="Write the full markdown report to this path.")
    ap.add_argument("--no-color", action="store_true")
    args = ap.parse_args()

    if not args.dmesg and not args.interrupts:
        ap.error("provide --dmesg and/or --interrupts")

    request = AnalysisRequest(
        dmesg=read_file(args.dmesg),
        proc_interrupts=read_file(args.interrupts),
        question=args.question,
    )

    result = run_analysis(request, get_knowledge_base(), build_provider())

    print(f"\nBackend: {result.llm_backend}")
    print(
        f"Parsed {len(result.events)} event(s), {len(result.counters)} counter row(s).\n"
    )

    if not result.findings:
        print("No interrupt anomalies detected.\n")
    for f in result.findings:
        colour = "" if args.no_color else SEVERITY_COLOR.get(f.severity.value, "")
        reset = "" if args.no_color else RESET
        print(f"{colour}[{f.confidence_pct:3d}%] {f.severity.value.upper():8s}{reset} {f.title}")
        for ev in f.evidence:
            print(f"        - {ev}")
        print()

    if result.references:
        print("References:")
        for r in result.references:
            print(f"  - {r.title} ({r.score:.3f})")
        print()

    if args.out:
        Path(args.out).write_text(result.report_markdown, encoding="utf-8")
        print(f"Report written to {args.out}")

    # Non-zero exit when something critical was found, so CI/monitoring can gate.
    return 2 if any(f.severity.value == "critical" for f in result.findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
