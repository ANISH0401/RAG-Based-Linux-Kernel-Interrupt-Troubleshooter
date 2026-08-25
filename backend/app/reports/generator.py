"""Render an engineering incident report from the analysis results."""
from __future__ import annotations

from datetime import UTC, datetime

from app.core.models import Finding, InterruptEvent, IrqCounter, RetrievedDoc, Severity

_SEVERITY_LABEL = {
    Severity.CRITICAL: "CRITICAL",
    Severity.WARNING: "WARNING",
    Severity.INFO: "INFO",
}


def build_report(
    events: list[InterruptEvent],
    counters: list[IrqCounter],
    findings: list[Finding],
    references: list[RetrievedDoc],
    narrative: str,
    llm_backend: str,
) -> str:
    ts = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    out: list[str] = []

    out.append("# Interrupt Incident Report")
    out.append("")
    out.append(f"*Generated {ts} by InterruptGPT (analysis backend: {llm_backend})*")
    out.append("")

    # ---- Summary -------------------------------------------------------
    out.append("## 1. Incident Summary")
    out.append("")
    if findings:
        top = findings[0]
        out.append(
            f"**{top.title}** — {_SEVERITY_LABEL[top.severity]}, "
            f"{top.confidence_pct}% confidence."
        )
        out.append("")
        out.append(
            f"Parsed {len(events)} interrupt-related log event(s) and "
            f"{len(counters)} counter row(s); the rule engine raised "
            f"{len(findings)} finding(s)."
        )
    else:
        out.append("No interrupt anomalies were detected in the supplied data.")
    out.append("")

    # ---- Observed symptoms --------------------------------------------
    out.append("## 2. Observed Symptoms")
    out.append("")
    notable = [e for e in events if e.severity is not Severity.INFO]
    if notable:
        out.append("| Line | IRQ | Event | Message |")
        out.append("|---|---|---|---|")
        for e in notable[:20]:
            msg = e.message.replace("|", "\\|")[:80]
            out.append(
                f"| {e.line_number} | {e.irq if e.irq is not None else '—'} "
                f"| `{e.kind.value}` | {msg} |"
            )
    else:
        out.append("_No warning or critical log events were parsed._")
    out.append("")

    # ---- Root cause ----------------------------------------------------
    out.append("## 3. Root Cause Analysis")
    out.append("")
    if findings:
        out.append("| Root Cause | Severity | Confidence |")
        out.append("|---|---|---|")
        for f in findings:
            out.append(
                f"| {f.title} | {_SEVERITY_LABEL[f.severity]} | {f.confidence_pct}% |"
            )
        out.append("")
    out.append(narrative)
    out.append("")

    # ---- Evidence ------------------------------------------------------
    out.append("## 4. Evidence")
    out.append("")
    if findings:
        for f in findings:
            out.append(f"### {f.title} ({f.confidence_pct}%)")
            for ev in f.evidence:
                out.append(f"- {ev}")
            out.append("")
    else:
        out.append("_No supporting evidence collected._")
        out.append("")

    # ---- Recommended actions ------------------------------------------
    out.append("## 5. Recommended Actions")
    out.append("")
    if findings:
        seen: set[str] = set()
        n = 1
        for f in findings:
            for rec in f.recommendations:
                if rec in seen:
                    continue
                seen.add(rec)
                out.append(f"{n}. {rec}")
                n += 1
    else:
        out.append("_None required._")
    out.append("")

    # ---- Preventive measures ------------------------------------------
    out.append("## 6. Preventive Measures")
    out.append("")
    out.extend(
        [
            "- Sample `/proc/interrupts` on a schedule and alert on per-line rate deltas.",
            "- Prefer MSI/MSI-X for new devices to avoid shared-line classes of failure.",
            "- Track kernel, firmware and BIOS versions alongside incidents; routing changes are a common trigger.",
            "- Capture `dmesg` and `/proc/interrupts` together at incident time — either alone is much weaker evidence.",
        ]
    )
    out.append("")

    # ---- References ----------------------------------------------------
    out.append("## 7. Documentation References")
    out.append("")
    if references:
        for r in references:
            out.append(f"- **{r.title}** — {r.source} (relevance {r.score:.3f})")
    else:
        out.append("_No documentation retrieved._")
    out.append("")

    return "\n".join(out)
