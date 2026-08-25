"""Rule engine that turns parsed events and counters into scored findings.

Confidence is deliberately *evidence-driven* rather than model-generated: each
rule starts at a base confidence and gains a bounded increment per corroborating
signal. This keeps scores reproducible and explainable, which matters more than
precision for a triage tool.
"""
from __future__ import annotations

from collections import defaultdict

from app.core.models import (
    EventKind,
    Finding,
    InterruptEvent,
    IrqCounter,
    Severity,
)

# An IRQ whose total count exceeds this and which dominates overall interrupt
# traffic is treated as a storm *candidate* (see _rule_storm for caveats).
STORM_ABSOLUTE_THRESHOLD = 100_000
STORM_SHARE_THRESHOLD = 0.75
# Ratio between busiest and quietest CPU above which affinity looks imbalanced.
IMBALANCE_RATIO = 20.0
IMBALANCE_MIN_TOTAL = 10_000

# Never report absolute certainty: this is a triage aid, and the evidence is
# always partial (a single log capture, cumulative counters, no hardware access).
MAX_CONFIDENCE = 0.95


def _clamp(value: float) -> float:
    return max(0.0, min(MAX_CONFIDENCE, value))


def analyze(
    events: list[InterruptEvent],
    counters: list[IrqCounter],
) -> list[Finding]:
    """Run all rules and return findings sorted by (severity, confidence)."""
    findings: list[Finding] = []
    findings += _rule_nobody_cared(events, counters)
    findings += _rule_shared_conflict(events, counters)
    findings += _rule_storm(events, counters)
    findings += _rule_affinity_imbalance(counters)
    findings += _rule_msi_failure(events)
    findings += _rule_error_counter(counters)

    order = {Severity.CRITICAL: 0, Severity.WARNING: 1, Severity.INFO: 2}
    findings.sort(key=lambda f: (order[f.severity], -f.confidence))
    return findings


def _actions_for_irq(counters: list[IrqCounter], irq: int | None) -> list[str]:
    if irq is None:
        return []
    for c in counters:
        if c.irq_number == irq:
            return c.actions
    return []


def _rule_nobody_cared(
    events: list[InterruptEvent], counters: list[IrqCounter]
) -> list[Finding]:
    """'nobody cared' means the kernel fired a handler chain and none claimed it."""
    out: list[Finding] = []
    by_irq: dict[int | None, list[InterruptEvent]] = defaultdict(list)
    for e in events:
        if e.kind in (EventKind.NOBODY_CARED, EventKind.IRQ_DISABLED):
            by_irq[e.irq].append(e)

    for irq, evs in by_irq.items():
        kinds = {e.kind for e in evs}
        if EventKind.NOBODY_CARED not in kinds:
            continue

        confidence = 0.62
        evidence = [e.raw_line for e in evs]

        if EventKind.IRQ_DISABLED in kinds:
            confidence += 0.18
            evidence.append("Kernel subsequently disabled the IRQ line.")

        handlers = sorted(
            {e.handler for e in events if e.irq == irq and e.handler}
        )
        drivers = sorted({e.driver for e in events if e.irq == irq and e.driver})
        if handlers:
            confidence += 0.08
            evidence.append(f"Registered handler(s): {', '.join(handlers)}.")

        actions = _actions_for_irq(counters, irq)
        if len(actions) > 1:
            confidence += 0.12
            evidence.append(
                f"/proc/interrupts shows IRQ {irq} shared by: {', '.join(actions)}."
            )

        out.append(
            Finding(
                rule_id="IRQ_NOBODY_CARED",
                title=f"Unhandled interrupt on IRQ {irq} (kernel gave up on the line)",
                severity=Severity.CRITICAL,
                confidence=_clamp(confidence),
                irq=irq,
                drivers=drivers,
                evidence=evidence,
                recommendations=[
                    "Confirm which devices share this line via /proc/interrupts.",
                    "Prefer MSI/MSI-X for the owning device so it gets a private vector.",
                    "Check the driver's IRQ handler returns IRQ_HANDLED when it services the device.",
                    "Update firmware/BIOS if IRQ routing for the slot looks wrong.",
                ],
            )
        )
    return out


def _rule_shared_conflict(
    events: list[InterruptEvent], counters: list[IrqCounter]
) -> list[Finding]:
    """Shared line where at least one participant is misbehaving."""
    out: list[Finding] = []
    troubled = {
        e.irq
        for e in events
        if e.kind
        in (
            EventKind.NOBODY_CARED,
            EventKind.IRQ_DISABLED,
            EventKind.SPURIOUS,
            EventKind.SHARED_CONFLICT,
        )
        and e.irq is not None
    }

    for c in counters:
        irq = c.irq_number
        if irq is None or not c.is_shared:
            continue

        confidence = 0.45
        evidence = [f"IRQ {irq} actions: {', '.join(c.actions)}."]

        if irq in troubled:
            confidence += 0.32
            evidence.append("Log shows unhandled/spurious activity on this line.")
        if c.total > STORM_ABSOLUTE_THRESHOLD:
            confidence += 0.10
            evidence.append(f"High aggregate count: {c.total:,}.")

        # A quiet, healthy shared line is normal on x86 - don't cry wolf.
        if confidence < 0.55:
            continue

        out.append(
            Finding(
                rule_id="IRQ_SHARED_CONFLICT",
                title=f"Shared interrupt conflict on IRQ {irq}",
                severity=Severity.WARNING,
                confidence=_clamp(confidence),
                irq=irq,
                drivers=list(c.actions),
                evidence=evidence,
                recommendations=[
                    "Move one of the devices to MSI/MSI-X to break the sharing.",
                    "Verify each driver registers with IRQF_SHARED and identifies its own device.",
                    "Try a different PCI slot to change ACPI IRQ routing.",
                ],
            )
        )
    return out


def _rule_storm(
    events: list[InterruptEvent], counters: list[IrqCounter]
) -> list[Finding]:
    """Detect interrupt storms.

    Important limitation: /proc/interrupts counters are cumulative since boot, so
    a single sample cannot distinguish a genuine storm from a busy device on a
    long-uptime machine. Only an explicit kernel storm message is treated as
    confirmation; counter dominance alone is reported as a lower-confidence
    *candidate* with that caveat stated in the evidence.
    """
    out: list[Finding] = []
    logged = {e.irq for e in events if e.kind is EventKind.IRQ_STORM and e.irq}

    numeric = [c for c in counters if c.irq_number is not None]
    grand_total = sum(c.total for c in numeric) or 1

    # IRQs mentioned in the log as a storm, even without counter corroboration.
    for irq in sorted(i for i in logged if i is not None):
        counter = next((c for c in numeric if c.irq_number == irq), None)
        share = (counter.total / grand_total) if counter else 0.0
        evidence = ["Kernel explicitly reported an interrupt storm on this line."]
        confidence = 0.80
        if counter:
            evidence.append(
                f"IRQ {irq} total {counter.total:,} interrupts "
                f"({share:.0%} of counted interrupt traffic)."
            )
            if counter.total > STORM_ABSOLUTE_THRESHOLD:
                confidence += 0.10

        out.append(
            Finding(
                rule_id="IRQ_STORM",
                title=f"Interrupt storm on IRQ {irq}",
                severity=Severity.CRITICAL,
                confidence=_clamp(confidence),
                irq=irq,
                drivers=list(counter.actions) if counter else [],
                evidence=evidence,
                recommendations=_STORM_RECOMMENDATIONS,
            )
        )

    # Counter-dominance candidates (unconfirmed).
    for c in numeric:
        irq = c.irq_number
        if irq in logged:
            continue
        share = c.total / grand_total
        if c.total <= STORM_ABSOLUTE_THRESHOLD or share <= STORM_SHARE_THRESHOLD:
            continue

        out.append(
            Finding(
                rule_id="IRQ_STORM_CANDIDATE",
                title=f"Possible high interrupt rate on IRQ {irq} (unconfirmed)",
                severity=Severity.WARNING,
                confidence=_clamp(0.35 + min(share - STORM_SHARE_THRESHOLD, 0.2)),
                irq=irq,
                drivers=list(c.actions),
                evidence=[
                    f"IRQ {irq} accounts for {share:.0%} of counted interrupts "
                    f"({c.total:,} total).",
                    "Counters are cumulative since boot, so this alone cannot "
                    "confirm a storm - sample /proc/interrupts twice and compare "
                    "the delta to measure the actual rate.",
                ],
                recommendations=[
                    "Sample /proc/interrupts ~1s apart and compute the per-line delta.",
                    *_STORM_RECOMMENDATIONS,
                ],
            )
        )
    return out


_STORM_RECOMMENDATIONS = [
    "Check whether the device's interrupt status register is being cleared.",
    "Enable interrupt coalescing/moderation if the driver supports it.",
    "For NICs, verify NAPI polling is active under load.",
    "Test with a newer driver or firmware revision.",
]


def _rule_affinity_imbalance(counters: list[IrqCounter]) -> list[Finding]:
    """A busy IRQ pinned to a single CPU while others idle."""
    out: list[Finding] = []
    for c in counters:
        irq = c.irq_number
        if irq is None or len(c.per_cpu_counts) < 2:
            continue
        if c.total < IMBALANCE_MIN_TOTAL:
            continue

        busiest = max(c.per_cpu_counts)
        quietest = min(c.per_cpu_counts)
        if busiest == 0:
            continue
        ratio = busiest / max(quietest, 1)
        if ratio < IMBALANCE_RATIO:
            continue

        cpu = c.per_cpu_counts.index(busiest)
        confidence = _clamp(0.5 + min(ratio / 200.0, 0.3))

        out.append(
            Finding(
                rule_id="IRQ_AFFINITY_IMBALANCE",
                title=f"IRQ {irq} traffic concentrated on CPU{cpu}",
                severity=Severity.WARNING,
                confidence=confidence,
                irq=irq,
                drivers=list(c.actions),
                evidence=[
                    f"Per-CPU counts: {c.per_cpu_counts}.",
                    f"CPU{cpu} handles {busiest:,} vs minimum {quietest:,} "
                    f"(ratio {ratio:.0f}x).",
                ],
                recommendations=[
                    f"Inspect /proc/irq/{irq}/smp_affinity_list for a narrow mask.",
                    "Enable irqbalance, or pin deliberately if this is intentional tuning.",
                    "For multi-queue devices, confirm all queues have vectors assigned.",
                ],
            )
        )
    return out


def _rule_msi_failure(events: list[InterruptEvent]) -> list[Finding]:
    """MSI/MSI-X allocation failed and the device fell back to legacy INTx."""
    msi = [e for e in events if e.kind is EventKind.MSI_FAILURE]
    if not msi:
        return []

    drivers = sorted({e.driver for e in msi if e.driver})
    return [
        Finding(
            rule_id="MSI_ALLOCATION_FAILURE",
            title="MSI/MSI-X setup failed; device likely fell back to legacy INTx",
            severity=Severity.WARNING,
            confidence=_clamp(0.55 + 0.08 * len(msi)),
            irq=next((e.irq for e in msi if e.irq is not None), None),
            drivers=drivers,
            evidence=[e.raw_line for e in msi],
            recommendations=[
                "Confirm the platform is not booted with pci=nomsi.",
                "Check BIOS/UEFI settings for MSI support on the slot.",
                "Verify vector exhaustion is not occurring (dmesg for 'no free vectors').",
                "Legacy INTx is shared, so expect knock-on sharing conflicts.",
            ],
        )
    ]


def _rule_error_counter(counters: list[IrqCounter]) -> list[Finding]:
    """A non-zero ERR counter indicates spurious/unroutable interrupts."""
    for c in counters:
        if c.irq.upper() != "ERR" or c.total == 0:
            continue
        return [
            Finding(
                rule_id="APIC_ERROR_COUNTER",
                title=f"Non-zero APIC ERR counter ({c.total:,})",
                severity=Severity.WARNING,
                confidence=_clamp(0.45 + min(c.total / 1000.0, 0.25)),
                irq=None,
                drivers=[],
                evidence=[f"ERR counter total: {c.total:,}."],
                recommendations=[
                    "Non-zero ERR often accompanies spurious or misrouted interrupts.",
                    "Correlate with 'nobody cared' or spurious messages in dmesg.",
                    "Check for firmware ACPI/IRQ routing errata for this platform.",
                ],
            )
        ]
    return []
