"""Parse the /proc/interrupts table into structured counters."""
from __future__ import annotations

import re

from app.core.models import IrqCounter

_CPU_HEADER = re.compile(r"^\s*(CPU\d+\s*)+$")


def parse_proc_interrupts(text: str) -> list[IrqCounter]:
    """Parse /proc/interrupts.

    Format is::

               CPU0       CPU1
      16:      12345      67  IO-APIC   16-fasteoi   ahci, eth0
     NMI:          0       0  Non-maskable interrupts

    The number of CPU columns is taken from the header when present; otherwise it
    is inferred from the leading run of integers on each row. Non-numeric IRQ
    labels (NMI, LOC, ERR...) are kept, since counters like ERR are diagnostic.
    """
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if not lines:
        return []

    n_cpus: int | None = None
    start = 0
    if _CPU_HEADER.match(lines[0]):
        n_cpus = len(lines[0].split())
        start = 1

    counters: list[IrqCounter] = []
    for line in lines[start:]:
        if ":" not in line:
            continue
        label, _, remainder = line.partition(":")
        label = label.strip()
        if not label:
            continue

        tokens = remainder.split()
        counts: list[int] = []
        limit = n_cpus if n_cpus is not None else len(tokens)
        for tok in tokens[:limit]:
            if _is_int(tok):
                counts.append(int(tok))
            else:
                break

        rest = tokens[len(counts):]
        chip = rest[0] if rest else None
        kind = rest[1] if len(rest) > 1 else None

        # Trailing action list may be comma-separated across tokens.
        actions: list[str] = []
        if len(rest) > 2:
            actions = [
                a.strip()
                for a in " ".join(rest[2:]).split(",")
                if a.strip()
            ]

        counters.append(
            IrqCounter(
                irq=label,
                per_cpu_counts=counts,
                chip=chip,
                kind=kind,
                actions=actions,
            )
        )

    return counters


def _is_int(token: str) -> bool:
    try:
        int(token)
        return True
    except ValueError:
        return False
