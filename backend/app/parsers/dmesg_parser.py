"""Parse unstructured kernel logs (dmesg / journalctl / syslog) into events."""
from __future__ import annotations

import re

from app.core.models import EventKind, InterruptEvent, Severity

# [ 1234.567890 ] or [1234.567890] boot-time prefix
_TS = re.compile(r"^\s*\[\s*(\d+\.\d+)\s*\]\s*")
# journalctl / syslog prefix: "Mar 14 09:12:01 host kernel: ..."
_SYSLOG = re.compile(
    r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+kernel:\s*", re.IGNORECASE
)

_HANDLER = re.compile(r"\[<[0-9a-fx]+>\]\s*([A-Za-z_][\w.]*)", re.IGNORECASE)
_IRQ_HASH = re.compile(r"IRQ\s*#?\s*(\d+)", re.IGNORECASE)
_IRQ_COLON = re.compile(r"\birq\s+(\d+)\b", re.IGNORECASE)


def _strip_prefix(line: str) -> tuple[str, float | None]:
    """Remove timestamp/syslog prefixes, returning (body, seconds_since_boot)."""
    ts: float | None = None
    body = _SYSLOG.sub("", line)
    m = _TS.match(body)
    if m:
        ts = float(m.group(1))
        body = body[m.end():]
    return body.strip(), ts


def _extract_irq(text: str) -> int | None:
    for pattern in (_IRQ_HASH, _IRQ_COLON):
        m = pattern.search(text)
        if m:
            return int(m.group(1))
    return None


def _classify(body: str) -> tuple[EventKind, Severity]:
    low = body.lower()
    if "nobody cared" in low:
        return EventKind.NOBODY_CARED, Severity.CRITICAL
    if "disabling irq" in low or "irq disabled" in low:
        return EventKind.IRQ_DISABLED, Severity.CRITICAL
    if "interrupt storm" in low or "irq storm" in low:
        return EventKind.IRQ_STORM, Severity.CRITICAL
    if "spurious" in low:
        return EventKind.SPURIOUS, Severity.WARNING
    if "affinity" in low and ("mismatch" in low or "cannot" in low or "fail" in low):
        return EventKind.AFFINITY_MISMATCH, Severity.WARNING
    if "msi" in low and ("fail" in low or "error" in low or "disabl" in low):
        return EventKind.MSI_FAILURE, Severity.WARNING
    if "shared" in low and "interrupt" in low:
        return EventKind.SHARED_CONFLICT, Severity.WARNING
    return EventKind.UNKNOWN, Severity.INFO


def parse_dmesg(text: str) -> list[InterruptEvent]:
    """Extract interrupt-relevant events from raw kernel log text.

    Handler continuation lines (``[<ffffffff...>] ahci_interrupt``) are attached
    to the most recent event, because the kernel emits them as a block following
    the triggering message rather than as standalone events.
    """
    events: list[InterruptEvent] = []
    last_irq: int | None = None

    for idx, raw in enumerate(text.splitlines(), start=1):
        if not raw.strip():
            continue
        body, ts = _strip_prefix(raw)
        if not body:
            continue

        handler_match = _HANDLER.search(body)

        # Continuation line listing a handler symbol for the previous event.
        if handler_match and not _extract_irq(body):
            symbol = handler_match.group(1)
            if events:
                target = events[-1]
                target.handler = symbol
                if not target.driver:
                    target.driver = _driver_from_handler(symbol)
            events.append(
                InterruptEvent(
                    kind=EventKind.HANDLER_REGISTERED,
                    irq=last_irq,
                    handler=symbol,
                    driver=_driver_from_handler(symbol),
                    message=f"Handler {symbol} attached",
                    raw_line=raw.strip(),
                    line_number=idx,
                    timestamp=ts,
                    severity=Severity.INFO,
                )
            )
            continue

        kind, severity = _classify(body)
        irq = _extract_irq(body)
        if irq is not None:
            last_irq = irq

        # Skip lines that mention no IRQ and match no known pattern.
        if kind is EventKind.UNKNOWN and irq is None:
            continue

        driver = None
        if handler_match:
            driver = _driver_from_handler(handler_match.group(1))

        events.append(
            InterruptEvent(
                kind=kind,
                irq=irq,
                driver=driver,
                handler=handler_match.group(1) if handler_match else None,
                message=body,
                raw_line=raw.strip(),
                line_number=idx,
                timestamp=ts,
                severity=severity,
            )
        )

    return events


def _driver_from_handler(symbol: str) -> str:
    """Best-effort driver name from a handler symbol (``ahci_interrupt`` -> ``ahci``)."""
    for suffix in ("_interrupt", "_irq_handler", "_handler", "_isr", "_irq"):
        if symbol.endswith(suffix):
            return symbol[: -len(suffix)]
    return symbol
