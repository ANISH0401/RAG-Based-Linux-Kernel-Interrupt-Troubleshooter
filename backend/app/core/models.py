"""Domain models shared across parsing, analysis, RAG and reporting."""
from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class Severity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class EventKind(str, Enum):
    """Classes of interrupt-related events we recognise in kernel logs."""

    NOBODY_CARED = "nobody_cared"
    IRQ_DISABLED = "irq_disabled"
    IRQ_STORM = "irq_storm"
    SPURIOUS = "spurious"
    AFFINITY_MISMATCH = "affinity_mismatch"
    MSI_FAILURE = "msi_failure"
    SHARED_CONFLICT = "shared_conflict"
    HANDLER_REGISTERED = "handler_registered"
    UNKNOWN = "unknown"


class InterruptEvent(BaseModel):
    """A single structured event extracted from an unstructured log line."""

    kind: EventKind = EventKind.UNKNOWN
    irq: int | None = None
    driver: str | None = None
    handler: str | None = None
    message: str = ""
    raw_line: str = ""
    line_number: int = 0
    timestamp: float | None = Field(
        default=None, description="Seconds since boot, from the [ 123.456 ] prefix."
    )
    severity: Severity = Severity.INFO


class IrqCounter(BaseModel):
    """One row of /proc/interrupts."""

    irq: str
    per_cpu_counts: list[int] = Field(default_factory=list)
    chip: str | None = None
    kind: str | None = None
    actions: list[str] = Field(default_factory=list)

    @property
    def total(self) -> int:
        return sum(self.per_cpu_counts)

    @property
    def is_shared(self) -> bool:
        return len(self.actions) > 1

    @property
    def irq_number(self) -> int | None:
        try:
            return int(self.irq)
        except (TypeError, ValueError):
            return None


class Finding(BaseModel):
    """A diagnosed problem produced by the rule engine."""

    rule_id: str
    title: str
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    irq: int | None = None
    drivers: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)

    @property
    def confidence_pct(self) -> int:
        return round(self.confidence * 100)


class RetrievedDoc(BaseModel):
    doc_id: str
    title: str
    source: str
    score: float
    excerpt: str


class AnalysisRequest(BaseModel):
    dmesg: str = Field(default="", description="Raw dmesg/journalctl text.")
    proc_interrupts: str = Field(default="", description="Raw /proc/interrupts text.")
    question: str | None = None


class AnalysisResponse(BaseModel):
    events: list[InterruptEvent]
    counters: list[IrqCounter]
    findings: list[Finding]
    references: list[RetrievedDoc]
    narrative: str
    report_markdown: str
    llm_backend: str


class ChatRequest(BaseModel):
    question: str
    dmesg: str = ""
    proc_interrupts: str = ""


class ChatResponse(BaseModel):
    answer: str
    references: list[RetrievedDoc]
    llm_backend: str
