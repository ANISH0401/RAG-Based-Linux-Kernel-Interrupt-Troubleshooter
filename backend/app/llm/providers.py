"""LLM providers.

Two backends are supported:

* ``OllamaProvider``  - talks to a local Ollama server (Llama 3 by default).
* ``TemplateProvider`` - a deterministic, dependency-free generator.

The template provider exists so the product still returns a useful, grounded
answer when no model is reachable, and so tests are deterministic. It composes
its output strictly from rule-engine findings and retrieved documents, so it
never asserts anything the evidence does not support.
"""
from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
from typing import Protocol

from app.core.models import Finding, RetrievedDoc

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = (
    "You are a Linux kernel interrupt-handling expert helping an engineer triage "
    "an issue. Ground every claim in the supplied findings and documentation "
    "excerpts. If the evidence is insufficient, say so explicitly rather than "
    "speculating. Be concise and specific; prefer concrete commands and file "
    "paths. Never invent IRQ numbers, driver names, or counter values."
)


class LLMProvider(Protocol):
    name: str

    def generate(self, prompt: str) -> str: ...


class OllamaProvider:
    """Minimal Ollama client using only the standard library."""

    def __init__(
        self,
        model: str | None = None,
        host: str | None = None,
        timeout: float = 60.0,
    ) -> None:
        self.model = model or os.getenv("OLLAMA_MODEL", "llama3")
        self.host = (host or os.getenv("OLLAMA_HOST", "http://localhost:11434")).rstrip("/")
        self.timeout = timeout
        self.name = f"ollama:{self.model}"

    def available(self) -> bool:
        try:
            with urllib.request.urlopen(f"{self.host}/api/tags", timeout=2.0) as resp:
                return resp.status == 200
        except Exception:  # noqa: BLE001
            return False

    def generate(self, prompt: str) -> str:
        payload = json.dumps(
            {
                "model": self.model,
                "prompt": prompt,
                "system": SYSTEM_PROMPT,
                "stream": False,
                "options": {"temperature": 0.2},
            }
        ).encode("utf-8")
        req = urllib.request.Request(
            f"{self.host}/api/generate",
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        return body.get("response", "").strip()


class TemplateProvider:
    """Deterministic fallback that assembles prose from structured evidence."""

    name = "template"

    def generate(self, prompt: str) -> str:  # pragma: no cover - unused directly
        return prompt


def build_provider() -> LLMProvider:
    """Return Ollama if reachable, else the deterministic template provider."""
    if os.getenv("INTERRUPTGPT_DISABLE_LLM") == "1":
        return TemplateProvider()
    ollama = OllamaProvider()
    if ollama.available():
        logger.info("Using Ollama backend: %s", ollama.name)
        return ollama
    logger.info("Ollama unreachable; using deterministic template backend.")
    return TemplateProvider()


# --------------------------------------------------------------------------
# Prompt construction and grounded fallback narrative
# --------------------------------------------------------------------------

def build_analysis_prompt(
    findings: list[Finding],
    references: list[RetrievedDoc],
    question: str | None = None,
) -> str:
    parts = ["## Findings from the deterministic rule engine\n"]
    if findings:
        for f in findings:
            parts.append(
                f"- [{f.rule_id}] {f.title} "
                f"(severity={f.severity.value}, confidence={f.confidence_pct}%)"
            )
            for ev in f.evidence:
                parts.append(f"    evidence: {ev}")
    else:
        parts.append("- No interrupt anomalies were detected by the rules.")

    parts.append("\n## Retrieved documentation\n")
    for ref in references:
        parts.append(f"### {ref.title} ({ref.source})\n{ref.excerpt}\n")

    parts.append("\n## Task\n")
    if question:
        parts.append(f"Answer the engineer's question: {question}")
    else:
        parts.append(
            "Write a short root-cause analysis: what happened, why, and the "
            "single highest-value next action."
        )
    return "\n".join(parts)


def compose_fallback_narrative(
    findings: list[Finding], references: list[RetrievedDoc]
) -> str:
    """Grounded narrative used when no generative model is available."""
    if not findings:
        return (
            "No interrupt anomalies were detected in the supplied data. The parser "
            "found no unhandled-interrupt, storm, or MSI-failure signatures, and no "
            "counter pattern crossed the analyzer's thresholds. If you are chasing a "
            "specific symptom, capture /proc/interrupts twice a few seconds apart and "
            "compare the deltas, since cumulative counters alone rarely show the issue."
        )

    top = findings[0]
    lines: list[str] = []
    lines.append(
        f"The most likely root cause is **{top.title}** "
        f"(confidence {top.confidence_pct}%, severity {top.severity.value})."
    )

    if top.evidence:
        lines.append("\nThis is supported by:")
        lines.extend(f"- {ev}" for ev in top.evidence)

    if top.drivers:
        lines.append(
            f"\nDrivers implicated on this line: {', '.join(top.drivers)}."
        )

    if top.recommendations:
        lines.append("\nRecommended next steps, highest value first:")
        lines.extend(
            f"{i}. {rec}" for i, rec in enumerate(top.recommendations, start=1)
        )

    others = findings[1:]
    if others:
        lines.append("\nSecondary findings worth reviewing:")
        lines.extend(
            f"- {f.title} ({f.confidence_pct}% confidence)" for f in others
        )

    if references:
        lines.append(
            "\nRelevant background: "
            + "; ".join(f"{r.title}" for r in references[:3])
            + "."
        )

    lines.append(
        "\n_Generated without a language model. Start Ollama and set OLLAMA_HOST "
        "for narrative synthesis; findings and confidence scores above are produced "
        "by the deterministic rule engine either way._"
    )
    return "\n".join(lines)


def answer_question(
    provider: LLMProvider,
    question: str,
    findings: list[Finding],
    references: list[RetrievedDoc],
) -> str:
    """Answer a free-form question, falling back to grounded extraction."""
    if not isinstance(provider, TemplateProvider):
        prompt = build_analysis_prompt(findings, references, question=question)
        try:
            return provider.generate(prompt)
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            logger.warning("LLM call failed (%s); falling back.", exc)

    # Grounded fallback: surface the most relevant retrieved passages.
    if not references:
        return (
            "No indexed documentation matched that question, and no language model "
            "is currently available to reason about it. Try rephrasing using kernel "
            "terminology (for example 'shared IRQ', 'MSI', 'affinity')."
        )

    parts = ["Based on the indexed kernel documentation:\n"]
    for ref in references[:3]:
        parts.append(f"**{ref.title}**\n{ref.excerpt}\n")
    if findings:
        parts.append(
            "Relevant to your uploaded data: "
            + "; ".join(f"{f.title} ({f.confidence_pct}%)" for f in findings[:3])
            + "."
        )
    return "\n".join(parts)
