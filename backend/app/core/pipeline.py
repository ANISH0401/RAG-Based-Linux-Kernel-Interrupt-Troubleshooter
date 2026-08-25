"""End-to-end analysis pipeline."""
from __future__ import annotations

import logging
import urllib.error

from app.analyzer.rules import analyze
from app.core.models import AnalysisRequest, AnalysisResponse
from app.llm.providers import (
    LLMProvider,
    TemplateProvider,
    build_analysis_prompt,
    compose_fallback_narrative,
)
from app.parsers.dmesg_parser import parse_dmesg
from app.parsers.proc_interrupts_parser import parse_proc_interrupts
from app.rag.retriever import KnowledgeBase
from app.reports.generator import build_report

logger = logging.getLogger(__name__)


def run_analysis(
    request: AnalysisRequest,
    kb: KnowledgeBase,
    provider: LLMProvider,
) -> AnalysisResponse:
    events = parse_dmesg(request.dmesg) if request.dmesg else []
    counters = (
        parse_proc_interrupts(request.proc_interrupts)
        if request.proc_interrupts
        else []
    )

    findings = analyze(events, counters)
    references = kb.search_for_findings(findings)

    # If nothing was found but the user asked something, retrieve on the question
    # so the response is still useful rather than empty.
    if not references and request.question:
        references = kb.search(request.question, k=3)

    narrative, backend = _narrate(findings, references, provider, request.question)

    report = build_report(
        events=events,
        counters=counters,
        findings=findings,
        references=references,
        narrative=narrative,
        llm_backend=backend,
    )

    return AnalysisResponse(
        events=events,
        counters=counters,
        findings=findings,
        references=references,
        narrative=narrative,
        report_markdown=report,
        llm_backend=f"{backend} | retrieval: {kb.backend_description}",
    )


def _narrate(findings, references, provider: LLMProvider, question: str | None):
    """Generate the narrative, degrading gracefully if the model is unreachable."""
    if isinstance(provider, TemplateProvider):
        return compose_fallback_narrative(findings, references), "template"

    prompt = build_analysis_prompt(findings, references, question=question)
    try:
        text = provider.generate(prompt)
        if text:
            return text, provider.name
        logger.warning("LLM returned an empty response; using fallback narrative.")
    except (urllib.error.URLError, OSError, TimeoutError, ValueError) as exc:
        logger.warning("LLM generation failed (%s); using fallback narrative.", exc)

    return compose_fallback_narrative(findings, references), "template (llm-fallback)"
