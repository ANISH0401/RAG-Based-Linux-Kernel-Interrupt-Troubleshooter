"""InterruptGPT FastAPI application."""
from __future__ import annotations

import logging

from fastapi import Depends, FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware

from app.analyzer.rules import analyze
from app.core.models import (
    AnalysisRequest,
    AnalysisResponse,
    ChatRequest,
    ChatResponse,
    RetrievedDoc,
)
from app.core.pipeline import run_analysis
from app.llm.providers import LLMProvider, answer_question, build_provider
from app.parsers.dmesg_parser import parse_dmesg
from app.parsers.proc_interrupts_parser import parse_proc_interrupts
from app.rag.retriever import KnowledgeBase, get_knowledge_base

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)

MAX_UPLOAD_BYTES = 8 * 1024 * 1024  # 8 MB per file

app = FastAPI(
    title="InterruptGPT",
    version="1.0.0",
    description=(
        "RAG-based troubleshooting assistant for Linux kernel interrupt issues. "
        "Parses dmesg and /proc/interrupts, applies a deterministic rule engine, "
        "retrieves relevant kernel documentation, and produces a root-cause report."
    ),
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

_provider: LLMProvider | None = None


def get_provider() -> LLMProvider:
    global _provider
    if _provider is None:
        _provider = build_provider()
    return _provider


def get_kb() -> KnowledgeBase:
    return get_knowledge_base()


@app.get("/health", tags=["system"])
def health() -> dict:
    """Liveness probe plus a view of which backends resolved."""
    kb = get_kb()
    return {
        "status": "ok",
        "llm_backend": get_provider().name,
        "retrieval_backend": kb.backend_description,
        "documents_indexed": len(kb.docs),
    }


@app.post("/api/analyze", response_model=AnalysisResponse, tags=["analysis"])
def analyze_endpoint(
    request: AnalysisRequest,
    kb: KnowledgeBase = Depends(get_kb),
    provider: LLMProvider = Depends(get_provider),
) -> AnalysisResponse:
    """Analyse pasted log text and return findings, references and a report."""
    if not request.dmesg.strip() and not request.proc_interrupts.strip():
        raise HTTPException(
            status_code=422,
            detail="Provide at least one of 'dmesg' or 'proc_interrupts'.",
        )
    return run_analysis(request, kb, provider)


@app.post("/api/analyze/upload", response_model=AnalysisResponse, tags=["analysis"])
async def analyze_upload(
    dmesg_file: UploadFile | None = File(default=None),
    interrupts_file: UploadFile | None = File(default=None),
    question: str | None = Form(default=None),
    kb: KnowledgeBase = Depends(get_kb),
    provider: LLMProvider = Depends(get_provider),
) -> AnalysisResponse:
    """Same as /api/analyze but accepts uploaded files."""
    if dmesg_file is None and interrupts_file is None:
        raise HTTPException(status_code=422, detail="Upload at least one file.")

    dmesg_text = await _read_upload(dmesg_file)
    interrupts_text = await _read_upload(interrupts_file)

    return run_analysis(
        AnalysisRequest(
            dmesg=dmesg_text,
            proc_interrupts=interrupts_text,
            question=question,
        ),
        kb,
        provider,
    )


@app.post("/api/chat", response_model=ChatResponse, tags=["analysis"])
def chat_endpoint(
    request: ChatRequest,
    kb: KnowledgeBase = Depends(get_kb),
    provider: LLMProvider = Depends(get_provider),
) -> ChatResponse:
    """Free-form question answering, optionally grounded in uploaded logs."""
    if not request.question.strip():
        raise HTTPException(status_code=422, detail="Question must not be empty.")

    events = parse_dmesg(request.dmesg) if request.dmesg else []
    counters = (
        parse_proc_interrupts(request.proc_interrupts)
        if request.proc_interrupts
        else []
    )
    findings = analyze(events, counters)

    references = kb.search(request.question, k=3)
    if findings:
        for doc in kb.search_for_findings(findings, k_per_finding=1, limit=2):
            if all(d.doc_id != doc.doc_id for d in references):
                references.append(doc)

    answer = answer_question(provider, request.question, findings, references)
    return ChatResponse(
        answer=answer, references=references, llm_backend=provider.name
    )


@app.get("/api/search", response_model=list[RetrievedDoc], tags=["knowledge"])
def search_endpoint(
    q: str,
    k: int = 5,
    kb: KnowledgeBase = Depends(get_kb),
) -> list[RetrievedDoc]:
    """Semantic search across the indexed kernel documentation."""
    if not q.strip():
        raise HTTPException(status_code=422, detail="Query must not be empty.")
    return kb.search(q, k=max(1, min(k, 20)))


async def _read_upload(upload: UploadFile | None) -> str:
    if upload is None:
        return ""
    raw = await upload.read()
    if len(raw) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"{upload.filename} exceeds the {MAX_UPLOAD_BYTES // (1024*1024)} MB limit.",
        )
    return raw.decode("utf-8", errors="replace")
