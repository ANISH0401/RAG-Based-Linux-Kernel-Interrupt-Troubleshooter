"""Retrieval layer: loads the knowledge base, indexes it, and serves queries."""
from __future__ import annotations

import json
import logging
from functools import lru_cache
from pathlib import Path

from app.core.models import Finding, RetrievedDoc
from app.rag.embeddings import build_embedder
from app.rag.vector_store import build_index

logger = logging.getLogger(__name__)

DEFAULT_KB_PATH = (
    Path(__file__).resolve().parents[3] / "datasets" / "kernel_docs" / "knowledge_base.json"
)

# Findings map to knowledge-base tags so retrieval is steered by what the rule
# engine actually found, not just by raw log text.
RULE_TAG_HINTS: dict[str, list[str]] = {
    "IRQ_NOBODY_CARED": ["nobody cared", "spurious interrupt", "shared interrupt"],
    "IRQ_SHARED_CONFLICT": ["shared interrupt", "IRQF_SHARED", "MSI"],
    "IRQ_STORM": ["interrupt storm", "coalescing", "NAPI"],
    "IRQ_STORM_CANDIDATE": ["interrupt storm", "proc interrupts counters", "coalescing"],
    "IRQ_AFFINITY_IMBALANCE": ["smp affinity", "irqbalance"],
    "MSI_ALLOCATION_FAILURE": ["MSI MSI-X vectors", "legacy INTx"],
    "APIC_ERROR_COUNTER": ["proc interrupts ERR counter", "spurious"],
}


class KnowledgeBase:
    """Embeds a document collection and answers similarity queries."""

    def __init__(self, docs: list[dict], prefer_semantic: bool = True) -> None:
        if not docs:
            raise ValueError("Knowledge base is empty.")
        self.docs = docs
        self.embedder = build_embedder(prefer_semantic=prefer_semantic)

        corpus = [self._doc_text(d) for d in docs]
        self.embedder.fit(corpus)
        vectors = self.embedder.encode(corpus)

        self.index = build_index(vectors.shape[1])
        self.index.add(vectors)
        logger.info(
            "Indexed %d docs (embedder=%s, index=%s).",
            len(docs),
            self.embedder.name,
            self.index.backend,
        )

    @staticmethod
    def _doc_text(doc: dict) -> str:
        tags = " ".join(doc.get("tags", []))
        return f"{doc.get('title', '')}. {tags}. {doc.get('text', '')}"

    @property
    def backend_description(self) -> str:
        return f"{self.embedder.name} + {self.index.backend}"

    def search(self, query: str, k: int = 3) -> list[RetrievedDoc]:
        if not query.strip():
            return []
        vector = self.embedder.encode([query])
        scores, indices = self.index.search(vector, k)
        results: list[RetrievedDoc] = []
        for score, idx in zip(scores[0], indices[0], strict=False):
            if idx < 0:
                continue
            doc = self.docs[int(idx)]
            results.append(
                RetrievedDoc(
                    doc_id=doc["doc_id"],
                    title=doc["title"],
                    source=doc.get("source", "knowledge base"),
                    score=round(float(score), 4),
                    excerpt=_excerpt(doc["text"]),
                )
            )
        return results

    def search_for_findings(
        self, findings: list[Finding], k_per_finding: int = 2, limit: int = 5
    ) -> list[RetrievedDoc]:
        """Retrieve references relevant to the diagnosed findings.

        Deduplicates across findings and keeps the highest score per document.
        """
        best: dict[str, RetrievedDoc] = {}
        for finding in findings:
            hints = RULE_TAG_HINTS.get(finding.rule_id, [])
            query = " ".join([finding.title, *hints])
            for doc in self.search(query, k=k_per_finding):
                existing = best.get(doc.doc_id)
                if existing is None or doc.score > existing.score:
                    best[doc.doc_id] = doc
        ranked = sorted(best.values(), key=lambda d: -d.score)
        return ranked[:limit]


def _excerpt(text: str, max_chars: int = 320) -> str:
    text = " ".join(text.split())
    if len(text) <= max_chars:
        return text
    cut = text[:max_chars]
    if " " in cut:
        cut = cut[: cut.rfind(" ")]
    return cut + "..."


def load_documents(path: Path | None = None) -> list[dict]:
    kb_path = path or DEFAULT_KB_PATH
    with open(kb_path, encoding="utf-8") as fh:
        return json.load(fh)


@lru_cache(maxsize=1)
def get_knowledge_base() -> KnowledgeBase:
    """Process-wide singleton so the index is built once per worker."""
    import os

    prefer_semantic = os.getenv("INTERRUPTGPT_SEMANTIC_EMBEDDINGS", "1") != "0"
    return KnowledgeBase(load_documents(), prefer_semantic=prefer_semantic)
