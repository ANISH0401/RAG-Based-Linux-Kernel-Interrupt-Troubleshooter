"""Vector index abstraction.

Uses FAISS when installed (the production path) and a numpy brute-force index
otherwise. At knowledge-base scale the numpy path is exact and fast enough, so
tests and lightweight deployments lose nothing but speed at scale.
"""
from __future__ import annotations

import logging

import numpy as np

logger = logging.getLogger(__name__)


class NumpyVectorIndex:
    """Exact inner-product search over L2-normalised vectors."""

    backend = "numpy"

    def __init__(self, dim: int) -> None:
        self.dim = dim
        self._vectors: np.ndarray | None = None

    def add(self, vectors: np.ndarray) -> None:
        vectors = np.asarray(vectors, dtype=np.float32)
        self._vectors = (
            vectors if self._vectors is None else np.vstack([self._vectors, vectors])
        )

    def search(self, query: np.ndarray, k: int) -> tuple[np.ndarray, np.ndarray]:
        if self._vectors is None or len(self._vectors) == 0:
            return np.empty((1, 0), dtype=np.float32), np.empty((1, 0), dtype=np.int64)
        query = np.asarray(query, dtype=np.float32).reshape(1, -1)
        scores = (self._vectors @ query.T).ravel()
        k = min(k, len(scores))
        top = np.argsort(-scores)[:k]
        return scores[top].reshape(1, -1), top.reshape(1, -1)


class FaissVectorIndex:  # pragma: no cover - exercised only when FAISS present
    """FAISS-backed inner-product index."""

    backend = "faiss"

    def __init__(self, dim: int) -> None:
        import faiss

        self.dim = dim
        self._index = faiss.IndexFlatIP(dim)

    def add(self, vectors: np.ndarray) -> None:
        self._index.add(np.asarray(vectors, dtype=np.float32))

    def search(self, query: np.ndarray, k: int) -> tuple[np.ndarray, np.ndarray]:
        if self._index.ntotal == 0:
            return np.empty((1, 0), dtype=np.float32), np.empty((1, 0), dtype=np.int64)
        query = np.asarray(query, dtype=np.float32).reshape(1, -1)
        return self._index.search(query, min(k, self._index.ntotal))


def build_index(dim: int):
    """Return a FAISS index when available, else the numpy fallback."""
    try:
        return FaissVectorIndex(dim)
    except Exception as exc:  # noqa: BLE001
        logger.info("FAISS unavailable (%s); using numpy index.", exc)
        return NumpyVectorIndex(dim)
