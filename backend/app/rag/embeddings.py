"""Embedding backends.

The project prefers sentence-transformers when it is installed, but falls back
to a scikit-learn TF-IDF vectoriser so the whole pipeline stays runnable in a
lightweight container or CI job with no model download. Both backends return
L2-normalised dense vectors, so downstream cosine similarity is just a dot
product regardless of which one is active.
"""
from __future__ import annotations

import logging
from typing import Protocol

import numpy as np

logger = logging.getLogger(__name__)

DEFAULT_ST_MODEL = "sentence-transformers/all-MiniLM-L6-v2"


class Embedder(Protocol):
    name: str

    def fit(self, corpus: list[str]) -> None: ...

    def encode(self, texts: list[str]) -> np.ndarray: ...


def _l2_normalise(mat: np.ndarray) -> np.ndarray:
    norms = np.linalg.norm(mat, axis=1, keepdims=True)
    norms[norms == 0] = 1.0
    return mat / norms


class TfidfEmbedder:
    """Dependency-light fallback embedder built on TF-IDF + SVD."""

    name = "tfidf"

    def __init__(self, n_components: int = 128) -> None:
        self.n_components = n_components
        self._vectorizer = None
        self._svd = None

    def fit(self, corpus: list[str]) -> None:
        from sklearn.decomposition import TruncatedSVD
        from sklearn.feature_extraction.text import TfidfVectorizer

        self._vectorizer = TfidfVectorizer(
            lowercase=True,
            stop_words="english",
            ngram_range=(1, 2),
            sublinear_tf=True,
        )
        matrix = self._vectorizer.fit_transform(corpus)

        # SVD needs n_components < n_features and < n_samples.
        max_components = max(1, min(self.n_components, min(matrix.shape) - 1))
        if max_components > 1:
            self._svd = TruncatedSVD(n_components=max_components, random_state=42)
            self._svd.fit(matrix)

    def encode(self, texts: list[str]) -> np.ndarray:
        if self._vectorizer is None:
            raise RuntimeError("TfidfEmbedder.fit() must be called before encode().")
        matrix = self._vectorizer.transform(texts)
        dense = self._svd.transform(matrix) if self._svd is not None else matrix.toarray()
        return _l2_normalise(np.asarray(dense, dtype=np.float32))


class SentenceTransformerEmbedder:
    """Semantic embedder used when sentence-transformers is available."""

    name = "sentence-transformers"

    def __init__(self, model_name: str = DEFAULT_ST_MODEL) -> None:
        from sentence_transformers import SentenceTransformer

        self.model_name = model_name
        self._model = SentenceTransformer(model_name)
        self.name = f"sentence-transformers:{model_name}"

    def fit(self, corpus: list[str]) -> None:  # pragma: no cover - no-op
        """Pretrained models need no fitting."""

    def encode(self, texts: list[str]) -> np.ndarray:
        vectors = self._model.encode(texts, convert_to_numpy=True, show_progress_bar=False)
        return _l2_normalise(np.asarray(vectors, dtype=np.float32))


def build_embedder(prefer_semantic: bool = True) -> Embedder:
    """Return the best embedder available in this environment."""
    if prefer_semantic:
        try:
            return SentenceTransformerEmbedder()
        except Exception as exc:  # noqa: BLE001 - any import/download failure
            logger.info("sentence-transformers unavailable (%s); using TF-IDF.", exc)
    return TfidfEmbedder()
