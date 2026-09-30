from __future__ import annotations

import math
from typing import Any

import httpx


def rank_semantically(
    query: str,
    documents: list[dict[str, object]],
    *,
    base_url: str,
    model: str,
    timeout_seconds: int,
) -> list[dict[str, object]]:
    if not documents:
        return []
    ranked: list[dict[str, object]] = []
    for offset in range(0, len(documents), 64):
        batch = documents[offset : offset + 64]
        inputs = [query] + [f"{item.get('title', '')}\n{item.get('body', '')}" for item in batch]
        try:
            response = httpx.post(
                f"{base_url.rstrip('/')}/api/embed",
                json={"model": model, "input": inputs},
                timeout=timeout_seconds,
            )
            response.raise_for_status()
            data: Any = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise RuntimeError(
                f"Semantic search embedding request failed for model '{model}': {exc}"
            ) from exc
        vectors = data.get("embeddings") if isinstance(data, dict) else None
        if not isinstance(vectors, list) or len(vectors) != len(inputs):
            raise RuntimeError(
                "Ollama returned invalid embeddings; check that the model supports /api/embed."
            )
        numeric_vectors: list[list[float]] = []
        for vector in vectors:
            if not isinstance(vector, list) or not vector:
                raise RuntimeError(
                    "Ollama returned invalid embeddings; check that the model supports /api/embed."
                )
            numeric_vector: list[float] = []
            for value in vector:
                if (
                    not isinstance(value, (int, float))
                    or isinstance(value, bool)
                    or not math.isfinite(value)
                ):
                    raise RuntimeError(
                        "Ollama returned invalid embeddings; check that the model supports /api/embed."
                    )
                numeric_vector.append(value)
            numeric_vectors.append(numeric_vector)
        query_vector = numeric_vectors[0]
        for document, vector in zip(batch, numeric_vectors[1:], strict=True):
            score = _cosine_similarity(query_vector, vector)
            ranked.append({**document, "semantic_score": score})
    return sorted(ranked, key=_semantic_score, reverse=True)


def _semantic_score(document: dict[str, object]) -> float:
    score = document["semantic_score"]
    if not isinstance(score, (int, float)):
        raise RuntimeError("Semantic ranking returned a non-numeric score.")  # noqa: TRY004
    return float(score)


def _cosine_similarity(left: list[float], right: list[float]) -> float:
    if len(left) != len(right):
        raise RuntimeError("Ollama returned embeddings with inconsistent dimensions.")
    left_norm = math.sqrt(sum(value * value for value in left))
    right_norm = math.sqrt(sum(value * value for value in right))
    if left_norm == 0 or right_norm == 0:
        return 0.0
    return sum(a * b for a, b in zip(left, right, strict=True)) / (left_norm * right_norm)
