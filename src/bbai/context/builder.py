from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ContextInput:
    target: str
    scope: str | None = None
    assets: str | None = None
    endpoints: str | None = None
    recon: str | None = None
    http_observations: str | None = None
    previous_findings: str | None = None
    observations: str | None = None
    hypotheses: str | None = None
    evidence: str | None = None
    question: str | None = None


def build_context(payload: ContextInput) -> str:
    lines = [
        "TARGET",
        payload.target,
        "",
        "SCOPE",
        payload.scope or "Not specified.",
        "",
        "ASSETS",
        payload.assets or "No assets recorded.",
        "",
        "ENDPOINTS",
        payload.endpoints or "No endpoints recorded.",
        "",
        "RECON",
        payload.recon or "No reconnaissance notes yet.",
        "",
        "HTTP OBSERVATIONS",
        payload.http_observations or "No HTTP observations recorded.",
        "",
        "PREVIOUS FINDINGS",
        payload.previous_findings or "No previous findings.",
        "",
        "OBSERVATIONS",
        payload.observations or "No observations recorded.",
        "",
        "HYPOTHESES",
        payload.hypotheses or "No hypotheses recorded.",
        "",
        "EVIDENCE",
        payload.evidence or "No evidence attached.",
        "",
        "USER QUESTION",
        payload.question or "Provide a concise assessment of the current state.",
    ]
    return "\n".join(lines)
