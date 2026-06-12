# app/core/scoring.py
"""
Scoring and decision engine for SentraGuard Lite.

Aggregates detector results into a final risk score and maps it to a policy
decision (allow / transform / block).
"""

import os
from typing import List, Tuple

from app.schemas import AnalyzeRequest, AnalyzeResponse, ContextDoc, ReasonDetail
from app.core.detectors import (
    detect_prompt_injection,
    detect_pii,
    detect_rag_injection,
    redact_doc,
)


# ─── Thresholds (configurable via .env, with sensible defaults) ───────────────
BLOCK_SCORE: int = int(os.environ.get("BLOCK_SCORE", "80"))
TRANSFORM_SCORE: int = int(os.environ.get("TRANSFORM_SCORE", "40"))


def _decide(score: int) -> str: # _ --> private function, separate function --> single Responsibility Principle
    """Map a numeric score to a policy decision string."""
    if score >= BLOCK_SCORE:
        return "block"
    if score >= TRANSFORM_SCORE:
        return "transform"
    return "allow"


def run_analysis(request: AnalyzeRequest) -> AnalyzeResponse:
    """
    Run all detectors against the request and produce a full AnalyzeResponse.

    Steps:
    1. Detect prompt injection in the user prompt.
    2. Detect and redact PII from the prompt.
    3. Detect RAG injection in context docs.
    4. Redact PII from all context docs.
    5. Sum scores (capped at 100), derive decision, assemble response.
    """
    total_score: int = 0
    risk_tags: List[str] = []
    all_reasons: List[ReasonDetail] = []

    # ── 1. Prompt injection ──────────────────────────────────────────────────
    inj_score, inj_tag, inj_reasons = detect_prompt_injection(request.prompt)
    if inj_score > 0:
        total_score += inj_score
        risk_tags.append(inj_tag)
        all_reasons.extend(ReasonDetail(**r) for r in inj_reasons)

    # ── 2. PII detection + redaction ─────────────────────────────────────────
    pii_score, pii_tag, pii_reasons, sanitized_prompt = detect_pii(request.prompt)
    if pii_score > 0:
        total_score += pii_score
        risk_tags.append(pii_tag)
        all_reasons.extend(ReasonDetail(**r) for r in pii_reasons)
    else:
        sanitized_prompt = request.prompt  # no PII → return as-is

    # ── 3. RAG injection ─────────────────────────────────────────────────────
    rag_score, rag_tag, rag_reasons = detect_rag_injection(request.context_docs)
    if rag_score > 0:
        total_score += rag_score
        risk_tags.append(rag_tag)
        all_reasons.extend(ReasonDetail(**r) for r in rag_reasons)

    # ── 4. Redact PII from context docs ──────────────────────────────────────
    sanitized_docs: List[ContextDoc] = [redact_doc(doc) for doc in request.context_docs]

    # ── 5. Cap score and decide ───────────────────────────────────────────────
    final_score: int = min(total_score, 100)
    decision: str = _decide(final_score)

    return AnalyzeResponse( #send back to streamlit ui
        decision=decision,
        risk_score=final_score,
        risk_tags=risk_tags,
        sanitized_prompt=sanitized_prompt,
        sanitized_context_docs=sanitized_docs,
        reasons=all_reasons,
    )
