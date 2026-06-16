# app/core/detectors.py
"""
Three deterministic, regex-based detectors for SentraGuard Lite.

Design decision: regex only — no external NLP libraries — keeps the service
fully offline, fast, and free from model-version drift.  The tradeoff is lower
recall against sophisticated obfuscation; see README Design Notes.
"""

import re
from typing import List, Tuple

from app.schemas import ContextDoc

# ─── Type alias ────────────────────────────────────────────────────────────────
# Each detector returns (score_delta, tag, reasons_list)
# where reasons_list is a list of {"tag": str, "evidence": str} dicts
DetectorResult = Tuple[int, str, List[dict]]

# 1. Prompt Injection Detector (hard coded)
INJECTION_PHRASES: List[str] = [
    "ignore previous instructions",
    "reveal system prompt",
    "act as dan",
    "forget your instructions",
    "disregard previous",
    "override instructions",
    "you are now",
    "pretend you are",
]

# Subset of phrases that are high-confidence attacks — score=80 → single-shot block
HIGH_CONFIDENCE_PI_PHRASES: List[str] = [
    "ignore previous instructions",
    "reveal system prompt",
    "forget your instructions",
]


def detect_prompt_injection(prompt: str) -> DetectorResult:
    """
    Check for known prompt-injection phrases (case-insensitive).

    Returns +80 risk score for high-confidence phrases (single-shot block),
    or +50 for other known injection phrases.
    The phrase itself is safe to surface in evidence — it is not PII.
    """
    prompt_lower = prompt.lower()
    reasons: List[dict] = []
    is_high_confidence = False

    for phrase in INJECTION_PHRASES:
        if phrase in prompt_lower:
            reasons.append({
                "tag": "prompt_injection",
                "evidence": f"matched phrase: {phrase}",
            })
            if phrase in HIGH_CONFIDENCE_PI_PHRASES:
                is_high_confidence = True

    if reasons:
        # High-confidence phrases score 80 → forces block on a single hit
        score = 80 if is_high_confidence else 50
        return score, "prompt_injection", reasons
    return 0, "prompt_injection", []

# 2. PII Detector + Redactor

# Email pattern — ReDoS-safe: bounded local-part {0,63}, \b anchors,
# no unbounded repetition of overlapping character classes.
_EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9][A-Za-z0-9._%+\-]{0,63}@[A-Za-z0-9\-]{1,63}"
    r"(?:\.[A-Za-z0-9\-]{1,63})*\.[A-Za-z]{2,}\b"
)

# Phone patterns — ReDoS-safe: explicit bounded digit counts, \b anchors.
#   • Indian mobile: exactly 10 digits starting with 6-9
#   • Generic 10-digit run (no spaces/dashes — avoids false-positives)
_PHONE_INDIAN_RE = re.compile(r"\b[6-9]\d{9}\b")
_PHONE_GENERIC_RE = re.compile(r"\b\d{10}\b")


def _redact_pii(text: str) -> Tuple[str, List[dict]]:
    """
    Redact PII from *text* and return (redacted_text, reasons).

    Evidence strings NEVER include the actual PII value — only the pattern type.
    """
    reasons: List[dict] = []

    if _EMAIL_RE.search(text): #Do we see an email in this text?
        text = _EMAIL_RE.sub("[REDACTED_EMAIL]", text) #deletes the user's real email address
        reasons.append({"tag": "pii", "evidence": "found email pattern"})

    if _PHONE_INDIAN_RE.search(text) or _PHONE_GENERIC_RE.search(text):
        text = _PHONE_INDIAN_RE.sub("[REDACTED_PHONE]", text)
        text = _PHONE_GENERIC_RE.sub("[REDACTED_PHONE]", text)
        reasons.append({"tag": "pii", "evidence": "found phone pattern"})

    return text, reasons


def detect_pii(prompt: str) -> Tuple[int, str, List[dict], str]:
    """
    Detect and redact PII in the prompt.

    Returns (score_delta, tag, reasons, sanitized_prompt).
    +30 risk score when PII is found.
    """
    sanitized, reasons = _redact_pii(prompt)
    if reasons:
        return 30, "pii", reasons, sanitized
    return 0, "pii", [], sanitized


def redact_doc(doc: ContextDoc) -> ContextDoc:
    """Return a new ContextDoc with PII scrubbed from its text."""
    sanitized_text, _ = _redact_pii(doc.text)
    return ContextDoc(id=doc.id, text=sanitized_text)

# 3. RAG Injection Detector

RAG_INJECTION_PHRASES: List[str] = [
    "system:",
    "override policy",
    "ignore guidelines",
    "forget previous",
    "new instruction",
    "disregard above",
]


def detect_rag_injection(context_docs: List[ContextDoc]) -> DetectorResult:
    """
    Scan retrieved context documents for malicious instructions.

    Returns +40 risk score when any injection phrase is found.
    Evidence references the doc id and matched phrase — neither is PII.
    """
    reasons: List[dict] = []

    for doc in context_docs:
        doc_lower = doc.text.lower()
        for phrase in RAG_INJECTION_PHRASES:
            if phrase in doc_lower:
                reasons.append({
                    "tag": "rag_injection",
                    "evidence": f"matched phrase in doc {doc.id}: {phrase}",
                })

    if reasons:
        return 40, "rag_injection", reasons
    return 0, "rag_injection", []
