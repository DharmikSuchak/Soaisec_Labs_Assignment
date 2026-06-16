from typing import Dict, List, Literal, Optional
from pydantic import BaseModel, Field, field_validator


# ─── Request models ────────────────────────────────────────────────────────────

class ContextDoc(BaseModel):
    id: str = Field(..., description="Unique document identifier")
    text: str = Field(..., max_length=20_000, description="Document content (max 20 000 chars)")


class RequestMetadata(BaseModel):
    app_id: str = Field(..., description="Calling application identifier")
    user_id: str = Field(..., description="End-user identifier")
    request_id: str = Field(..., description="Unique request identifier for tracing")


class AnalyzeRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=10_000, description="The user prompt to be analyzed (max 10 000 chars)")
    context_docs: List[ContextDoc] = Field( #list of documents — spec allows 0–3
        default_factory=list,
        max_length=3,
        description="Retrieved context documents (RAG sources), max 3"
    )
    metadata: RequestMetadata = Field(..., description="Request metadata for logging")

    @field_validator("prompt")
    @classmethod
    def prompt_not_empty(cls, v: str) -> str:
        if not v.strip(): #strip() returns the string with whitespace removed from the beginning and end
            raise ValueError("prompt must not be empty")
        return v


# ─── Response models ───────────────────────────────────────────────────────────

class ReasonDetail(BaseModel):
    tag: str = Field(..., description="Detector tag that fired")
    evidence: str = Field(..., description="Safe, non-PII evidence string")


class AnalyzeResponse(BaseModel):
    decision: Literal["allow", "transform", "block"] = Field(..., description="allow | transform | block")
    risk_score: int = Field(..., ge=0, le=100, description="Aggregate risk score 0–100")
    risk_tags: List[str] = Field(default_factory=list, description="Tags of triggered detectors")
    sanitized_prompt: str = Field(..., description="Prompt after PII redaction")
    sanitized_context_docs: List[ContextDoc] = Field(
        default_factory=list,
        description="Context docs after PII redaction"
    )
    reasons: List[ReasonDetail] = Field(
        default_factory=list,
        description="Per-detector reason details"
    )


class PolicyResponse(BaseModel):
    version: str = Field(..., description="Policy version string")
    detectors: List[str] = Field(..., description="Active detector names")
    thresholds: Dict[str, int] = Field(..., description="Decision thresholds")
