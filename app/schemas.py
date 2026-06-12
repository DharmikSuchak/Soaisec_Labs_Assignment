from typing import List, Optional
from pydantic import BaseModel, Field, field_validator


# ─── Request models ────────────────────────────────────────────────────────────

class ContextDoc(BaseModel):
    id: str = Field(..., description="Unique document identifier")
    text: str = Field(..., description="Document content")


class RequestMetadata(BaseModel):
    app_id: str = Field(..., description="Calling application identifier")
    user_id: str = Field(..., description="End-user identifier")
    request_id: str = Field(..., description="Unique request identifier for tracing")


class AnalyzeRequest(BaseModel):
    prompt: str = Field(..., description="The user prompt to be analyzed")
    context_docs: List[ContextDoc] = Field( #list of documents
        default_factory=list,
        description="Retrieved context documents (RAG sources)"
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
    decision: str = Field(..., description="allow | block | transform")
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
    thresholds: dict = Field(..., description="Decision thresholds")
