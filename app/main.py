# app/main.py
"""
SentraGuard Lite — FastAPI entrypoint.

2 endpoints:
  POST /analyze  — authenticated, runs all detectors, returns policy decision
  GET  /policy   — public, returns current detector configuration

Security controls implemented here:
  • API key authentication via X-API-Key header (POST /analyze only)
  • Input size limits: max 10 000-char prompt, max 10 context docs
  • Rate limiting: 30 req/min per app_id (slowapi)
  • Secure logging: never logs prompt/doc content, only request_id, app_id, tags
"""

import logging
import os
from datetime import datetime, timezone

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from app.schemas import AnalyzeRequest, AnalyzeResponse, PolicyResponse
from app.core.scoring import run_analysis, BLOCK_SCORE, TRANSFORM_SCORE

# ─── Logging setup ─────────────────────────────────────────────────────────────
# JSON-style structured logging — prompts/docs are NEVER included.
logging.basicConfig(
    level=logging.INFO,
    format='{"time":"%(asctime)s","level":"%(levelname)s","msg":%(message)s}',
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
logger = logging.getLogger("sentraguard")


# ─── Rate limiter ──────────────────────────────────────────────────────────────
# Keyed by remote IP by default; /analyze overrides this to use app_id.
limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="SentraGuard Lite",
    description="Minimal GenAI guardrails gateway — fully offline and deterministic.",
    version="1.0.0",
    docs_url="/docs",
    redoc_url=None,
)

app.state.limiter = limiter


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=429,
        content={"detail": "Rate limit exceeded. Max 30 requests per minute per app_id."},
    )


# ─── API key dependency ─────────────────────────────────────────────────────────

def _get_api_key() -> str:
    """Load API key from environment. Raises on misconfiguration."""
    key = os.environ.get("API_KEY", "").strip()
    if not key:
        raise RuntimeError("API_KEY environment variable is not set.")
    return key


def _verify_api_key(x_api_key: str | None) -> None:
    """Raise HTTP 401 if the provided key is missing or incorrect."""
    expected = _get_api_key()
    if x_api_key is None or x_api_key.strip() != expected:
        raise HTTPException(status_code=401, detail="Unauthorized: invalid or missing X-API-Key")


# ─── App-id based rate-limit key extractor ────────────────────────────────────

def _app_id_key(request: Request) -> str:
    """Extract app_id from the parsed body for rate-limit keying.
    Falls back to remote IP if body is not yet parsed."""
    try:
        # slowapi calls this before the route handler; body may not be parsed yet
        body = request.state.__dict__.get("_body")
        if body:
            import json
            data = json.loads(body)
            return data.get("metadata", {}).get("app_id", get_remote_address(request))
    except Exception:
        pass
    return get_remote_address(request)


# ══════════════════════════════════════════════════════════════════════════════
# Endpoint 1 — POST /analyze
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/analyze", response_model=AnalyzeResponse)
@limiter.limit("30/minute", key_func=_app_id_key)
async def analyze(
    request: Request,
    body: AnalyzeRequest,
    x_api_key: str | None = Header(default=None),
) -> AnalyzeResponse:
    """
    Analyze a prompt + optional RAG context docs and return a policy decision.

    Authentication: X-API-Key header required.
    Input limits: prompt ≤ 10 000 chars, context_docs ≤ 10 items.
    """
    # ── Auth ──────────────────────────────────────────────────────────────────
    _verify_api_key(x_api_key)

    # ── Input size guards ─────────────────────────────────────────────────────
    if len(body.prompt) > 10_000:
        raise HTTPException(
            status_code=400,
            detail="prompt exceeds maximum length of 10,000 characters",
        )
    if len(body.context_docs) > 10:
        raise HTTPException(
            status_code=400,
            detail="context_docs exceeds maximum of 10 documents",
        )

    # ── Run detectors ────────────────────────────────────────────────────────
    result: AnalyzeResponse = run_analysis(body)

    # ── Secure log (no prompt/doc content) ───────────────────────────────────
    logger.info(
        '"request_id":"%s","app_id":"%s","risk_score":%d,"risk_tags":%s,"timestamp":"%s"',
        body.metadata.request_id,
        body.metadata.app_id,
        result.risk_score,
        result.risk_tags,
        datetime.now(timezone.utc).isoformat(),
    )

    return result


# ══════════════════════════════════════════════════════════════════════════════
# Endpoint 2 — GET /policy
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/policy", response_model=PolicyResponse)
async def get_policy() -> PolicyResponse:
    """
    Return the current policy/detector configuration.

    Public endpoint — no authentication required.
    """
    return PolicyResponse(
        version="1",
        detectors=["prompt_injection", "pii", "rag_injection"],
        thresholds={
            "block_score": BLOCK_SCORE,
            "transform_score": TRANSFORM_SCORE,
        },
    )
