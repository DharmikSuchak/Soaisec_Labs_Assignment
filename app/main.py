# app/main.py
"""
SentraGuard Lite — FastAPI entrypoint.

2 endpoints:
  POST /analyze  — authenticated, runs all detectors, returns policy decision
  GET  /policy   — public, returns current detector configuration

Security controls implemented here:
  • API key authentication via X-API-Key header (POST /analyze only)
  • Input size limits: max 10 000-char prompt, max 3 context docs (Pydantic-enforced)
  • Rate limiting: 30 req/min per app_id (slowapi)
  • Secure logging: never logs prompt/doc content, only request_id, app_id, tags
"""

import json
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
# Keyed by app_id extracted from request body via AppIdMiddleware (see below).
limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="SentraGuard Lite",
    description="Minimal GenAI guardrails gateway — fully offline and deterministic.",
    version="1.0.0",
    docs_url=None,     
    redoc_url=None,
    openapi_url=None,   
)

app.state.limiter = limiter


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=429,
        content={"detail": "Rate limit exceeded. Max 30 requests per minute per app_id."},
    )


# ─── AppId middleware ──────────────────────────────────────────────────────────
# Pre-parses app_id from the request body BEFORE slowapi's key-extractor runs.
# Starlette's Request.body() caches bytes internally via _body, so FastAPI/Pydantic
# can still read the body normally in the route handler — no stream consumption issue.
#
# Registration order matters: FastAPI middleware runs in LIFO (last-registered-first).
# slowapi is attached via app.state.limiter (already done above).
# AppIdMiddleware is added below via app.add_middleware() — registered AFTER slowapi,
# so it runs BEFORE slowapi's rate-check.

from starlette.middleware.base import BaseHTTPMiddleware

class AppIdMiddleware(BaseHTTPMiddleware):
    """Read the JSON body once and stash app_id on request.state for rate limiting."""
    async def dispatch(self, request, call_next):
        if request.method == "POST" and request.url.path == "/analyze":
            try:
                body_bytes = await request.body()
                data = json.loads(body_bytes)
                request.state.app_id = data.get("metadata", {}).get("app_id", "")
            except Exception:
                request.state.app_id = ""
        return await call_next(request)

app.add_middleware(AppIdMiddleware)


# ─── App-id based rate-limit key extractor ────────────────────────────────────

def _app_id_key(request: Request) -> str:
    """Read app_id from request.state (set by AppIdMiddleware).
    Falls back to remote IP if app_id is missing or empty."""
    app_id = getattr(request.state, "app_id", None)
    if app_id:
        return app_id
    return get_remote_address(request)


# ─── API key validation (startup-time) ──────────────────────────────────────────
# Validate API_KEY once at startup — refuse to start if missing.
# This prevents a per-request 500 RuntimeError.

def _load_api_key() -> str:
    """Load and validate API key at startup. Fails fast if not set."""
    key = os.environ.get("API_KEY", "").strip()
    if not key:
        raise SystemExit(
            "FATAL: API_KEY environment variable is not set. "
            "Copy .env.example → .env and set API_KEY before starting."
        )
    return key

_CACHED_API_KEY: str = _load_api_key()


def _verify_api_key(x_api_key: str | None) -> None:
    """Raise HTTP 401 if the provided key is missing or incorrect."""
    if x_api_key is None or x_api_key.strip() != _CACHED_API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized: invalid or missing X-API-Key")


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
    Input limits: prompt ≤ 10 000 chars, context_docs ≤ 3 items (Pydantic-enforced → 422).
    """
    # ── Auth ──────────────────────────────────────────────────────────────────
    _verify_api_key(x_api_key)

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
