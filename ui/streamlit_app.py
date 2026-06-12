"""
Configuration:
    API_BASE_URL env var  — defaults to http://localhost:8000
                            Set to http://api:8000 inside Docker.
"""

import os
import uuid

import requests  # type: ignore[import-untyped]
import streamlit as st

# ─── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="SentraGuard Lite",
    page_icon="🛡️",
    layout="centered",
)

# ─── API base URL ──────────────────────────────────────────────────────────────
API_BASE_URL = os.environ.get("API_BASE_URL", "http://localhost:8000").rstrip("/")

# ── API Key — read silently from environment, never shown to the user ──────────
api_key = os.environ.get("API_KEY", "").strip()

# ─── UI ───────────────────────────────────────────────────────────────────────
st.title("🛡️ SentraGuard Lite")
st.caption("Minimal GenAI Guardrails Gateway — fully offline & deterministic")

st.divider()

# ── Prompt input ───────────────────────────────────────────────────────────────
st.subheader("📝 Prompt")
prompt = st.text_area(
    "Enter the user prompt to analyze",
    placeholder='e.g. "What is the capital of France?"',
    height=120,
)

# ── Context documents ──────────────────────────────────────────────────────────
st.subheader("📄 Context Documents (optional, up to 3)")

context_docs = []
for i in range(1, 4):
    with st.expander(f"Context Document {i}", expanded=(i == 1)):
        doc_text = st.text_area(
            f"Document {i} text",
            key=f"doc_{i}",
            height=80,
            placeholder=f"Paste retrieved context document {i} here…",
            label_visibility="collapsed",
        )
        if doc_text.strip():
            context_docs.append({"id": f"doc-{i}", "text": doc_text})

st.divider()

# ── Metadata fields (auto-filled) ─────────────────────────────────────────────

app_id = st.text_input("App ID", value="streamlit-ui", help="Identifies the calling application")
user_id = st.text_input("User ID", value="demo-user", help="End-user identifier")

# ── Analyze button ─────────────────────────────────────────────────────────────
analyze_clicked = st.button("🔍 Analyze", type="primary", use_container_width=True)

if analyze_clicked:
    if not prompt.strip():
        st.warning("Please enter a prompt before analyzing.")
    elif not api_key:
        st.error(
            "❌ API key not configured. "
            "Ensure `API_KEY` is set in your `.env` file and the container was restarted."
        )
    else:
        request_id = str(uuid.uuid4())
        payload = {
            "prompt": prompt,
            "context_docs": context_docs,
            "metadata": {
                "app_id": app_id,
                "user_id": user_id,
                "request_id": request_id,
            },
        }

        with st.spinner("Analyzing…"):
            try:
                resp = requests.post(
                    f"{API_BASE_URL}/analyze",
                    json=payload,
                    headers={"X-API-Key": api_key},
                    timeout=15,
                )
            except requests.ConnectionError:
                st.error(
                    f"❌ Could not connect to API at `{API_BASE_URL}`. "
                    "Is the API service running?"
                )
                st.stop()
            except requests.Timeout:
                st.error("❌ Request timed out after 15 seconds.")
                st.stop()

        if resp.status_code == 401:
            st.error("❌ **Unauthorized** — wrong or missing API key.")
        elif resp.status_code == 429:
            st.error("⏱️ **Rate limit exceeded** — wait a minute and try again.")
        elif resp.status_code == 400:
            st.error(f"❌ **Bad Request** — {resp.json().get('detail', resp.text)}")
        elif not resp.ok:
            st.error(f"❌ **API Error {resp.status_code}** — {resp.text}")
        else:
            data = resp.json()

            st.divider()
            st.subheader("📊 Analysis Results")

            # Decision badge
            decision = data.get("decision", "unknown")
            risk_score = data.get("risk_score", 0)
            risk_tags = data.get("risk_tags", [])

            DECISION_COLORS = {
                "allow": "🟢",
                "transform": "🟡",
                "block": "🔴",
            }
            emoji = DECISION_COLORS.get(decision, "⚪")

            col1, col2 = st.columns(2)
            col1.metric("Decision", f"{emoji} {decision.upper()}")
            col2.metric("Risk Score", f"{risk_score} / 100")

            if risk_tags:
                st.info("**Risk Tags:** " + "  •  ".join(f"`{t}`" for t in risk_tags))
            else:
                st.success("No risk tags — prompt looks clean.")

            # Reasons
            reasons = data.get("reasons", [])
            if reasons:
                st.subheader("🔍 Reasons")
                for r in reasons:
                    st.warning(f"**{r['tag']}** — {r['evidence']}")

            # Sanitized outputs
            st.subheader("🧹 Sanitized Output")
            st.markdown("**Sanitized Prompt**")
            st.code(data.get("sanitized_prompt", ""), language=None)

            san_docs = data.get("sanitized_context_docs", [])
            if san_docs:
                st.markdown("**Sanitized Context Documents**")
                for doc in san_docs:
                    with st.expander(f"Document: {doc['id']}"):
                        st.code(doc["text"], language=None)

            # Raw JSON (collapsible)
            with st.expander("📦 Raw JSON Response"):
                st.json(data)
