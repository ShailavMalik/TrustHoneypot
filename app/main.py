"""
Phase 2 – Agentic Honeypot API  (FastAPI entry point).

Orchestrates the detection → extraction → engagement → callback pipeline.
Always returns HTTP 200 with {status, reply}. Internal analysis is never
exposed in the response body.
"""
import json
import logging
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.models import HoneypotRequest, HoneypotResponse
from app.auth import verify_api_key
from app.detector import risk_accumulator
from app.extractor import intelligence_store
from app.agent import engagement_controller
from app.memory import memory
from app.callback import build_final_output, send_final_callback, should_send_callback

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
app = FastAPI(
    title="Agentic Honey-Pot API",
    description="Phase 2 – Scam Detection & Intelligence Extraction",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def startup_event():
    logger.info("API Ready | Docs: /docs | Health: GET / | Honeypot: POST /honeypot")


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    logger.error(f"422 ERROR | {request.url.path} | {exc.errors()}")
    return JSONResponse(
        status_code=422,
        content={"detail": exc.errors(), "message": "Invalid request payload."},
    )


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------
@app.get("/")
async def health_check():
    return {"status": "online", "service": "Agentic Honey-Pot API", "version": "2.0.0"}


# ---------------------------------------------------------------------------
# Main honeypot endpoint
# ---------------------------------------------------------------------------
@app.post("/honeypot", response_model=HoneypotResponse)
async def process_message(
    request: HoneypotRequest,
    api_key: str = Depends(verify_api_key),
):
    """
    Process an incoming scammer message and return a human-like reply.

    Pipeline:
      1. Ensure session exists.
      2. Replay conversation history through detector + extractor (idempotent).
      3. Analyse current message   → risk score, scam flag.
      4. Extract intelligence      → deduplicated per session.
      5. Generate engagement reply  → 5-stage adaptive.
      6. Check callback eligibility → send finalOutput once per session.
      7. Return {status: "success", reply: "<text>"}.
    """
    try:
        session_id = request.sessionId
        current_text = request.message.text or ""
        history = request.conversationHistory or []

        logger.info(
            f"[{session_id[:8]}] REQUEST msg_len={len(current_text)} "
            f"history_len={len(history)}"
        )

        # 1. Ensure session
        memory.ensure_session(session_id)

        # 2. Replay history (idempotent – detector & extractor deduplicate)
        for hist_msg in history:
            sender = hist_msg.sender or "scammer"
            if sender == "scammer" and hist_msg.text:
                risk_accumulator.analyze_message(hist_msg.text, session_id)
                intelligence_store.extract(hist_msg.text, session_id)

        # 3. Analyse current message
        memory.add_message(session_id, "scammer", current_text)
        cum_score, is_scam = risk_accumulator.analyze_message(current_text, session_id)
        profile = risk_accumulator.get_profile(session_id)

        if is_scam and not memory.is_scam_confirmed(session_id):
            memory.mark_scam_confirmed(session_id)

        # 4. Extract intelligence from current message
        intelligence_store.extract(current_text, session_id)
        intel = intelligence_store.get_intelligence(session_id)

        # 5. Compute message count (history + current message)
        #    history contains both scammer & agent messages from previous turns
        total_messages = len(history) + 1

        # 6. Generate reply
        scam_confirmed = memory.is_scam_confirmed(session_id)
        reply = engagement_controller.get_reply(
            session_id=session_id,
            message=current_text,
            msg_count=total_messages,
            risk_score=cum_score,
            is_scam=scam_confirmed,
            scam_type=profile.scam_type,
        )
        memory.add_message(session_id, "agent", reply)
        memory.set_agent_response(session_id, reply)

        # 7. Callback (once per session when eligible)
        callback_sent = False
        if should_send_callback(scam_confirmed, total_messages, intel):
            if not memory.is_callback_sent(session_id):
                duration = memory.get_guaranteed_duration(session_id)
                signals = risk_accumulator.get_triggered_signals(session_id)
                notes = engagement_controller.generate_agent_notes(
                    session_id=session_id,
                    signals=signals,
                    scam_type=profile.scam_type,
                    intel=intel,
                    total_msgs=total_messages,
                    duration=duration,
                )
                payload = build_final_output(
                    session_id=session_id,
                    scam_detected=True,
                    scam_type=profile.scam_type,
                    intelligence=intel,
                    total_messages=total_messages,
                    duration_seconds=duration,
                    agent_notes=notes,
                )
                if send_final_callback(session_id, payload):
                    memory.mark_callback_sent(session_id)
                    callback_sent = True

        # Internal log (never exposed in response)
        logger.info(
            f"[{session_id[:8]}] INTERNAL score={cum_score:.0f} "
            f"scam={scam_confirmed} type={profile.scam_type} "
            f"msgs={total_messages} callback={'sent' if callback_sent else 'no'}"
        )

        # 8. Return simple response
        return HoneypotResponse(status="success", reply=reply)

    except Exception as exc:
        logger.error(f"Error processing request: {exc}", exc_info=True)
        # Graceful fallback – never return non-200 for transient errors
        return HoneypotResponse(
            status="success",
            reply="Sorry, I didn't catch that. Can you please repeat?",
        )


# ---------------------------------------------------------------------------
# Dev runner
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
