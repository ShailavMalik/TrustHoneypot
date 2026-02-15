"""FastAPI entry point. Wires detection -> extraction -> engagement -> callback
pipeline. Exposes GET / (health) and POST /honeypot (conversation endpoint)."""

import logging

from fastapi import FastAPI, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.models import HoneypotRequest, HoneypotResponse
from app.auth import verify_api_key
from app.detector import risk_accumulator
from app.extractor import intelligence_store
from app.agent import engagement_controller
from app.memory import memory
from app.callback import (
    build_final_output,
    send_final_callback,
    should_send_callback,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Agentic Honey-Pot API",
    description="Phase 2 — Scam Detection, Engagement, and Intelligence Extraction",
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
async def _on_startup() -> None:
    logger.info("Agentic Honey-Pot API v2.0.0 started | Docs: /docs | Health: GET /")


@app.exception_handler(RequestValidationError)
async def _validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    logger.error(f"422 VALIDATION ERROR | {request.url.path} | {exc.errors()}")
    return JSONResponse(
        status_code=422,
        content={"detail": exc.errors(), "message": "Invalid request payload."},
    )


@app.get("/")
async def health_check() -> dict:
    return {
        "status": "online",
        "service": "Agentic Honey-Pot API",
        "version": "2.0.0",
    }


@app.post("/honeypot", response_model=HoneypotResponse)
async def process_message(
    request: HoneypotRequest,
    api_key: str = Depends(verify_api_key),
) -> HoneypotResponse:
    """Process a scammer message through the full detection/engagement pipeline."""
    try:
        session_id = request.sessionId
        current_text = request.message.text or ""
        history = request.conversationHistory or []

        logger.info(
            f"[{session_id[:8]}] REQUEST  "
            f"msg_len={len(current_text)}  history_len={len(history)}"
        )

        # 1. Session management
        session = memory.ensure_session(session_id)
        is_fresh = len(session.get("messages", [])) == 0

        # 2. Replay history — extractor always, detector only on fresh sessions
        for hist_msg in history:
            sender = hist_msg.sender or "scammer"
            if sender == "scammer" and hist_msg.text:
                intelligence_store.extract(hist_msg.text, session_id)
                if is_fresh:
                    risk_accumulator.analyze_message(hist_msg.text, session_id)

        # 3. Analyze current message
        memory.add_message(session_id, "scammer", current_text)
        cum_score, is_scam = risk_accumulator.analyze_message(current_text, session_id)
        profile = risk_accumulator.get_profile(session_id)

        if is_scam and not memory.is_scam_confirmed(session_id):
            memory.mark_scam_confirmed(session_id)

        # 4. Extract intelligence
        intelligence_store.extract(current_text, session_id)
        intel = intelligence_store.get_intelligence(session_id)

        # 5. Total message count (history + current)
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

        # 7. Callback (re-sent every eligible turn)
        callback_sent = False
        if should_send_callback(scam_confirmed, total_messages, intel):
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

        logger.info(
            f"[{session_id[:8]}] INTERNAL  "
            f"score={cum_score:.0f}  scam={scam_confirmed}  "
            f"type={profile.scam_type}  msgs={total_messages}  "
            f"callback={'sent' if callback_sent else 'no'}"
        )

        return HoneypotResponse(status="success", reply=reply)

    except Exception as exc:
        logger.error(f"Error processing request: {exc}", exc_info=True)
        return HoneypotResponse(
            status="success",
            reply="Sorry, I didn't catch that. Can you please repeat?",
        )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
