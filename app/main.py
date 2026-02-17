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
    """Process a scammer message through the full detection/engagement pipeline.
    
    Pipeline stages:
    1. Session management - Initialize or retrieve conversation state
    2. History replay - Process historical messages for context
    3. Risk analysis - Evaluate current message for scam indicators
    4. Intelligence extraction - Extract actionable identifiers
    5. Response generation - Create contextually appropriate victim reply
    6. Callback dispatch - Send final result to evaluation endpoint
    """
    session_id = ""
    try:
        # Extract request parameters with validation
        session_id = request.sessionId
        current_text = request.message.text or ""
        history = request.conversationHistory or []

        # Validate minimum requirements
        if not session_id or not current_text.strip():
            logger.warning("Invalid request: missing sessionId or message text")
            return HoneypotResponse(
                status="success",
                reply="Sorry, I didn't hear you clearly. Can you repeat that?",
            )

        logger.info(
            f"[{session_id[:8]}] REQUEST  "
            f"msg_len={len(current_text)}  history_len={len(history)}"
        )

        # 1. Session management - ensure session exists and track state
        try:
            session = memory.ensure_session(session_id)
            is_fresh = len(session.get("messages", [])) == 0
        except Exception as e:
            logger.error(f"[{session_id[:8]}] Session management error: {e}")
            # Continue with fresh session if retrieval fails
            is_fresh = True

        # 2. Replay history — extractor runs always, detector only on fresh sessions
        # This prevents duplicate detection scoring on repeated history
        try:
            for hist_msg in history:
                sender = hist_msg.sender or "scammer"
                if sender == "scammer" and hist_msg.text:
                    # Always extract intelligence from history
                    intelligence_store.extract(hist_msg.text, session_id)
                    # Only run detection on fresh sessions to avoid score inflation
                    if is_fresh:
                        risk_accumulator.analyze_message(hist_msg.text, session_id)
        except Exception as e:
            logger.warning(f"[{session_id[:8]}] History replay error: {e}")
            # Continue processing - history replay failure shouldn't block current message

        # 3. Analyze current message for scam indicators
        try:
            memory.add_message(session_id, "scammer", current_text)
            cum_score, is_scam = risk_accumulator.analyze_message(current_text, session_id)
            profile = risk_accumulator.get_profile(session_id)

            # Mark scam confirmation on first detection
            if is_scam and not memory.is_scam_confirmed(session_id):
                memory.mark_scam_confirmed(session_id)
                logger.info(f"[{session_id[:8]}] SCAM CONFIRMED score={cum_score:.0f}")
        except Exception as e:
            logger.error(f"[{session_id[:8]}] Risk analysis error: {e}")
            # Fallback to safe defaults if detection fails
            cum_score, is_scam = 0.0, False
            profile = risk_accumulator.get_profile(session_id)

        # 4. Extract intelligence (phone numbers, accounts, UPIs, links, emails)
        try:
            intelligence_store.extract(current_text, session_id)
            intel = intelligence_store.get_intelligence(session_id)
        except Exception as e:
            logger.error(f"[{session_id[:8]}] Intelligence extraction error: {e}")
            # Use empty intelligence if extraction fails
            intel = {}

        # 5. Calculate total message count for engagement stage determination
        total_messages = len(history) + 1

        # 6. Generate contextually appropriate victim-persona reply
        try:
            scam_confirmed = memory.is_scam_confirmed(session_id)
            # Inject extracted intel so the engagement engine avoids redundant asks
            engagement_controller.set_extracted_intel(session_id, intel)
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
        except Exception as e:
            logger.error(f"[{session_id[:8]}] Reply generation error: {e}")
            # Fallback to generic response if generation fails
            reply = "Sorry, can you please repeat that? I didn't catch everything."

        # 7. Send callback to evaluation endpoint (if scam confirmed and threshold met)
        callback_sent = False
        try:
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
        except Exception as e:
            logger.error(f"[{session_id[:8]}] Callback dispatch error: {e}")
            # Callback failure shouldn't affect user-facing response

        logger.info(
            f"[{session_id[:8]}] INTERNAL  "
            f"score={cum_score:0f}  scam={scam_confirmed}  "
            f"type={profile.scam_type}  msgs={total_messages}  "
            f"callback={'sent' if callback_sent else 'no'}"
        )

        return HoneypotResponse(status="success", reply=reply)

    except Exception as exc:
        # Top-level exception handler - catches any unhandled errors
        logger.error(
            f"[{session_id[:8] if session_id else 'UNKNOWN'}] "
            f"Unhandled error in process_message: {exc}",
            exc_info=True
        )
        # Always return success to evaluator with generic response
        return HoneypotResponse(
            status="success",
            reply="Sorry, I didn't catch that. Can you please repeat?",
        )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
