"""
Agentic Honey-Pot API
Built for the India AI Impact Buildathon (GUVI) - Problem Statement 2

This is the main entry point for the honeypot system. It receives suspected
scam messages from the GUVI platform, analyzes them, generates responses,
extracts intelligence, and reports back when we've gathered enough info.
"""
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
import logging

from app.models import (
    HoneypotRequest,
    HoneypotResponse,
    EngagementMetrics,
    ExtractedIntelligence
)
from app.auth import verify_api_key
from app.detector import detector
from app.extractor import extractor
from app.agent import agent
from app.memory import memory
from app.callback import send_final_callback, should_send_callback

# Set up logging so we can see what's happening
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Create the FastAPI app
app = FastAPI(
    title="Agentic Honey-Pot API",
    description="Scam Detection & Intelligence Extraction for GUVI Hackathon",
    version="1.0.0"
)

# Allow cross-origin requests (needed for the evaluation platform)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def startup_event():
    """Log essential startup information"""
    logger.info("✅ API ready at http://127.0.0.1:8000")
    logger.info("📚 Docs: http://127.0.0.1:8000/docs")
    logger.info("🏥 Health: GET /")
    logger.info("🍯 Honeypot: POST /honeypot")


@app.middleware("http")
async def log_all_requests(request: Request, call_next):
    """Log incoming requests (simplified for readability)."""
    import json
    
    # Only log path and method for non-health endpoints
    if request.url.path != "/":
        logger.info(f"→ {request.method} {request.url.path}")
    
    # Process request
    response = await call_next(request)
    
    return response


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Log validation errors clearly."""
    logger.error("=" * 60)
    logger.error("[VALIDATION ERROR - 422]")
    logger.error("-" * 60)
    logger.error(f"Path: {request.url.path}")
    logger.error(f"Errors: {exc.errors()}")
    logger.error("=" * 60)
    
    return JSONResponse(
        status_code=422,
        content={
            "detail": exc.errors(),
            "message": "Invalid request payload. See detail for exact fields.",
        },
    )


@app.get("/")
async def health_check():
    """Simple health check - lets the platform know we're alive."""
    return {
        "status": "online",
        "service": "Agentic Honey-Pot API",
        "version": "1.0.0"
    }


@app.post("/honeypot", response_model=HoneypotResponse)
async def process_message(
    request: HoneypotRequest,
    api_key: str = Depends(verify_api_key)
):
    """Process incoming scam messages and return analysis results."""
    try:
        session_id = request.sessionId
        current_message = request.message.text
        
        # ============================================================
        # [REQUEST RECEIVED]
        # ============================================================
        logger.info("=" * 60)
        logger.info("[REQUEST RECEIVED]")
        logger.info("-" * 60)
        logger.info(f"Session ID      : {session_id}")
        logger.info(f"Sender          : {request.message.sender}")
        logger.info(f"Message         : {current_message[:120]}{'...' if len(current_message) > 120 else ''}")
        logger.info(f"History Count   : {len(request.conversationHistory)} messages")
        if request.metadata:
            logger.info(f"Channel         : {request.metadata.channel}")
        logger.info("-" * 60)
        
        # Process conversation history for context
        for hist_msg in request.conversationHistory:
            if hist_msg.sender == "scammer":
                detector.calculate_risk_score(hist_msg.text, session_id)
                extractor.extract(hist_msg.text, session_id)
        
        memory.add_message(session_id, "scammer", current_message)
        
        # Analyze current message
        risk_score, is_scam = detector.calculate_risk_score(current_message, session_id)
        detection_details = detector.get_detection_details(session_id)
        
        # ============================================================
        # [SCAM ANALYSIS]
        # ============================================================
        logger.info("[SCAM ANALYSIS]")
        logger.info("-" * 60)
        logger.info(f"Risk Score      : {risk_score}/100")
        logger.info(f"Risk Level      : {detection_details.risk_level.upper()}")
        logger.info(f"Scam Detected   : {is_scam}")
        logger.info(f"Scam Type       : {detection_details.scam_type}")
        logger.info(f"Confidence      : {detection_details.confidence*100:.0f}%")
        logger.info("-" * 60)
        
        if is_scam and not memory.is_scam_confirmed(session_id):
            memory.mark_scam_confirmed(session_id)
            logger.info(f"⚠️  SCAM CONFIRMED for session {session_id}")
        
        # Generate internal agent response (not returned to client)
        if memory.is_scam_confirmed(session_id):
            msg_count = memory.get_message_count(session_id)
            internal_response = agent.generate_response(session_id, current_message, msg_count)
            memory.set_agent_response(session_id, internal_response)
            memory.add_message(session_id, "agent", internal_response)
        
        # Extract intelligence
        intelligence = extractor.extract(current_message, session_id)
        intel_summary = extractor.get_intelligence_summary(session_id)
        
        # Mask PII in logs
        def mask_pii(data):
            """Mask sensitive data for logging."""
            masked = {}
            if data.get("upiIds"):
                masked["UPI IDs"] = f"{len(data['upiIds'])} found (masked)"
            if data.get("phoneNumbers"):
                masked["Phone Numbers"] = f"{len(data['phoneNumbers'])} found (masked)"
            if data.get("bankAccounts"):
                masked["Bank Accounts"] = f"{len(data['bankAccounts'])} found (masked)"
            if data.get("phishingLinks"):
                masked["Links"] = f"{len(data['phishingLinks'])} found"
            if data.get("emails"):
                masked["Emails"] = f"{len(data['emails'])} found"
            return masked
        
        # ============================================================
        # [INTELLIGENCE STATUS]
        # ============================================================
        logger.info("[INTELLIGENCE EXTRACTED]")
        logger.info("-" * 60)
        masked_intel = mask_pii(intelligence)
        if masked_intel:
            for key, value in masked_intel.items():
                logger.info(f"{key:20}: {value}")
        else:
            logger.info("No intelligence extracted yet")
        logger.info("-" * 60)
        
        # Enrich suspiciousKeywords with detected categories for better analysis
        detected_categories = list(detection_details.triggered_categories)
        if detection_details.scam_type and detection_details.scam_type != "unknown":
            detected_categories.append(detection_details.scam_type)
        existing_keywords = intelligence.get("suspiciousKeywords", [])
        intelligence["suspiciousKeywords"] = list(set(existing_keywords + detected_categories))
        
        # Calculate metrics using conversation history length + 1
        total_messages = len(request.conversationHistory) + 1
        duration_seconds = memory.get_duration(session_id)
        
        # Generate notes with enhanced detection details
        scam_confirmed = memory.is_scam_confirmed(session_id)
        if scam_confirmed:
            agent_notes = agent.generate_agent_notes(
                session_id, total_messages, intelligence, detection_details
            )
        else:
            agent_notes = agent.generate_monitoring_notes(session_id, total_messages)
        
        # Send callback if conditions met
        callback_sent = False
        callback_eligible = should_send_callback(scam_confirmed, total_messages, intelligence)
        
        # ============================================================
        # [CALLBACK STATUS]
        # ============================================================
        logger.info("[CALLBACK STATUS]")
        logger.info("-" * 60)
        logger.info(f"Scam Confirmed  : {scam_confirmed}")
        logger.info(f"Message Count   : {total_messages}")
        logger.info(f"Has Intel       : {bool(masked_intel)}")
        logger.info(f"Eligible        : {callback_eligible}")
        
        if callback_eligible:
            if not memory.is_callback_sent(session_id):
                logger.info("Sending callback to GUVI...")
                success = send_final_callback(session_id, total_messages, intelligence, agent_notes)
                if success:
                    memory.mark_callback_sent(session_id)
                    callback_sent = True
                    logger.info("✅ Callback sent successfully")
                else:
                    logger.info("❌ Callback failed")
            else:
                logger.info("⏭️  Callback already sent for this session")
        else:
            logger.info("⏸️  Callback not eligible yet")
        logger.info("-" * 60)
        
        response = HoneypotResponse(
            status="success",
            scamDetected=scam_confirmed,
            engagementMetrics=EngagementMetrics(
                engagementDurationSeconds=duration_seconds,
                totalMessagesExchanged=total_messages
            ),
            extractedIntelligence=ExtractedIntelligence(
                bankAccounts=intelligence.get("bankAccounts", []),
                upiIds=intelligence.get("upiIds", []),
                phishingLinks=intelligence.get("phishingLinks", []),
                phoneNumbers=intelligence.get("phoneNumbers", []),
                suspiciousKeywords=intelligence.get("suspiciousKeywords", [])
            ),
            agentNotes=agent_notes
        )
        
        # ============================================================
        # [RESPONSE]
        # ============================================================
        logger.info("[RESPONSE SENT]")
        logger.info("-" * 60)
        logger.info(f"Status          : success")
        logger.info(f"Scam Detected   : {scam_confirmed}")
        logger.info(f"Duration        : {duration_seconds}s")
        logger.info(f"Callback Sent   : {callback_sent}")
        logger.info("=" * 60)
        logger.info("")
        
        return response
        
    except Exception as e:
        logger.error(f"Error processing request: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")


if __name__ == "__main__":
    import uvicorn
    print("Starting Agentic Honey-Pot API...")
    print("Make sure your .env file has API_KEY set")
    uvicorn.run(app, host="0.0.0.0", port=8000)
