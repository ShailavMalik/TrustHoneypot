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


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Log full validation errors to help diagnose 422s from external testers."""
    try:
        body = await request.json()
    except Exception:
        body = None
    logger.error(
        "422 Validation Error on %s: errors=%s, body=%s",
        request.url.path, exc.errors(), body
    )
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
        
        logger.info(f"Session {session_id}: Received message from {request.message.sender}")
        
        # Process conversation history for context
        for hist_msg in request.conversationHistory:
            if hist_msg.sender == "scammer":
                detector.calculate_risk_score(hist_msg.text, session_id)
                extractor.extract(hist_msg.text, session_id)
        
        memory.add_message(session_id, "scammer", current_message)
        
        # Analyze current message
        risk_score, is_scam = detector.calculate_risk_score(current_message, session_id)
        logger.info(f"Session {session_id}: Risk score = {risk_score}, Scam = {is_scam}")
        
        if is_scam and not memory.is_scam_confirmed(session_id):
            memory.mark_scam_confirmed(session_id)
            logger.info(f"Session {session_id}: Scam confirmed!")
        
        # Generate internal agent response (not returned to client)
        if memory.is_scam_confirmed(session_id):
            msg_count = memory.get_message_count(session_id)
            internal_response = agent.generate_response(session_id, current_message, msg_count)
            memory.set_agent_response(session_id, internal_response)
            memory.add_message(session_id, "agent", internal_response)
        
        # Extract intelligence
        intelligence = extractor.extract(current_message, session_id)
        
        # Calculate metrics using conversation history length + 1
        total_messages = len(request.conversationHistory) + 1
        duration_seconds = memory.get_duration(session_id)
        
        # Generate notes with enhanced detection details
        scam_confirmed = memory.is_scam_confirmed(session_id)
        if scam_confirmed:
            detection_details = detector.get_detection_details(session_id)
            agent_notes = agent.generate_agent_notes(
                session_id, total_messages, intelligence, detection_details
            )
        else:
            agent_notes = agent.generate_monitoring_notes(session_id, total_messages)
        
        # Send callback if conditions met
        if should_send_callback(scam_confirmed, total_messages, intelligence):
            if not memory.is_callback_sent(session_id):
                logger.info(f"Session {session_id}: Sending callback...")
                success = send_final_callback(session_id, total_messages, intelligence, agent_notes)
                if success:
                    memory.mark_callback_sent(session_id)
                    logger.info(f"Session {session_id}: Callback sent")
        
        return HoneypotResponse(
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
        
    except Exception as e:
        logger.error(f"Error processing request: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")


if __name__ == "__main__":
    import uvicorn
    print("Starting Agentic Honey-Pot API...")
    print("Make sure your .env file has API_KEY set")
    uvicorn.run(app, host="0.0.0.0", port=8000)
