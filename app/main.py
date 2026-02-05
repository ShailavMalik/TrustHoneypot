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
    HoneypotResponse
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
    logger.info("API Ready | Docs: /docs | Health: GET / | Honeypot: POST /honeypot")


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Log validation errors clearly."""
    logger.error(f"422 ERROR | {request.url.path} | {exc.errors()}")
    
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
        import json
        
        session_id = request.sessionId
        current_message = request.message.text
        
        # Log full request body in one line
        request_dict = request.model_dump()
        logger.info(f"[{session_id[:8]}] REQUEST: {json.dumps(request_dict, ensure_ascii=False)}")
        
        # Process conversation history for context
        # First, update agent's context awareness from history
        agent.process_conversation_history(session_id, request.conversationHistory)
        
        for hist_msg in request.conversationHistory:
            if hist_msg.sender == "scammer":
                detector.calculate_risk_score(hist_msg.text, session_id)
                extractor.extract(hist_msg.text, session_id)
        
        memory.add_message(session_id, "scammer", current_message)
        
        # Analyze current message
        risk_score, is_scam = detector.calculate_risk_score(current_message, session_id)
        detection_details = detector.get_detection_details(session_id)
        
        if is_scam and not memory.is_scam_confirmed(session_id):
            memory.mark_scam_confirmed(session_id)
        
        # Generate internal agent response (not returned to client)
        scam_confirmed = memory.is_scam_confirmed(session_id)
        # Use actual conversation length from history, not just server memory count
        msg_count = len(request.conversationHistory) + 1
        
        # Always generate a reply using get_reply (handles both scam and non-scam)
        agent_reply = agent.get_reply(session_id, current_message, msg_count, scam_confirmed)
        memory.set_agent_response(session_id, agent_reply)
        memory.add_message(session_id, "agent", agent_reply)
        
        # Extract intelligence
        intelligence = extractor.extract(current_message, session_id)
        
        # Enrich suspiciousKeywords with detected categories for better analysis
        detected_categories = list(detection_details.triggered_categories)
        if detection_details.scam_type and detection_details.scam_type != "unknown":
            detected_categories.append(detection_details.scam_type)
        existing_keywords = intelligence.get("suspiciousKeywords", [])
        intelligence["suspiciousKeywords"] = list(set(existing_keywords + detected_categories))
        
        # Calculate metrics using conversation history length + 1
        total_messages = len(request.conversationHistory) + 1
        duration_seconds = memory.get_duration(session_id)
        
        # Generate notes with enhanced detection details (internal use only)
        if scam_confirmed:
            agent_notes = agent.generate_agent_notes(
                session_id, total_messages, intelligence, detection_details
            )
        else:
            agent_notes = agent.generate_monitoring_notes(session_id, total_messages)
        
        # Send callback if conditions met
        callback_sent = False
        callback_eligible = should_send_callback(scam_confirmed, total_messages, intelligence)
        
        if callback_eligible:
            if not memory.is_callback_sent(session_id):
                success = send_final_callback(session_id, total_messages, intelligence, agent_notes)
                if success:
                    memory.mark_callback_sent(session_id)
                    callback_sent = True
        
        # Build simplified response (only status and reply)
        response = HoneypotResponse(
            status="success",
            reply=agent_reply
        )
        
        # Internal logging - detection result, intelligence, notes, callback (not exposed in response)
        internal_log = {
            "scamDetected": scam_confirmed,
            "engagementMetrics": {
                "engagementDurationSeconds": duration_seconds,
                "totalMessagesExchanged": total_messages
            },
            "extractedIntelligence": {
                "bankAccounts": intelligence.get("bankAccounts", []),
                "upiIds": intelligence.get("upiIds", []),
                "phishingLinks": intelligence.get("phishingLinks", []),
                "phoneNumbers": intelligence.get("phoneNumbers", []),
                "suspiciousKeywords": intelligence.get("suspiciousKeywords", [])
            },
            "agentNotes": agent_notes
        }
        logger.info(f"[{session_id[:8]}] INTERNAL: {json.dumps(internal_log, ensure_ascii=False)}")
        
        # Log simplified response
        response_dict = response.model_dump()
        logger.info(f"[{session_id[:8]}] RESPONSE: {json.dumps(response_dict, ensure_ascii=False)}")
        logger.info(f"[{session_id[:8]}] CALLBACK: {'sent' if callback_sent else 'not sent'}")
        
        return response
        
    except Exception as e:
        logger.error(f"Error processing request: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")


if __name__ == "__main__":
    import uvicorn
    print("Starting Agentic Honey-Pot API...")
    print("Make sure your .env file has API_KEY set")
    uvicorn.run(app, host="0.0.0.0", port=8000)
