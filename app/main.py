"""
Agentic Honey-Pot API
Built for the India AI Impact Buildathon (GUVI) - Problem Statement 2

This is the main entry point for the honeypot system. It receives suspected
scam messages from the GUVI platform, analyzes them, generates responses,
extracts intelligence, and reports back when we've gathered enough info.
"""
from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
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
    """
    Main endpoint that receives and processes scam messages.
    
    The GUVI platform sends suspected scam messages here. We:
    1. Analyze the message for scam indicators
    2. If it looks like a scam, activate the agent to respond
    3. Extract any useful intel (UPI IDs, phone numbers, etc.)
    4. Send results to GUVI when we have enough evidence
    5. Return a structured response with everything we found
    """
    try:
        session_id = request.sessionId
        current_message = request.message.text
        
        logger.info(f"Session {session_id}: Received message from {request.message.sender}")
        
        # Process any conversation history first (for context)
        # This helps us understand multi-turn conversations better
        for hist_msg in request.conversationHistory:
            if hist_msg.sender == "scammer":
                # Run detection on historical messages too
                detector.calculate_risk_score(hist_msg.text, session_id)
                extractor.extract(hist_msg.text, session_id)
        
        # Store this message in our session memory
        memory.add_message(session_id, "scammer", current_message)
        
        # Analyze the current message for scam indicators
        risk_score, is_scam = detector.calculate_risk_score(current_message, session_id)
        logger.info(f"Session {session_id}: Risk score = {risk_score}, Scam = {is_scam}")
        
        # Mark this session as a confirmed scam if we've crossed the threshold
        if is_scam and not memory.is_scam_confirmed(session_id):
            memory.mark_scam_confirmed(session_id)
            logger.info(f"Session {session_id}: Scam confirmed!")
        
        # Generate agent response if this is a confirmed scam
        agent_response = None
        if memory.is_scam_confirmed(session_id):
            msg_count = memory.get_message_count(session_id)
            agent_response = agent.generate_response(session_id, current_message, msg_count)
            memory.set_agent_response(session_id, agent_response)
            memory.add_message(session_id, "agent", agent_response)
            logger.info(f"Session {session_id}: Agent replied - {agent_response[:50]}...")
        
        # Extract intelligence from this message
        intelligence = extractor.extract(current_message, session_id)
        
        # Calculate engagement metrics
        total_messages = memory.get_message_count(session_id)
        duration_seconds = memory.get_duration(session_id)
        
        # Generate notes about the scammer's behavior
        scam_confirmed = memory.is_scam_confirmed(session_id)
        if scam_confirmed:
            agent_notes = agent.generate_agent_notes(session_id, total_messages, intelligence)
        else:
            agent_notes = "Monitoring conversation. Scam not yet confirmed."
        
        # Check if we should send the final callback to GUVI
        # Only happens when: scam confirmed + enough messages + intel extracted
        if should_send_callback(scam_confirmed, total_messages, intelligence):
            if not memory.is_callback_sent(session_id):
                logger.info(f"Session {session_id}: Sending callback to GUVI...")
                success = send_final_callback(
                    session_id,
                    total_messages,
                    intelligence,
                    agent_notes
                )
                if success:
                    memory.mark_callback_sent(session_id)
                    logger.info(f"Session {session_id}: Callback sent successfully")
                else:
                    logger.warning(f"Session {session_id}: Callback failed, will retry")
        
        # Build and return the response
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
            agentNotes=agent_notes,
            agentResponse=agent_response
        )
        
    except Exception as e:
        logger.error(f"Error processing request: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")


if __name__ == "__main__":
    import uvicorn
    print("Starting Agentic Honey-Pot API...")
    print("Make sure your .env file has API_KEY set")
    uvicorn.run(app, host="0.0.0.0", port=8000)
