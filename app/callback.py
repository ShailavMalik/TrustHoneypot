"""
Callback module for reporting results to GUVI evaluation endpoint.

This is a MANDATORY part of the hackathon requirements. Without sending
this callback, our submission won't be properly evaluated.
"""
import requests
import os
import json
from datetime import datetime
from dotenv import load_dotenv
import logging

load_dotenv()

logger = logging.getLogger(__name__)

# The GUVI endpoint where we submit our final results
CALLBACK_URL = os.getenv("CALLBACK_URL", "https://hackathon.guvi.in/api/updateHoneyPotFinalResult")

# File to store callback history for debugging/audit
CALLBACK_LOG_FILE = "callback_history.json"


def _log_callback(session_id: str, payload: dict, response_status: int, response_text: str, success: bool):
    """Persist callback details to JSON file for audit trail AND log to stdout."""
    callback_record = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "sessionId": session_id,
        "success": success,
        "responseStatus": response_status,
        "responseText": response_text[:500] if response_text else "",
        "payload": payload
    }
    
    # IMPORTANT: Log to stdout for Railway logs (always visible)
    logger.info(f"📞 CALLBACK RECORD: {json.dumps(callback_record, indent=None)}")
    
    try:
        # Also save to local file (works locally, not on Railway)
        if os.path.exists(CALLBACK_LOG_FILE):
            with open(CALLBACK_LOG_FILE, "r") as f:
                logs = json.load(f)
        else:
            logs = []
        
        logs.append(callback_record)
        
        with open(CALLBACK_LOG_FILE, "w") as f:
            json.dump(logs, f, indent=2)
            
    except Exception as e:
        logger.warning(f"Failed to log callback to file: {e}")


def send_final_callback(
    session_id: str,
    total_messages: int,
    intelligence: dict,
    agent_notes: str
) -> bool:
    """
    Send final results to the GUVI hackathon evaluation API.
    
    This gets called once per session when we have:
    - Confirmed it's a scam
    - Engaged enough to gather intel  
    - Extracted at least one piece of useful info
    
    Returns True if the callback was accepted, False otherwise.
    """
    try:
        # Build payload matching the exact format GUVI expects
        payload = {
            "sessionId": session_id,
            "scamDetected": True,
            "totalMessagesExchanged": total_messages,
            "extractedIntelligence": {
                "bankAccounts": intelligence.get("bankAccounts", []),
                "upiIds": intelligence.get("upiIds", []),
                "phishingLinks": intelligence.get("phishingLinks", []),
                "phoneNumbers": intelligence.get("phoneNumbers", []),
                "suspiciousKeywords": intelligence.get("suspiciousKeywords", []),
            },
            "agentNotes": agent_notes
        }
        
        logger.info(f"Sending callback for session {session_id} to {CALLBACK_URL}")
        
        response = requests.post(
            CALLBACK_URL,
            json=payload,
            timeout=10,
            headers={"Content-Type": "application/json"}
        )
        
        # 200, 201, 204 all mean success
        if response.status_code in [200, 201, 204]:
            logger.info(f"Callback accepted for session {session_id}")
            _log_callback(session_id, payload, response.status_code, response.text, True)
            return True
        else:
            logger.error(f"Callback rejected: {response.status_code} - {response.text}")
            _log_callback(session_id, payload, response.status_code, response.text, False)
            return False
            
    except requests.exceptions.Timeout:
        logger.error("Callback timed out after 10 seconds")
        _log_callback(session_id, payload, 0, "Timeout after 10 seconds", False)
        return False
    except requests.exceptions.RequestException as e:
        logger.error(f"Network error sending callback: {str(e)}")
        _log_callback(session_id, payload, 0, f"Network error: {str(e)}", False)
        return False
    except Exception as e:
        logger.error(f"Unexpected error in callback: {str(e)}")
        _log_callback(session_id, payload, 0, f"Unexpected error: {str(e)}", False)
        return False


def should_send_callback(scam_detected: bool, total_messages: int, intelligence: dict) -> bool:
    """
    Check if conditions are met to send the callback.
    Requires: scam confirmed and at least one intel item.
    Changed from 5+ messages to 1+ to ensure callback fires for short test sessions.
    """
    has_intel = any([
        len(intelligence.get("bankAccounts", [])) > 0,
        len(intelligence.get("upiIds", [])) > 0,
        len(intelligence.get("phishingLinks", [])) > 0,
        len(intelligence.get("phoneNumbers", [])) > 0,
    ])
    
    return scam_detected and total_messages >= 1 and has_intel
