"""
Callback module for reporting results to GUVI evaluation endpoint.

This is a MANDATORY part of the hackathon requirements. Without sending
this callback, our submission won't be properly evaluated.
"""
import requests
import os
from dotenv import load_dotenv
import logging

load_dotenv()

logger = logging.getLogger(__name__)

# The GUVI endpoint where we submit our final results
CALLBACK_URL = os.getenv("CALLBACK_URL", "https://hackathon.guvi.in/api/updateHoneyPotFinalResult")


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
            return True
        else:
            logger.error(f"Callback rejected: {response.status_code} - {response.text}")
            return False
            
    except requests.exceptions.Timeout:
        logger.error("Callback timed out after 10 seconds")
        return False
    except requests.exceptions.RequestException as e:
        logger.error(f"Network error sending callback: {str(e)}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error in callback: {str(e)}")
        return False


def should_send_callback(scam_detected: bool, total_messages: int, intelligence: dict) -> bool:
    """
    Check if we should send the final callback to GUVI.
    
    We only send when ALL of these are true:
    1. We've confirmed it's a scam
    2. We've exchanged enough messages (at least 3)
    3. We've extracted at least one piece of intelligence
    
    The threshold of 3 messages balances engagement depth with efficiency.
    """
    # Do we have any intel to report?
    has_intel = any([
        len(intelligence.get("bankAccounts", [])) > 0,
        len(intelligence.get("upiIds", [])) > 0,
        len(intelligence.get("phishingLinks", [])) > 0,
        len(intelligence.get("phoneNumbers", [])) > 0,
        len(intelligence.get("suspiciousKeywords", [])) > 0,
    ])
    
    # All three conditions must be met
    return scam_detected and total_messages >= 3 and has_intel
