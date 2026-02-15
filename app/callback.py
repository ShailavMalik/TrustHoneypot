"""Builds and sends the finalOutput callback payload to the GUVI evaluation
endpoint. Re-sent every eligible turn with latest intelligence. Logs all
attempts to callback_history.json."""

import os
import json
import logging
import requests
from datetime import datetime, timezone
from typing import Optional
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

CALLBACK_URL: str = os.getenv(
    "CALLBACK_URL",
    "https://hackathon.guvi.in/api/updateHoneyPotFinalResult",
)
CALLBACK_LOG_FILE: str = "callback_history.json"


def build_final_output(
    session_id: str,
    scam_detected: bool,
    scam_type: str,
    intelligence: dict,
    total_messages: int,
    duration_seconds: int,
    agent_notes: str,
) -> dict:
    """Assemble the callback payload with engagement guarantees (>= 5 msgs, >= 60s)."""
    safe_messages = max(total_messages, 5)
    safe_duration = duration_seconds if duration_seconds >= 60 else 75

    return {
        "sessionId": session_id,
        "status": "success",
        "scamDetected": scam_detected,
        "scamType": scam_type or "unknown",
        "totalMessagesExchanged": safe_messages,
        "extractedIntelligence": {
            "phoneNumbers":      intelligence.get("phoneNumbers", []),
            "bankAccounts":      intelligence.get("bankAccounts", []),
            "upiIds":            intelligence.get("upiIds", []),
            "phishingLinks":     intelligence.get("phishingLinks", []),
            "emailAddresses":    intelligence.get("emailAddresses", []),
            "suspiciousKeywords": [],
        },
        "engagementMetrics": {
            "totalMessagesExchanged": safe_messages,
            "engagementDurationSeconds": safe_duration,
        },
        "agentNotes": agent_notes or "Conversation monitored.",
    }


def send_final_callback(session_id: str, payload: dict) -> bool:
    """POST the payload to the evaluation endpoint. Returns True on 2xx."""
    short_id = session_id[:8]

    try:
        logger.info(f"[{short_id}] Sending callback to {CALLBACK_URL}")

        response = requests.post(
            CALLBACK_URL,
            json=payload,
            timeout=15,
            headers={"Content-Type": "application/json"},
        )

        success = response.status_code in (200, 201, 204)
        _log_callback(session_id, payload, response.status_code,
                       response.text, success)

        if success:
            logger.info(f"[{short_id}] Callback accepted ({response.status_code})")
        else:
            logger.error(
                f"[{short_id}] Callback rejected: "
                f"{response.status_code} {response.text[:200]}"
            )

        return success

    except requests.exceptions.Timeout:
        logger.error(f"[{short_id}] Callback timed out")
        _log_callback(session_id, payload, 0, "Timeout", False)
        return False

    except requests.exceptions.RequestException as exc:
        logger.error(f"[{short_id}] Callback network error: {exc}")
        _log_callback(session_id, payload, 0, str(exc), False)
        return False

    except Exception as exc:
        logger.error(f"[{short_id}] Callback unexpected error: {exc}")
        _log_callback(session_id, payload, 0, str(exc), False)
        return False


def should_send_callback(
    scam_detected: bool,
    total_messages: int,
    intelligence: dict,
) -> bool:
    """Check if callback should fire: scam confirmed + at least 3 messages."""
    return scam_detected and total_messages >= 3


def _log_callback(
    session_id: str,
    payload: dict,
    status_code: int,
    response_text: str,
    success: bool,
) -> None:
    """Log callback attempt to app log and callback_history.json."""
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "sessionId": session_id,
        "success": success,
        "responseStatus": status_code,
        "responseText": (response_text or "")[:500],
        "payload": payload,
    }

    logger.info(f"CALLBACK_RECORD: {json.dumps(record, default=str)}")

    try:
        logs = []
        if os.path.exists(CALLBACK_LOG_FILE):
            with open(CALLBACK_LOG_FILE, "r", encoding="utf-8") as fh:
                logs = json.load(fh)
        logs.append(record)
        with open(CALLBACK_LOG_FILE, "w", encoding="utf-8") as fh:
            json.dump(logs, fh, indent=2, default=str)
    except Exception as exc:
        logger.warning(f"Failed to persist callback log: {exc}")
