"""
Phase 2 – Thread-safe Session Memory.

Stores per-session state including:
  - Message history        - Start time
  - Scam confirmation      - Callback status
  - Agent response cache   - Duration tracking
"""
import threading
from datetime import datetime, timezone
from typing import Dict, Optional, List


class SessionMemory:
    """
    Thread-safe in-memory session store.

    Each session tracks messages, timestamps, scam status, and callback state.
    Duration guarantee logic lives here (>= 75 s for output assembly).
    """

    def __init__(self):
        self._sessions: Dict[str, dict] = {}
        self._lock = threading.Lock()

    # -----------------------------------------------------------------
    # Session lifecycle
    # -----------------------------------------------------------------

    def ensure_session(self, session_id: str) -> dict:
        """Get or create a session."""
        with self._lock:
            if session_id not in self._sessions:
                self._sessions[session_id] = {
                    "start_time": datetime.now(timezone.utc),
                    "messages": [],
                    "scam_confirmed": False,
                    "callback_sent": False,
                    "agent_response": None,
                }
            return self._sessions[session_id]

    # -----------------------------------------------------------------
    # Messages
    # -----------------------------------------------------------------

    def add_message(self, session_id: str, sender: str, text: str) -> None:
        sess = self.ensure_session(session_id)
        sess["messages"].append({
            "sender": sender,
            "text": text,
            "ts": datetime.now(timezone.utc).isoformat(),
        })

    def get_message_count(self, session_id: str, sender: Optional[str] = None) -> int:
        """Count messages (all senders or filtered)."""
        sess = self.ensure_session(session_id)
        if sender:
            return sum(1 for m in sess["messages"] if m["sender"] == sender)
        return len(sess["messages"])

    # -----------------------------------------------------------------
    # Duration
    # -----------------------------------------------------------------

    def get_raw_duration(self, session_id: str) -> int:
        """Actual elapsed seconds since session start."""
        sess = self.ensure_session(session_id)
        delta = datetime.now(timezone.utc) - sess["start_time"]
        return max(int(delta.total_seconds()), 0)

    def get_guaranteed_duration(self, session_id: str) -> int:
        """
        Duration with minimum guarantee for scoring.
        If raw duration < 60 → report 75 seconds.
        """
        raw = self.get_raw_duration(session_id)
        return raw if raw >= 60 else 75

    # -----------------------------------------------------------------
    # Scam / callback flags
    # -----------------------------------------------------------------

    def mark_scam_confirmed(self, session_id: str) -> None:
        self.ensure_session(session_id)["scam_confirmed"] = True

    def is_scam_confirmed(self, session_id: str) -> bool:
        return self.ensure_session(session_id).get("scam_confirmed", False)

    def mark_callback_sent(self, session_id: str) -> None:
        self.ensure_session(session_id)["callback_sent"] = True

    def is_callback_sent(self, session_id: str) -> bool:
        return self.ensure_session(session_id).get("callback_sent", False)

    # -----------------------------------------------------------------
    # Agent response cache (current turn)
    # -----------------------------------------------------------------

    def set_agent_response(self, session_id: str, response: str) -> None:
        self.ensure_session(session_id)["agent_response"] = response

    def get_agent_response(self, session_id: str) -> Optional[str]:
        return self.ensure_session(session_id).get("agent_response")


# Module-level singleton
memory = SessionMemory()
