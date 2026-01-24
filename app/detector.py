"""
Scam detection engine using weighted keyword scoring.

The idea is simple: scammers use predictable language patterns.
We score each message based on suspicious keywords, and when
the cumulative score crosses a threshold, we flag it as a scam.

This approach works better than binary yes/no detection because
scammers often start with innocent-sounding messages and gradually
escalate. The scoring system catches this progression.
"""
import re
from typing import Tuple


class ScamDetector:
    """
    Detects scam messages by analyzing text patterns.
    
    Uses a point-based system where different red flags have different weights.
    A message about "urgent account verification" scores higher than just "hello".
    Scores accumulate across a session so we catch slow-burn scams too.
    """
    
    # Urgency tactics - scammers want you to act before you think
    URGENCY_KEYWORDS = {
        "urgent": 15, "immediately": 15, "right now": 12, "hurry": 12,
        "asap": 12, "quick": 8, "fast": 8, "now": 5,
        "expire": 15, "limited time": 15, "last chance": 18,
        "act now": 18, "don't wait": 12, "today only": 15,
        "within 24 hours": 18, "deadline": 12, "final notice": 20,
        "time sensitive": 15, "running out": 12
    }
    
    # Account/verification scams - pretending to be your bank
    VERIFICATION_KEYWORDS = {
        "verify": 12, "confirm": 10, "update": 8,
        "account suspended": 22, "account blocked": 22, "blocked": 15,
        "deactivated": 18, "suspended": 18, "secure your": 12,
        "validate": 12, "authentication": 10, "kyc": 18,
        "reactivate": 15, "unlock": 12, "restore": 10,
        "verification required": 20, "verify immediately": 25
    }
    
    # Money-related scams - lottery, refunds, prizes
    PAYMENT_KEYWORDS = {
        "refund": 18, "cashback": 15, "reward": 15,
        "prize": 20, "won": 18, "winner": 20, "lottery": 25,
        "transfer": 10, "payment": 8, "bank": 8,
        "upi": 12, "account number": 15, "ifsc": 12,
        "card": 10, "credit": 8, "debit": 8,
        "paytm": 10, "phonepe": 10, "googlepay": 10, "gpay": 10,
        "send money": 18, "pay now": 15, "processing fee": 20,
        "claim your": 18, "collect your": 15
    }
    
    # Threats and intimidation - creating fear
    THREAT_KEYWORDS = {
        "legal action": 25, "police": 20, "arrest": 25,
        "penalty": 18, "fine": 15, "court": 20,
        "jail": 25, "investigation": 18, "case filed": 22,
        "warrant": 25, "fraud case": 22, "cyber crime": 20,
        "legal notice": 22, "fir": 20, "complaint": 12
    }
    
    # Suspicious link patterns
    LINK_PATTERNS = [
        r"https?://[^\s]+",  # Any URL
        r"bit\.ly", r"tinyurl", r"goo\.gl",  # URL shorteners
        r"click here", r"click this", r"tap here",
        r"link:", r"visit:"
    ]
    
    # How many points before we call it a scam
    # Set at 30 so it triggers after 1-2 clearly suspicious messages
    SCAM_THRESHOLD = 30
    
    def __init__(self):
        self.session_scores = {}
    
    def calculate_risk_score(self, text: str, session_id: str) -> Tuple[int, bool]:
        """
        Analyze a message and return its risk score.
        
        Args:
            text: The message content to analyze
            session_id: Unique ID for this conversation
            
        Returns:
            (cumulative_score, is_scam) - total score so far and whether it's a scam
        """
        text_lower = text.lower()
        message_score = 0
        
        # Check each category of suspicious keywords
        all_keywords = [
            self.URGENCY_KEYWORDS,
            self.VERIFICATION_KEYWORDS, 
            self.PAYMENT_KEYWORDS,
            self.THREAT_KEYWORDS
        ]
        
        for keyword_dict in all_keywords:
            for keyword, weight in keyword_dict.items():
                if keyword in text_lower:
                    message_score += weight
        
        # Check for suspicious links
        for pattern in self.LINK_PATTERNS:
            if re.search(pattern, text_lower):
                message_score += 15
                break  # Only count link bonus once
        
        # Initialize session if new
        if session_id not in self.session_scores:
            self.session_scores[session_id] = 0
        
        # Add this message's score to the session total
        self.session_scores[session_id] += message_score
        total_score = self.session_scores[session_id]
        
        # Check if we've crossed the threshold
        is_scam = total_score >= self.SCAM_THRESHOLD
        
        return total_score, is_scam
    
    def get_session_score(self, session_id: str) -> int:
        """Get the current risk score for a session."""
        return self.session_scores.get(session_id, 0)
    
    def reset_session(self, session_id: str) -> None:
        """Clear score for a session (useful for testing)."""
        if session_id in self.session_scores:
            del self.session_scores[session_id]


# Single instance used across the app
detector = ScamDetector()
