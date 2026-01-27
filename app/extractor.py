"""
Intelligence extraction from scammer messages.

This module pulls out actionable data from conversations:
- UPI IDs (like scammer@upi, fraud@paytm)
- Bank account numbers
- Phone numbers (Indian format)
- Suspicious URLs/phishing links
- Keywords that indicate scam tactics

We only extract what the scammer voluntarily shares.
We never ask for OTPs, passwords, or other sensitive info.
"""
import re
from typing import Dict, Set


class IntelligenceExtractor:
    """
    Parses messages for useful scam-related information.
    
    All extracted data is stored per-session so we can build up
    a complete picture as the conversation progresses.
    """
    
    # UPI ID patterns - covers most Indian payment apps
    # Format: username@bankcode (e.g., scammer@paytm, fraud@ybl)
    UPI_PATTERNS = [
        r'\b[\w\.\-]+@(paytm|ybl|okaxis|oksbi|okhdfcbank|okicici|axl|ibl|upi|apl|rapl|waaxis|wahdfcbank|waicici|wasbi|ikwik|freecharge|airtel|jio|pingpay|slice|amazonpay|axisb|sbi|hdfc|icici|kotak|indus|federal|idbi|pnb|bob|union|canara|boi|cbi|iob|andhra|vijaya|allahabad|syndicate|dena|oriental|corporation)\b',
        r'\b[\w\.\-]+@[\w]+\b'  # Generic fallback for less common UPI handles
    ]
    
    # Bank account numbers are 9-18 digits in India
    BANK_ACCOUNT_PATTERN = r'\b[0-9]{9,18}\b'
    
    # Indian phone numbers: +91, 91, or starting with 6-9
    PHONE_PATTERNS = [
        r'\+91[\s\-]?[6-9]\d{9}\b',  # +91 format
        r'\b91[6-9]\d{9}\b',          # 91 prefix without +
        r'\b[6-9]\d{9}\b'             # 10 digit starting with 6-9
    ]
    
    # URL patterns to catch phishing links
    URL_PATTERNS = [
        r'https?://[^\s<>"{}|\\^`\[\]]+',  # Standard URLs
        r'bit\.ly/[a-zA-Z0-9]+',            # Shortened URLs
        r'tinyurl\.com/[a-zA-Z0-9]+',
        r'goo\.gl/[a-zA-Z0-9]+'
    ]
    
    # Keywords that indicate scam tactics
    SUSPICIOUS_KEYWORDS = [
        "urgent", "immediately", "verify", "blocked", "suspended",
        "payment", "prize", "refund", "cashback", "kyc", "account",
        "otp", "bank", "upi", "transfer", "lottery", "winner",
        "legal", "police", "arrest", "confirm", "update"
    ]
    
    def __init__(self):
        self.session_data: Dict[str, Dict[str, Set]] = {}
    
    def _init_session(self, session_id: str) -> None:
        """Initialize storage for a new session."""
        if session_id not in self.session_data:
            self.session_data[session_id] = {
                "bankAccounts": set(),
                "upiIds": set(),
                "phishingLinks": set(),
                "phoneNumbers": set(),
                "suspiciousKeywords": set()
            }
    
    def extract(self, text: str, session_id: str) -> dict:
        """
        Extract all intelligence from a message.
        
        Returns a dict with lists of extracted items.
        Items accumulate across the session.
        """
        self._init_session(session_id)
        data = self.session_data[session_id]
        text_lower = text.lower()
        
        # Extract UPI IDs
        for pattern in self.UPI_PATTERNS:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                # The pattern might return tuple or string depending on groups
                if isinstance(match, tuple):
                    continue  # Skip group captures
                if '@' in text:
                    # Find the full UPI ID around this match
                    upi_full = re.search(r'[\w\.\-]+@[\w]+', text, re.IGNORECASE)
                    if upi_full:
                        data["upiIds"].add(upi_full.group().lower())
        
        # Also try direct UPI pattern match
        direct_upi = re.findall(r'[\w\.\-]+@[a-z]+', text.lower())
        for upi in direct_upi:
            if len(upi) > 5 and '@' in upi:  # Basic sanity check
                data["upiIds"].add(upi)
        
        # Extract bank account numbers
        potential_accounts = re.findall(self.BANK_ACCOUNT_PATTERN, text)
        for acc in potential_accounts:
            # Filter out obvious non-accounts (like phone numbers, years, etc.)
            if len(acc) >= 9 and len(acc) <= 18:
                # Avoid common false positives
                if not acc.startswith('20') or len(acc) > 4:  # Not a year
                    data["bankAccounts"].add(acc)
        
        # Extract phone numbers
        for pattern in self.PHONE_PATTERNS:
            matches = re.findall(pattern, text)
            for phone in matches:
                # Normalize: remove spaces, dashes, + prefix
                cleaned = re.sub(r'[\s\-\+]', '', phone)
                if cleaned.startswith('91') and len(cleaned) == 12:
                    cleaned = cleaned[2:]  # Remove 91 prefix
                if len(cleaned) == 10:
                    data["phoneNumbers"].add(cleaned)
        
        # Extract URLs
        for pattern in self.URL_PATTERNS:
            matches = re.findall(pattern, text)
            for url in matches:
                data["phishingLinks"].add(url)
        
        # Extract suspicious keywords (single words only, normalized)
        for keyword in self.SUSPICIOUS_KEYWORDS:
            if keyword in text_lower:
                data["suspiciousKeywords"].add(keyword)
        
        # Return current session intel as lists
        return {
            "bankAccounts": list(data["bankAccounts"]),
            "upiIds": list(data["upiIds"]),
            "phishingLinks": list(data["phishingLinks"]),
            "phoneNumbers": list(data["phoneNumbers"]),
            "suspiciousKeywords": list(data["suspiciousKeywords"])
        }
    
    def has_intelligence(self, session_id: str) -> bool:
        """Check if we've extracted anything useful from this session."""
        if session_id not in self.session_data:
            return False
        
        data = self.session_data[session_id]
        return any(len(v) > 0 for v in data.values())


# Single instance used across the app
extractor = IntelligenceExtractor()
