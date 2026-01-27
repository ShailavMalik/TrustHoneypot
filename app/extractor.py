"""
Advanced Intelligence Extraction from Scammer Messages.

This module pulls out actionable data from conversations with enhanced
detection capabilities for India-specific identifiers:

- UPI IDs (like scammer@upi, fraud@paytm)
- Bank account numbers (with IFSC codes)
- Phone numbers (Indian format, multiple patterns)
- Email addresses
- Suspicious URLs/phishing links
- Aadhaar numbers (masked for privacy: XXXX-XXXX-1234)
- PAN card numbers (masked: XXXXX1234X)
- Crypto wallet addresses
- App-specific identifiers (WhatsApp, Telegram)
- Keywords that indicate scam tactics

We only extract what the scammer voluntarily shares.
We never ask for OTPs, passwords, or other sensitive info.
"""
import re
from typing import Dict, Set, List


class IntelligenceExtractor:
    """
    Advanced parser for extracting scam-related intelligence.
    
    All extracted data is stored per-session so we can build up
    a complete picture as the conversation progresses.
    
    Privacy-conscious: Aadhaar and PAN are masked in output.
    """
    
    # =========================================================================
    # UPI ID PATTERNS - Covers all major Indian payment apps
    # =========================================================================
    
    # Known UPI handles (major banks and payment apps)
    UPI_HANDLES = [
        "paytm", "ybl", "okaxis", "oksbi", "okhdfcbank", "okicici",
        "axl", "ibl", "upi", "apl", "rapl", "waaxis", "wahdfcbank",
        "waicici", "wasbi", "ikwik", "freecharge", "airtel", "jio",
        "pingpay", "slice", "amazonpay", "axisb", "sbi", "hdfc",
        "icici", "kotak", "indus", "federal", "idbi", "pnb", "bob",
        "union", "canara", "boi", "cbi", "iob", "jupiter", "fi",
        "groww", "cred", "bharatpe", "navi", "mobikwik", "postpe"
    ]
    
    UPI_PATTERN = r'\b[\w\.\-]+@(' + '|'.join(UPI_HANDLES) + r')\b'
    UPI_GENERIC_PATTERN = r'\b[\w\.\-]{3,}@[a-z]{2,15}\b'
    
    # =========================================================================
    # BANK ACCOUNT PATTERNS
    # =========================================================================
    
    # Bank account: 9-18 digits
    BANK_ACCOUNT_PATTERN = r'\b[0-9]{9,18}\b'
    
    # IFSC Code: 4 letters + 0 + 6 alphanumeric
    IFSC_PATTERN = r'\b[A-Z]{4}0[A-Z0-9]{6}\b'
    
    # =========================================================================
    # PHONE NUMBER PATTERNS - Multiple Indian formats
    # =========================================================================
    
    PHONE_PATTERNS = [
        r'\+91[\s\-]?[6-9]\d{9}\b',      # +91 9876543210
        r'\b91[\s\-]?[6-9]\d{9}\b',       # 91 9876543210
        r'\b[6-9]\d{9}\b',                 # 9876543210
        r'\b[6-9]\d{4}[\s\-]?\d{5}\b',    # 98765-43210 or 98765 43210
        r'\(\+91\)[\s\-]?[6-9]\d{9}',     # (+91) 9876543210
    ]
    
    # =========================================================================
    # EMAIL PATTERN
    # =========================================================================
    
    EMAIL_PATTERN = r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
    
    # =========================================================================
    # AADHAAR PATTERN (12 digits, various formats)
    # =========================================================================
    
    AADHAAR_PATTERNS = [
        r'\b[2-9]\d{3}[\s\-]?\d{4}[\s\-]?\d{4}\b',  # XXXX XXXX XXXX or XXXX-XXXX-XXXX
        r'\b[2-9]\d{11}\b',                           # 12 continuous digits starting with 2-9
    ]
    
    # =========================================================================
    # PAN CARD PATTERN (AAAAA9999A format)
    # =========================================================================
    
    PAN_PATTERN = r'\b[A-Z]{3}[ABCFGHLJPTK][A-Z][0-9]{4}[A-Z]\b'
    
    # =========================================================================
    # CRYPTO WALLET PATTERNS
    # =========================================================================
    
    CRYPTO_PATTERNS = {
        "bitcoin": r'\b(1|3|bc1)[a-zA-HJ-NP-Z0-9]{25,62}\b',
        "ethereum": r'\b0x[a-fA-F0-9]{40}\b',
        "usdt_trc20": r'\bT[a-zA-Z0-9]{33}\b',
    }
    
    # =========================================================================
    # URL/LINK PATTERNS
    # =========================================================================
    
    URL_PATTERNS = [
        r'https?://[^\s<>"{}|\\^`\[\]]+',
        r'bit\.ly/[a-zA-Z0-9]+',
        r'tinyurl\.com/[a-zA-Z0-9]+',
        r'goo\.gl/[a-zA-Z0-9]+',
        r't\.co/[a-zA-Z0-9]+',
        r'rb\.gy/[a-zA-Z0-9]+',
        r'wa\.me/[0-9]+',  # WhatsApp links
        r't\.me/[a-zA-Z0-9_]+',  # Telegram links
    ]
    
    # =========================================================================
    # MESSAGING APP IDENTIFIERS
    # =========================================================================
    
    WHATSAPP_PATTERN = r'(?:whatsapp|wa)[\s:]*\+?[0-9]{10,13}'
    TELEGRAM_PATTERN = r'(?:telegram|tg)[\s:@]*[a-zA-Z0-9_]{5,32}'
    
    # =========================================================================
    # SUSPICIOUS KEYWORDS (Enhanced list)
    # =========================================================================
    
    # Keywords must be specific enough to avoid false positives
    # Using longer phrases where single words are too common
    SUSPICIOUS_KEYWORDS = [
        # Urgency - more specific phrases
        "urgent", "immediately", "asap", "hurry up", "act now", "right now",
        # Verification/Account - scam-specific terms
        "verify your", "blocked account", "suspended", "kyc update", "account deactivated",
        # Money - scam-specific terms
        "prize money", "refund pending", "cashback offer", "lottery winner",
        "money transfer", "upi payment",
        # Identity - document-related
        "aadhaar card", "aadhar number", "pan card", "share otp", "enter otp",
        # Threats - specific phrases
        "legal action", "police case", "arrest warrant", "court notice", "case filed",
        # Government impersonation
        "rbi notice", "trai notice", "income tax", "customs department", "cbi officer",
        # Jobs/Loans - scam patterns
        "work from home job", "instant loan", "investment opportunity",
        # Actions - scam-specific
        "click here", "click this link", "send money", "share details"
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
                "suspiciousKeywords": set(),
                # New extraction types
                "emails": set(),
                "aadhaarNumbers": set(),
                "panNumbers": set(),
                "ifscCodes": set(),
                "cryptoWallets": set(),
                "messagingIds": set(),
            }
    
    def _mask_aadhaar(self, aadhaar: str) -> str:
        """Mask Aadhaar for privacy: XXXX-XXXX-1234."""
        clean = re.sub(r'[\s\-]', '', aadhaar)
        if len(clean) == 12:
            return f"XXXX-XXXX-{clean[-4:]}"
        return aadhaar
    
    def _mask_pan(self, pan: str) -> str:
        """Mask PAN for privacy: XXXXX1234X."""
        if len(pan) == 10:
            return f"XXXXX{pan[5:9]}X"
        return pan
    
    def extract(self, text: str, session_id: str) -> dict:
        """
        Extract all intelligence from a message.
        
        Returns a dict with lists of extracted items.
        Items accumulate across the session.
        """
        self._init_session(session_id)
        data = self.session_data[session_id]
        text_lower = text.lower()
        
        # -----------------------------------------------------------------
        # Extract UPI IDs (known handles)
        # -----------------------------------------------------------------
        known_upis = re.findall(self.UPI_PATTERN, text, re.IGNORECASE)
        for _ in known_upis:
            full_matches = re.findall(r'[\w\.\-]+@[a-z]+', text.lower())
            for upi in full_matches:
                if len(upi) > 5:
                    data["upiIds"].add(upi)
        
        # Also try generic UPI pattern
        generic_upis = re.findall(self.UPI_GENERIC_PATTERN, text, re.IGNORECASE)
        for upi in generic_upis:
            if len(upi) > 5 and '@' in upi:
                # Exclude emails from UPI detection
                if not re.match(self.EMAIL_PATTERN, upi):
                    data["upiIds"].add(upi.lower())
        
        # -----------------------------------------------------------------
        # Extract Bank Accounts and IFSC
        # -----------------------------------------------------------------
        potential_accounts = re.findall(self.BANK_ACCOUNT_PATTERN, text)
        for acc in potential_accounts:
            if 9 <= len(acc) <= 18:
                # Filter out dates, years, phone numbers, aadhaar
                if not (acc.startswith('20') and len(acc) == 4):  # Not a year
                    if not re.match(r'^[6-9]\d{9}$', acc):  # Not a phone
                        if len(acc) != 12:  # Probably not Aadhaar
                            data["bankAccounts"].add(acc)
        
        ifsc_codes = re.findall(self.IFSC_PATTERN, text.upper())
        for ifsc in ifsc_codes:
            data["ifscCodes"].add(ifsc)
        
        # -----------------------------------------------------------------
        # Extract Phone Numbers
        # -----------------------------------------------------------------
        for pattern in self.PHONE_PATTERNS:
            matches = re.findall(pattern, text)
            for phone in matches:
                cleaned = re.sub(r'[\s\-\+\(\)]', '', phone)
                if cleaned.startswith('91') and len(cleaned) == 12:
                    cleaned = cleaned[2:]
                if len(cleaned) == 10 and cleaned[0] in '6789':
                    data["phoneNumbers"].add(cleaned)
        
        # -----------------------------------------------------------------
        # Extract Emails
        # -----------------------------------------------------------------
        emails = re.findall(self.EMAIL_PATTERN, text)
        for email in emails:
            # Exclude known UPI handles from being treated as email
            domain = email.split('@')[1].lower()
            if domain not in self.UPI_HANDLES and '.' in domain:
                data["emails"].add(email.lower())
        
        # -----------------------------------------------------------------
        # Extract Aadhaar (masked for privacy)
        # -----------------------------------------------------------------
        for pattern in self.AADHAAR_PATTERNS:
            matches = re.findall(pattern, text)
            for match in matches:
                clean = re.sub(r'[\s\-]', '', match)
                if len(clean) == 12 and clean[0] in '23456789':
                    # Additional validation: Aadhaar can't start with 0 or 1
                    masked = self._mask_aadhaar(clean)
                    data["aadhaarNumbers"].add(masked)
        
        # -----------------------------------------------------------------
        # Extract PAN (masked for privacy)
        # -----------------------------------------------------------------
        pan_matches = re.findall(self.PAN_PATTERN, text.upper())
        for pan in pan_matches:
            masked = self._mask_pan(pan)
            data["panNumbers"].add(masked)
        
        # -----------------------------------------------------------------
        # Extract Crypto Wallets
        # -----------------------------------------------------------------
        for crypto_type, pattern in self.CRYPTO_PATTERNS.items():
            matches = re.findall(pattern, text)
            for wallet in matches:
                data["cryptoWallets"].add(f"{crypto_type}:{wallet[:8]}...{wallet[-6:]}")
        
        # -----------------------------------------------------------------
        # Extract URLs/Links
        # -----------------------------------------------------------------
        for pattern in self.URL_PATTERNS:
            matches = re.findall(pattern, text)
            for url in matches:
                data["phishingLinks"].add(url)
        
        # -----------------------------------------------------------------
        # Extract Messaging IDs (WhatsApp, Telegram)
        # -----------------------------------------------------------------
        wa_matches = re.findall(self.WHATSAPP_PATTERN, text, re.IGNORECASE)
        for wa in wa_matches:
            data["messagingIds"].add(f"whatsapp:{wa}")
        
        tg_matches = re.findall(self.TELEGRAM_PATTERN, text, re.IGNORECASE)
        for tg in tg_matches:
            data["messagingIds"].add(f"telegram:{tg}")
        
        # -----------------------------------------------------------------
        # Extract Suspicious Keywords (using word boundary matching)
        # -----------------------------------------------------------------
        for keyword in self.SUSPICIOUS_KEYWORDS:
            # Use word boundary regex to avoid false positives
            pattern = r'\b' + re.escape(keyword) + r'\b'
            if re.search(pattern, text_lower):
                data["suspiciousKeywords"].add(keyword)
        
        # Return current session intel as lists (main fields for API response)
        return {
            "bankAccounts": list(data["bankAccounts"]),
            "upiIds": list(data["upiIds"]),
            "phishingLinks": list(data["phishingLinks"]),
            "phoneNumbers": list(data["phoneNumbers"]),
            "suspiciousKeywords": list(data["suspiciousKeywords"]),
            # Additional intelligence (can be accessed separately)
            "emails": list(data["emails"]),
            "aadhaarNumbers": list(data["aadhaarNumbers"]),
            "panNumbers": list(data["panNumbers"]),
            "ifscCodes": list(data["ifscCodes"]),
            "cryptoWallets": list(data["cryptoWallets"]),
            "messagingIds": list(data["messagingIds"]),
        }
    
    def has_intelligence(self, session_id: str) -> bool:
        """Check if we've extracted anything useful from this session."""
        if session_id not in self.session_data:
            return False
        
        data = self.session_data[session_id]
        # Check all extraction fields
        important_fields = [
            "bankAccounts", "upiIds", "phishingLinks", "phoneNumbers",
            "emails", "aadhaarNumbers", "panNumbers", "ifscCodes",
            "cryptoWallets", "messagingIds"
        ]
        return any(len(data.get(f, set())) > 0 for f in important_fields)
    
    def get_intelligence_summary(self, session_id: str) -> Dict[str, int]:
        """Get a count summary of extracted intelligence."""
        if session_id not in self.session_data:
            return {}
        
        data = self.session_data[session_id]
        return {k: len(v) for k, v in data.items() if len(v) > 0}
    
    def get_all_identifiers(self, session_id: str) -> List[str]:
        """Get all extracted identifiers as a flat list for reporting."""
        if session_id not in self.session_data:
            return []
        
        data = self.session_data[session_id]
        identifiers = []
        
        for upi in data["upiIds"]:
            identifiers.append(f"UPI: {upi}")
        for phone in data["phoneNumbers"]:
            identifiers.append(f"Phone: {phone}")
        for email in data["emails"]:
            identifiers.append(f"Email: {email}")
        for bank in data["bankAccounts"]:
            identifiers.append(f"Bank Acc: {bank}")
        for ifsc in data["ifscCodes"]:
            identifiers.append(f"IFSC: {ifsc}")
        for aadhaar in data["aadhaarNumbers"]:
            identifiers.append(f"Aadhaar: {aadhaar}")
        for pan in data["panNumbers"]:
            identifiers.append(f"PAN: {pan}")
        for link in data["phishingLinks"]:
            identifiers.append(f"Link: {link}")
        for crypto in data["cryptoWallets"]:
            identifiers.append(f"Crypto: {crypto}")
        for msg_id in data["messagingIds"]:
            identifiers.append(f"Messaging: {msg_id}")
        
        return identifiers


# Single instance used across the app
extractor = IntelligenceExtractor()


# Single instance used across the app
extractor = IntelligenceExtractor()
