"""
Phase 2 – Intelligence Extraction Engine (IntelligenceStore).

Dynamically extracts actionable identifiers from scammer messages using
generic regex patterns. All data is deduplicated and stored per session.

Extracted entity types:
  - Phone numbers  (all Indian formats incl. +91, spaced, dashed)
  - Bank accounts  (9-18 consecutive digits, filtered)
  - UPI IDs        (name@provider pattern)
  - URLs           (http/https, shorteners, suspicious TLDs)
  - Email addresses
  - Reference / case IDs (generic numeric identifiers)
"""
import re
import threading
from typing import Dict, Set, List


class IntelligenceStore:
    """
    Thread-safe, per-session intelligence accumulator.

    Public API
    ----------
    extract(text, session_id) -> dict   Process a message, return current intel.
    get_intelligence(session_id) -> dict  Return accumulated intelligence.
    has_intelligence(session_id) -> bool  Any actionable data gathered?
    """

    # =================================================================
    # PHONE NUMBER PATTERNS  (Indian formats)
    # =================================================================
    PHONE_PATTERNS = [
        r'\+91[\s\-]?[6-9]\d{9}\b',
        r'\b91[\s\-]?[6-9]\d{9}\b',
        r'\b0[6-9]\d{9}\b',
        r'\b[6-9]\d{9}\b',
        r'\b[6-9]\d{4}[\s\-]\d{5}\b',
        r'\b[6-9]\d{2}[\s\-]\d{3}[\s\-]\d{4}\b',
        r'\(\+91\)[\s\-]?[6-9]\d{9}',
    ]

    # =================================================================
    # BANK ACCOUNT  (9-18 digits)
    # =================================================================
    BANK_ACCOUNT_PATTERN = r'\b\d{9,18}\b'

    # =================================================================
    # UPI IDs  (generic name@provider)
    # =================================================================
    UPI_PATTERN = r'\b[\w.\-]{2,}@[a-zA-Z]{2,20}\b'

    # =================================================================
    # EMAIL
    # =================================================================
    EMAIL_PATTERN = r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b'

    # =================================================================
    # URLs / LINKS
    # =================================================================
    URL_PATTERNS = [
        r'https?://[^\s<>"{}|\\^`\[\]]+',
        r'\b(?:bit\.ly|tinyurl\.com|goo\.gl|t\.co|rb\.gy|is\.gd|cutt\.ly|shorturl\.at|ow\.ly)/[a-zA-Z0-9\-_]+',
        r'\bwa\.me/[0-9]+',
        r'\bt\.me/[a-zA-Z0-9_]+',
        r'\b[a-z0-9]{4,}\.(?:xyz|top|online|site|work|click)[^\s]*',
    ]

    # =================================================================
    # REFERENCE / CASE IDs  (generic numeric identifiers)
    # =================================================================
    REFERENCE_PATTERNS = [
        r'\b(?:ref|reference|case|complaint|ticket|order|txn|transaction)\s*(?:no|number|id|#)?[\s:.#\-]*([A-Z0-9\-]{4,20})\b',
    ]

    # Known UPI providers (used to disambiguate UPI from email)
    _UPI_PROVIDERS = {
        "paytm", "ybl", "okaxis", "oksbi", "okhdfcbank", "okicici",
        "axl", "ibl", "upi", "apl", "rapl", "waaxis", "wahdfcbank",
        "waicici", "wasbi", "ikwik", "freecharge", "airtel", "jio",
        "pingpay", "slice", "amazonpay", "postpe", "axisb", "sbi",
        "hdfc", "icici", "kotak", "indus", "federal", "idbi", "pnb",
        "bob", "union", "canara", "boi", "cbi", "iob", "jupiter",
        "fi", "groww", "cred", "bharatpe", "navi", "mobikwik",
        "yesbank", "rbl", "dbs", "hsbc", "scb", "citi", "barodapay",
        "aubank", "bandhan", "payzapp", "phonepe", "gpay", "googlepay",
    }

    def __init__(self):
        self._store: Dict[str, Dict[str, Set[str]]] = {}
        self._lock = threading.Lock()

    # -----------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------

    def extract(self, text: str, session_id: str) -> dict:
        """Extract all intelligence from *text* and merge into session store."""
        if not text or not text.strip():
            return self.get_intelligence(session_id)

        data = self._init_session(session_id)

        self._extract_phones(text, data)
        self._extract_bank_accounts(text, data)
        self._extract_upi_ids(text, data)
        self._extract_emails(text, data)
        self._extract_urls(text, data)
        self._extract_references(text, data)

        return self.get_intelligence(session_id)

    def get_intelligence(self, session_id: str) -> dict:
        """Return deduplicated intelligence dict for the session."""
        data = self._init_session(session_id)
        return {
            "phoneNumbers":   sorted(data["phoneNumbers"]),
            "bankAccounts":   sorted(data["bankAccounts"]),
            "upiIds":         sorted(data["upiIds"]),
            "phishingLinks":  sorted(data["phishingLinks"]),
            "emailAddresses": sorted(data["emailAddresses"]),
        }

    def has_intelligence(self, session_id: str) -> bool:
        data = self._init_session(session_id)
        return any(len(data[k]) > 0 for k in
                   ("phoneNumbers", "bankAccounts", "upiIds",
                    "phishingLinks", "emailAddresses"))

    # -----------------------------------------------------------------
    # Extraction helpers
    # -----------------------------------------------------------------

    def _extract_phones(self, text: str, data: Dict[str, Set[str]]):
        for pattern in self.PHONE_PATTERNS:
            for match in re.findall(pattern, text):
                cleaned = re.sub(r'[\s\-+()]', '', match)
                if cleaned.startswith('91') and len(cleaned) == 12:
                    cleaned = cleaned[2:]
                elif cleaned.startswith('0') and len(cleaned) == 11:
                    cleaned = cleaned[1:]
                if len(cleaned) == 10 and cleaned[0] in '6789':
                    data["phoneNumbers"].add(cleaned)

    def _extract_bank_accounts(self, text: str, data: Dict[str, Set[str]]):
        for match in re.findall(self.BANK_ACCOUNT_PATTERN, text):
            n = len(match)
            if n < 9 or n > 18:
                continue
            # Filter out likely phone numbers
            if n == 10 and match[0] in '6789':
                continue
            # Filter out likely years
            if n == 4 and match.startswith('20'):
                continue
            # Filter out 12-digit Aadhaar
            if n == 12:
                continue
            data["bankAccounts"].add(match)

    def _extract_upi_ids(self, text: str, data: Dict[str, Set[str]]):
        for match in re.findall(self.UPI_PATTERN, text, re.IGNORECASE):
            local, domain = match.rsplit('@', 1)
            domain_lower = domain.lower()
            # Accept known UPI providers, or short domain (no dot = UPI handle)
            if domain_lower in self._UPI_PROVIDERS or '.' not in domain_lower:
                if len(local) >= 2:
                    data["upiIds"].add(match.lower())

    def _extract_emails(self, text: str, data: Dict[str, Set[str]]):
        for match in re.findall(self.EMAIL_PATTERN, text):
            domain = match.split('@')[1].lower()
            # Skip if this domain is a known UPI handle (not a real email)
            if domain in self._UPI_PROVIDERS:
                continue
            if '.' in domain:
                data["emailAddresses"].add(match.lower())

    def _extract_urls(self, text: str, data: Dict[str, Set[str]]):
        for pattern in self.URL_PATTERNS:
            for match in re.findall(pattern, text, re.IGNORECASE):
                if len(match) > 5:
                    data["phishingLinks"].add(match)

    def _extract_references(self, text: str, data: Dict[str, Set[str]]):
        """Extract generic reference / case IDs (stored in bankAccounts if numeric,
        otherwise noted – but per spec we only store in defined fields)."""
        for pattern in self.REFERENCE_PATTERNS:
            for match in re.findall(pattern, text, re.IGNORECASE):
                # Only store clearly numeric reference IDs in bankAccounts
                # if they look like account-length numbers
                if match.isdigit() and 9 <= len(match) <= 18:
                    self._extract_bank_accounts(match, self._init_session(""))

    # -----------------------------------------------------------------
    # Session helpers
    # -----------------------------------------------------------------

    def _init_session(self, session_id: str) -> Dict[str, Set[str]]:
        with self._lock:
            if session_id not in self._store:
                self._store[session_id] = {
                    "phoneNumbers":   set(),
                    "bankAccounts":   set(),
                    "upiIds":         set(),
                    "phishingLinks":  set(),
                    "emailAddresses": set(),
                }
            return self._store[session_id]


# Module-level singleton
intelligence_store = IntelligenceStore()
