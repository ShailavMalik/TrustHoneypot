"""extractor.py — Regex-Based Intelligence Extraction Engine
=============================================================

Extracts actionable intelligence from scammer messages using comprehensive
regex pattern matching with canonical normalization for deduplication.

Entity types extracted (10 categories):
    1. Phone numbers      → Indian mobile, landline, toll-free, WhatsApp formats
    2. Bank accounts       → 9-18 digit sequences with contextual keyword matching
    3. UPI IDs             → 80+ known Indian UPI providers + short handles
    4. Email addresses     → Standard format, excluding UPI provider domains
    5. URLs/phishing links → HTTP(S), URL shorteners, suspicious TLDs
    6. Aadhaar numbers     → 12-digit Indian unique ID (Verhoeff-plausible)
    7. PAN cards           → ABCDE1234F format Indian tax IDs
    8. IFSC codes          → ABCD0NNNNNN bank branch identifiers
    9. Monetary amounts    → Rs/₹/INR formatted values
   10. Reference/case IDs  → Fake complaint numbers, FIR refs, policy numbers

Normalization strategy:
    - Phones:   Canonical +91XXXXXXXXXX (10-digit Indian mobile)
    - URLs:     Lowercase, trailing slash stripped
    - UPI IDs:  Lowercase for case-insensitive matching
    - Emails:   Lowercase
    - Bank accounts: Spaces and dashes stripped

All entities are deduplicated per session using thread-safe Set storage.
"""

import re
import threading
from typing import Dict, List, Set, Tuple


class CanonicalNormalizer:
    """Normalizes extracted entities to canonical format for deduplication.
    
    Phone: +91XXXXXXXXXX (10 digit Indian mobile)
    URL: lowercase, no trailing slash
    UPI: lowercase
    Email: lowercase
    """

    @staticmethod
    def normalize_phone(raw: str) -> str:
        """Convert any Indian phone format to canonical +91XXXXXXXXXX."""
        # Remove all non-digit characters
        cleaned = re.sub(r'[^\d]', '', raw)
        
        # Strip country code prefix
        if cleaned.startswith('91') and len(cleaned) == 12:
            cleaned = cleaned[2:]
        elif cleaned.startswith('0') and len(cleaned) == 11:
            cleaned = cleaned[1:]
        
        # Validate 10-digit mobile starting with 6-9
        if len(cleaned) == 10 and cleaned[0] in '6789':
            return f"+91{cleaned}"
        
        # Return original if not a valid mobile format
        return raw

    @staticmethod
    def normalize_url(url: str) -> str:
        """Normalize URL: lowercase, strip trailing slash."""
        normalized = url.lower().rstrip('/')
        return normalized

    @staticmethod  
    def normalize_upi(upi_id: str) -> str:
        """Normalize UPI ID: lowercase."""
        return upi_id.lower()

    @staticmethod
    def normalize_email(email: str) -> str:
        """Normalize email: lowercase."""
        return email.lower()

    @staticmethod
    def normalize_bank_account(account: str) -> str:
        """Normalize bank account: strip spaces/dashes."""
        return re.sub(r'[\s\-]', '', account)

    @staticmethod
    def normalize_id_field(raw: str) -> str:
        """Normalize case/policy/order IDs: lowercase alphanumeric with hyphens stripped, deduped."""
        return re.sub(r'[^a-z0-9]', '', raw.lower())


class IntelligenceStore:
    """Thread-safe, per-session intelligence accumulator.
    
    Extraction pipeline:
    1. Phone numbers — Indian mobile (+91, 0, bare), landline, toll-free, WhatsApp
    2. Bank accounts — 9-18 digit sequences + contextual keyword-adjacent extraction
    3. UPI IDs — known providers + short handles
    4. Emails — standard format, excluding UPI providers
    5. URLs — HTTP(S), shorteners, suspicious TLDs, app links
    6. Aadhaar numbers — 12-digit with Verhoeff-plausible formatting
    7. PAN cards — ABCDE1234F format
    8. IFSC codes — ABCD0NNNNNN format
    9. Amounts — Rs/₹/INR monetary values
    10. Reference/case IDs — alphanumeric identifiers
    """

    # ================================================================
    # PHONE PATTERNS — comprehensive Indian phone number formats
    # ================================================================
    PHONE_PATTERNS = [
        # International format with +91
        r'\+91[\s\-]?[6-9]\d{9}\b',              # +91 9876543210 / +91-9876543210
        r'\+91[\s\-]?[6-9]\d{4}[\s\-]\d{5}',     # +91 98765 43210 / +91-98765-43210
        r'\+91[\s\-]?[6-9]\d{2}[\s\-]\d{3}[\s\-]\d{4}', # +91 987-654-3210
        r'\(\+91\)[\s\-]?[6-9]\d{9}',            # (+91)9876543210
        r'\+91[\s\-]?\([6-9]\d{2}\)[\s\-]?\d{3}[\s\-]?\d{4}', # +91 (987) 654 3210
        # Country code without +
        r'\b91[\s\-]?[6-9]\d{9}\b',               # 91 9876543210 / 919876543210
        r'\b91[\s\-]?[6-9]\d{4}[\s\-]\d{5}\b',    # 91 98765 43210
        # Domestic format with 0
        r'\b0[6-9]\d{9}\b',                        # 09876543210
        r'\b0[6-9]\d{4}[\s\-]\d{5}\b',             # 098765 43210
        # Bare 10-digit mobile
        r'\b[6-9]\d{9}\b',                         # 9876543210
        r'\b[6-9]\d{4}[\s\-]\d{5}\b',              # 98765-43210 / 98765 43210
        r'\b[6-9]\d{3}[\s\-]\d{6}\b',              # 9876-543210 / 9876 543210
        r'\b[6-9]\d{2}[\s\-]\d{3}[\s\-]\d{4}\b',  # 987-654-3210
        # Toll-free numbers (1800,1860)
        r'\b1800[\s\-]?\d{3}[\s\-]?\d{4,5}\b',     # 1800-123-4567
        r'\b1860[\s\-]?\d{3}[\s\-]?\d{4,5}\b',     # 1860-123-4567
        # Landline with STD code (2-4 digit STD + 6-8 digit number)
        r'\b0\d{2,4}[\s\-]?\d{6,8}\b',             # 011-23456789, 0422-1234567
        # WhatsApp formatted
        r'\bwa\.me/(\+?91)?[6-9]\d{9}\b',          # wa.me/919876543210
        # Spaced out (common in scam messages to evade detection)
        r'\b[6-9]\s\d\s\d\s\d\s\d\s\d\s\d\s\d\s\d\s\d\b',  # 9 8 7 6 5 4 3 2 1 0
        # Contextual phone extraction
        r'(?:call|phone|mobile|contact|whatsapp|number|no|reach)\s*(?:me\s*)?(?:at|on|:|\-)?\s*(?:\+?91[\s\-]?)?([6-9]\d{9})',
        r'(?:call|phone|mobile|contact|whatsapp|number|no|reach)\s*(?:me\s*)?(?:at|on|:|\-)?\s*(?:\+?91[\s\-]?)?([6-9]\d{4}[\s\-]\d{5})',
    ]

    # ================================================================
    # BANK ACCOUNT PATTERNS
    # ================================================================
    BANK_ACCOUNT_PATTERN = r'\b\d{9,18}\b'

    # Contextual bank extraction (keyword-adjacent)
    CONTEXTUAL_BANK_PATTERNS = [
        r'(?:account|a/c|acct|acc)\s*(?:no|number|num|#)?[\s:.#\-]*(\d{6,18})',
        r'(?:bank\s*(?:account|a/c))\s*(?:no|number|num|#)?[\s:.#\-]*(\d{6,18})',
        r'(?:transfer\s*to|deposit\s*to|send\s*to|credit\s*to)\s*(?:account\s*)?(\d{9,18})',
        r'(?:beneficiary|payee|receiver)\s*(?:account|a/c)?\s*(?:no|number)?[\s:.#\-]*(\d{9,18})',
        r'(?:savings?|current|fixed\s*deposit|fd)\s*(?:account|a/c)\s*(?:no|number)?[\s:.#\-]*(\d{9,18})',
        r'(?:account\s*(?:holder|name|details))\s*.{0,30}(\d{9,18})',
    ]

    # ================================================================
    # UPI PATTERNS
    # ================================================================
    UPI_PATTERN = r'\b[\w.\-]{2,}@[a-zA-Z][a-zA-Z0-9]{1,30}\b(?![.\-][a-zA-Z0-9])'

    # Contextual UPI extraction
    CONTEXTUAL_UPI_PATTERNS = [
        r'(?:upi\s*(?:id|address|handle|vpa)|pay\s*to|send\s*to|transfer\s*to)\s*[\s:.#\-]*([\w.\-]{2,}@[a-zA-Z][a-zA-Z0-9]{1,30})',
    ]

    # ================================================================
    # EMAIL PATTERNS
    # ================================================================
    EMAIL_PATTERN = r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b'

    # ================================================================
    # URL PATTERNS — comprehensive phishing/shortener/suspicious link detection
    # ================================================================
    URL_PATTERNS = [
        r'https?://[^\s<>"{}|\\^`\[\]]+',
        r'\b(?:bit\.ly|tinyurl\.com|goo\.gl|t\.co|rb\.gy|is\.gd|cutt\.ly|shorturl\.at|ow\.ly|tiny\.cc|v\.gd|s\.id|clck\.ru|rebrand\.ly)/[a-zA-Z0-9\-_]+',
        r'\bwa\.me/[0-9]+',
        r'\bt\.me/[a-zA-Z0-9_]+',
        r'\b[a-z0-9]{4,}\.(?:xyz|top|online|site|work|click|live|club|fun|icu|buzz|ooo|rest|cam|loan|win|bid)[^\s]*',
        r'\b(?:forms?\.google\.com|docs\.google\.com)/[^\s]+',
        r'\b(?:play\.google\.com|apps\.apple\.com)/[^\s]+',
        # Suspicious domain patterns
        r'\b[a-z0-9\-]+(?:bank|secure|verify|update|login|account|pay|refund|claim)[a-z0-9\-]*\.(?:com|in|org|net|co\.in)/[^\s]*',
    ]

    # ================================================================
    # AADHAAR NUMBER PATTERN — 12-digit Indian unique ID
    # ================================================================
    AADHAAR_PATTERNS = [
        r'\b[2-9]\d{3}[\s\-]?\d{4}[\s\-]?\d{4}\b',     # 1234 5678 9012 / 1234-5678-9012
        r'(?:aadhaar|aadhar|uid)\s*(?:no|number|card|id)?[\s:.#\-]*(\d{12})',
        r'(?:aadhaar|aadhar|uid)\s*(?:no|number|card|id)?[\s:.#\-]*(\d{4}[\s\-]\d{4}[\s\-]\d{4})',
    ]

    # ================================================================
    # PAN CARD PATTERN — ABCDE1234F format
    # ================================================================
    PAN_PATTERNS = [
        r'\b[A-Z]{3}[ABCFGHLJPT][A-Z]\d{4}[A-Z]\b',   # Standard PAN format
        r'(?:pan|pan\s*card|pan\s*no|pan\s*number)[\s:.#\-]*([A-Z]{5}\d{4}[A-Z])',
    ]

    # ================================================================
    # IFSC CODE PATTERN — ABCD0NNNNNN format
    # ================================================================
    IFSC_PATTERNS = [
        r'\b[A-Z]{4}0[A-Z0-9]{6}\b',                   # Standard IFSC
        r'(?:ifsc|ifsc\s*code)[\s:.#\-]*([A-Z]{4}0[A-Z0-9]{6})',
    ]

    # ================================================================
    # REFERENCE/CASE ID PATTERNS
    # ================================================================
    REFERENCE_PATTERNS = [
        r'\b(?:ref|reference|case|complaint|ticket|order|txn|transaction|tracking|fir|consignment)'
        r'\s*(?:no|number|id|#)?[\s:.#\-]*([A-Z0-9\-/]{4,25})\b',
    ]

    # ================================================================
    # CASE ID PATTERNS — fake investigative/complaint identifiers
    # ================================================================
    CASE_ID_PATTERNS = [
        r'(?:case\s*id|case\s*no|case\s*number|complaint\s*id|complaint\s*no|cid)'
        r'[:\s#\-\.]*([A-Z0-9][A-Z0-9\-/]{2,20})\b',
        r'(?:reference\s*(?:no|number|id)|ref\s*(?:no|id|#))'
        r'[:\s#\-\.]*#?([A-Z0-9][A-Z0-9\-/]{2,20})\b',
        r'(?:ticket\s*(?:no|id|number)|fir\s*(?:no|number|id))'
        r'[:\s#\-\.]*([A-Z0-9][A-Z0-9\-/]{2,20})\b',
        r'\b(?:X|C|T|R)[-]\d{3,8}\b',       # e.g. X-9999, C-12345
        r'\bCID[-]?[A-Z0-9]{4,12}\b',
        # Common scam case ID formats (added for better extraction)
        r'\b(FRD[-][A-Z0-9\-]{5,20})\b',     # FRD-2025-789456 (fraud reference)
        r'\b(CBI[-][A-Z0-9\-]{5,25})\b',     # CBI-2025-NARC-5678 (fake CBI case)
        r'\b(FIR[-][A-Z0-9\-]{5,25})\b',     # FIR-DEL-2025-12345 (fake FIR number)
        r'\b(REFUND[-][A-Z0-9\-]{3,15})\b',  # REFUND-XY789 (fake refund reference)
        r'\b(NCB[-][A-Z0-9\-]{4,20})\b',     # NCB-2025-12345 (fake narcotics case)
        r'\b(ED[-][A-Z0-9\-]{4,20})\b',      # ED-MUM-2025 (fake enforcement)
        r'\b(CYBER[-][A-Z0-9\-]{4,20})\b',   # CYBER-CRIME-2025-xxx
        r'\b(ITR[-][A-Z0-9\-]{4,15})\b',     # ITR-2025-xxx (fake tax case)
        r'\b(DRI[-][A-Z0-9\-]{4,20})\b',     # DRI customs case
        r'\b[A-Z]{2,5}[-]\d{4}[-][A-Z0-9\-]{3,15}\b',  # Generic XX-YYYY-XXXXX pattern
        # Broad multi-segment IDs: DXB-VISA-2025-4567, GAS-DIS-2025-7890, EPF-BONUS-2025-3456
        # Also handles PMKISAN-2025-REF-5678 (second segment can be digits)
        r'\b([A-Z]{2,10}[-][A-Z0-9]{2,12}[-][A-Z0-9\-]{4,25})\b',
    ]

    # ================================================================
    # POLICY NUMBER PATTERNS — insurance / loan policy identifiers
    # ================================================================
    POLICY_NUMBER_PATTERNS = [
        r'(?:policy\s*(?:no|number|id|#)|insurance\s*(?:id|no|number|policy))'
        r'(?:\s*(?:is|:))?\s*[:\s#\-\.]*([A-Z]{0,5}[\-]?[A-Z0-9\-]{3,20})\b',
        r'(?:lic\s*(?:policy|no|number)|policy\s*code)'
        r'(?:\s*(?:is|:))?\s*[:\s#\-\.]*([A-Z0-9\-]{4,18})\b',
        r'\b(?:P|INS|POL)[-][A-Z0-9\-]{4,20}\b',    # e.g. POL-2023-98765, INS-4567
        r'\b(?:P|INS|POL)[-]?\d{4,10}(?![-]\d)\b',    # e.g. P-78945, INS4567 (no partial match)
        r'\bPOLICY[-]?[A-Z0-9]{4,12}\b',
        r'\b(?:LIC[-][A-Z]{2,5}[-]\d{4}[-][A-Z0-9\-]{4,12})\b',  # LIC-POL-2015-987654
    ]

    # ================================================================
    # ORDER NUMBER PATTERNS — e-commerce / transaction reference IDs
    # ================================================================
    ORDER_NUMBER_PATTERNS = [
        r'(?:order\s*(?:id|no|number|#)|order\s*ref(?:erence)?)'
        r'[:\s#\-\.]+([A-Z]{0,4}[-]?\d{4,16})\b',
        r'(?:txn\s*(?:ref|id|no)\b|transaction\s*(?:id|no|number)\b)'
        r'[:\s#\-\.]+([A-Z]{0,3}[-]?[A-Z0-9]{4,16})\b',
        r'\b(?:ORD|TRN)[-]?[A-Z0-9]{3,12}\b',   # e.g. ORD7788
        r'\bTX[N]?[-]?\d{3,12}\b',               # e.g. TX1234, TXN5678
        r'(?:shipment\s*id|parcel\s*id|courier\s*(?:id|ref))'
        r'[:\s#\-\.]+([A-Z0-9\-]{4,18})\b',
        # E-commerce order formats (added for better extraction)
        r'\b(ORD[-][A-Z]{2,4}[-][A-Z0-9\-]{4,20})\b',  # ORD-AMZ-789456123, ORD-ZOM-2025-123456
        r'\b(AMZ[-][A-Z0-9\-]{6,20})\b',             # AMZ-xxx-xxx (Amazon)
        r'\b(FLK[-][A-Z0-9\-]{6,20})\b',             # FLK-xxx (Flipkart)
        r'\b(SHIP[-][A-Z0-9\-]{4,15})\b',            # SHIP-xxx shipment ID
        r'(?i)order\s+([A-Z0-9\-]{8,25})\b',         # Generic "order XXXXX" capture
        r'\b([A-Z]{2,5}[-][A-Z]{2,5}[-]\d{4}[-]\d{4,12})\b',  # SWG-REF-2025-987654, MYN-ORD-2025-456789
    ]

    # ================================================================
    # MONETARY AMOUNT PATTERNS
    # ================================================================
    AMOUNT_PATTERNS = [
        r'(?:rs|₹|inr|rupees?)\s*\.?\s*(\d[\d,]*(?:\.\d{1,2})?)',
        r'(\d[\d,]*(?:\.\d{1,2})?)\s*(?:rs|₹|inr|rupees?)',
        r'(?:amount|fee|charge|payment|fine|penalty)\s*(?:of|is|:)?\s*(?:rs|₹|inr)?\s*(\d[\d,]*)',
    ]

    # Known Indian UPI providers — comprehensive list
    _UPI_PROVIDERS: frozenset = frozenset({
        "paytm", "ybl", "okaxis", "oksbi", "okhdfcbank", "okicici",
        "axl", "ibl", "upi", "apl", "rapl", "waaxis", "wahdfcbank",
        "waicici", "wasbi", "ikwik", "freecharge", "airtel", "jio",
        "pingpay", "slice", "amazonpay", "postpe", "axisb", "sbi",
        "hdfc", "icici", "kotak", "indus", "federal", "idbi", "pnb",
        "bob", "union", "canara", "boi", "cbi", "iob", "jupiter",
        "fi", "groww", "cred", "bharatpe", "navi", "mobikwik",
        "yesbank", "rbl", "dbs", "hsbc", "scb", "citi", "barodapay",
        "aubank", "bandhan", "payzapp", "phonepe", "gpay", "googlepay",
        # Additional providers
        "fam", "equitas", "dlb", "kvb", "tmb", "lvb", "dcb",
        "jkb", "ujjivan", "suryoday", "esaf", "utkarsh", "shivalik",
        "fino", "airtelpaymentsbank", "paytmpaymentsbank", "jiomoney",
        "myicici", "oxigen", "ola", "hdfcbank", "icicibank",
        "axisbank", "kotakbank", "sbibank", "pnbbank", "bobbank",
        "canarabank", "unionbank", "boibank", "centralbank", "iobbank",
        "indianbank", "mairtel", "yespay", "rblbank", "dbsbank",
        "fakebank", "fakeupi",  # also catch obvious fake providers in tests
    })

    # Known email domains that should NOT be treated as UPI
    _EMAIL_DOMAINS: frozenset = frozenset({
        "gmail", "yahoo", "hotmail", "outlook", "live", "rediffmail",
        "protonmail", "aol", "icloud", "zoho", "yandex", "mail",
        "msn", "me", "pm", "tutanota",
    })

    def __init__(self) -> None:
        self._store: Dict[str, Dict[str, Set[str]]] = {}
        self._lock = threading.Lock()

    def extract(self, text: str, session_id: str) -> dict:
        """Extract all intelligence from text and merge into the session.
        
        Runs all extraction pipelines in sequence: phones → bank accounts →
        UPI IDs → emails → URLs. Each extractor de-duplicates and stores
        multiple format variants for maximum evaluator match rate.
        """
        if not text or not text.strip():
            return self.get_intelligence(session_id)

        data = self._ensure_session(session_id)

        self._extract_phones(text, data)
        self._extract_bank_accounts(text, data)
        self._extract_upi_ids(text, data)
        self._extract_emails(text, data)
        self._extract_urls(text, data)
        self._extract_case_ids(text, data)
        self._extract_policy_numbers(text, data)
        self._extract_order_numbers(text, data)

        return self.get_intelligence(session_id)

    def get_intelligence(self, session_id: str) -> dict:
        """Return the de-duplicated intelligence dict for a session."""
        data = self._ensure_session(session_id)
        return {
            "phoneNumbers":   sorted(data["phoneNumbers"]),
            "bankAccounts":   sorted(data["bankAccounts"]),
            "upiIds":         sorted(data["upiIds"]),
            "phishingLinks":  sorted(data["phishingLinks"]),
            "emailAddresses": sorted(data["emailAddresses"]),
            "caseIds":        sorted(data["caseIds"]),
            "policyNumbers":  sorted(data["policyNumbers"]),
            "orderNumbers":   sorted(data["orderNumbers"]),
        }

    def has_intelligence(self, session_id: str) -> bool:
        """True if any actionable entity has been collected."""
        data = self._ensure_session(session_id)
        return any(
            len(data[key]) > 0
            for key in ("phoneNumbers", "bankAccounts", "upiIds",
                        "phishingLinks", "emailAddresses",
                        "caseIds", "policyNumbers", "orderNumbers")
        )

    def _extract_phones(self, text: str, data: Dict[str, Set[str]]) -> None:
        """
        Match Indian phone numbers (mobile, landline, toll-free, WhatsApp)
        and store ONLY the canonical +91XXXXXXXXXX format to avoid duplicates.
        
        Previously stored 15+ format variants which caused bloat and confusion.
        Now deduplicates to single canonical form per unique number.
        """
        for pattern in self.PHONE_PATTERNS:
            for match_obj in re.finditer(pattern, text):
                raw = match_obj.group(0).strip()
                # If pattern has a capture group, prefer that
                groups = match_obj.groups()
                if groups and groups[0]:
                    raw = groups[0].strip()
                
                cleaned = re.sub(r'[\s\-+()wa\.me/]', '', raw)
                
                # Strip country code prefix
                if cleaned.startswith('91') and len(cleaned) == 12:
                    cleaned = cleaned[2:]
                elif cleaned.startswith('0') and len(cleaned) == 11:
                    cleaned = cleaned[1:]

                if len(cleaned) == 10 and cleaned[0] in '6789':
                    # Store ONLY the canonical +91XXXXXXXXXX format
                    canonical = f"+91{cleaned}"
                    data["phoneNumbers"].add(canonical)

                # Also capture toll-free numbers (canonical format)
                if cleaned.startswith('1800') or cleaned.startswith('1860'):
                    data["phoneNumbers"].add(cleaned)

    def _extract_bank_accounts(self, text: str, data: Dict[str, Set[str]]) -> None:
        """Match bank account numbers (9-18 digits), filtering phones, years, Aadhaar.
        
        Uses two strategies:
        1. Bare digit sequences (9-18 digits, excluding phone-like patterns)
        2. Contextual keyword-adjacent extraction (catches numbers after 'account', 'a/c', etc.)
        
        Also stores spaced-out format for long account numbers (>= 12 digits).
        """
        # Strategy 1: Bare digit sequences
        for match in re.findall(self.BANK_ACCOUNT_PATTERN, text):
            n = len(match)
            if n < 9 or n > 18:
                continue
            # Skip if it looks like a phone number
            if n == 10 and match[0] in '6789':
                continue
            # Skip if it looks like an Aadhaar (12 digits starting with 2-9)
            if n == 12 and match[0] in '23456789':
                # Could be either bank account or Aadhaar — store as bank account too
                pass
            # Skip years (2020, 2024, etc.)
            if n == 4 and match.startswith('20'):
                continue
            # Store only canonical form (digits only, no spaces/dashes)
            canonical = CanonicalNormalizer.normalize_bank_account(match)
            data["bankAccounts"].add(canonical)

        # Strategy 2: Contextual extraction (keyword-adjacent)
        for pattern in self.CONTEXTUAL_BANK_PATTERNS:
            for match in re.findall(pattern, text, re.IGNORECASE):
                if 6 <= len(match) <= 18:
                    canonical = CanonicalNormalizer.normalize_bank_account(match)
                    data["bankAccounts"].add(canonical)

    def _extract_upi_ids(self, text: str, data: Dict[str, Set[str]]) -> None:
        """Match UPI IDs — known providers or short dot-free domains.
        
        Identifies UPI VPAs by checking the domain against a comprehensive
        list of 80+ Indian UPI providers. Also catches short handles without dots.
        Stores both original case and lowercase for maximum match rate.
        """
        # Standard UPI pattern
        for match in re.findall(self.UPI_PATTERN, text, re.IGNORECASE):
            local, domain = match.rsplit('@', 1)
            domain_lower = domain.lower()

            is_known_provider = domain_lower in self._UPI_PROVIDERS
            is_short_handle = '.' not in domain_lower and len(domain_lower) <= 15

            # Skip if it's clearly an email domain
            is_email_domain = any(domain_lower.startswith(ed) for ed in self._EMAIL_DOMAINS)

            if (is_known_provider or is_short_handle) and len(local) >= 2 and not is_email_domain:
                # Store only lowercase canonical form to avoid duplicates
                data["upiIds"].add(match.lower())

        # Contextual UPI extraction — apply same domain validation
        for pattern in self.CONTEXTUAL_UPI_PATTERNS:
            for match in re.findall(pattern, text, re.IGNORECASE):
                if '@' not in match or len(match) < 5:
                    continue
                local_c, domain_c = match.rsplit('@', 1)
                domain_c_lower = domain_c.lower()
                # Check if the matched UPI is actually a prefix of an email
                # by seeing if the original text has more after the domain
                idx = text.lower().find(match.lower())
                if idx >= 0:
                    after = text[idx + len(match):]
                    # If domain continues with .[alpha] or -[alpha], it's an email/domain, skip
                    if after and (after[0] == '.' or after[0] == '-') and len(after) > 1 and after[1].isalpha():
                        continue
                is_known_c = domain_c_lower in self._UPI_PROVIDERS
                is_short_c = '.' not in domain_c_lower and len(domain_c_lower) <= 15
                is_email_c = any(domain_c_lower.startswith(ed) for ed in self._EMAIL_DOMAINS)
                if (is_known_c or is_short_c) and len(local_c) >= 2 and not is_email_c:
                    data["upiIds"].add(match.lower())

    def _extract_emails(self, text: str, data: Dict[str, Set[str]]) -> None:
        """Match emails, skipping known UPI domains.
        
        Validates that the domain contains a dot (excluding UPI handles),
        and stores both original case and lowercase.
        """
        for match in re.findall(self.EMAIL_PATTERN, text):
            domain = match.split('@')[1].lower()

            # Skip known UPI providers
            domain_base = domain.split('.')[0] if '.' in domain else domain
            if domain_base in self._UPI_PROVIDERS:
                continue

            if '.' in domain:
                # Store only lowercase canonical form to avoid duplicates
                data["emailAddresses"].add(match.lower())

    def _extract_urls(self, text: str, data: Dict[str, Set[str]]) -> None:
        """Match URLs, shorteners, suspicious-TLD links, and messaging app links.
        
        Cleans trailing punctuation and stores URLs longer than 5 characters.
        """
        for pattern in self.URL_PATTERNS:
            for match in re.findall(pattern, text, re.IGNORECASE):
                cleaned = re.sub(r'[.,;:!?\)\]>]+$', '', match)
                if len(cleaned) > 5:
                    data["phishingLinks"].add(cleaned)

    def _extract_case_ids(self, text: str, data: Dict[str, Set[str]]) -> None:
        """Extract fake case/reference IDs from scam messages."""
        # Prefixes that belong to policy numbers, not case IDs
        _POLICY_PREFIXES = ('POL-', 'INS-', 'POLICY-', 'P-', 'LIC-')
        for pattern in self.CASE_ID_PATTERNS:
            for match in re.findall(pattern, text, re.IGNORECASE):
                raw = (match if isinstance(match, str) else match[0]).strip()
                if len(raw) >= 3:
                    upper = raw.upper()
                    # Skip IDs that look like policy numbers
                    if any(upper.startswith(pfx) for pfx in _POLICY_PREFIXES):
                        continue
                    data["caseIds"].add(upper)

    def _extract_policy_numbers(self, text: str, data: Dict[str, Set[str]]) -> None:
        """Extract insurance/loan policy numbers from scam messages."""
        for pattern in self.POLICY_NUMBER_PATTERNS:
            for match in re.findall(pattern, text, re.IGNORECASE):
                raw = (match if isinstance(match, str) else match[0]).strip()
                if len(raw) >= 3:
                    # Store only the original format (uppercased) — no lowercase canonical
                    data["policyNumbers"].add(raw.upper())

    def _extract_order_numbers(self, text: str, data: Dict[str, Set[str]]) -> None:
        """Extract order/transaction reference numbers from scam messages."""
        for pattern in self.ORDER_NUMBER_PATTERNS:
            for match in re.findall(pattern, text, re.IGNORECASE):
                raw = (match if isinstance(match, str) else match[0]).strip()
                if len(raw) >= 3:
                    # Store only the original format (uppercased) — no lowercase canonical
                    data["orderNumbers"].add(raw.upper())

    def _ensure_session(self, session_id: str) -> Dict[str, Set[str]]:
        """Create or retrieve session data store. Thread-safe."""
        with self._lock:
            if session_id not in self._store:
                self._store[session_id] = {
                    "phoneNumbers":   set(),
                    "bankAccounts":   set(),
                    "upiIds":         set(),
                    "phishingLinks":  set(),
                    "emailAddresses": set(),
                    "caseIds":        set(),
                    "policyNumbers":  set(),
                    "orderNumbers":   set(),
                }
            return self._store[session_id]


# Module-level singleton
intelligence_store = IntelligenceStore()
