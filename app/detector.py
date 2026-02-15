"""
Advanced Scam Detection Engine with Multi-Signal Analysis.

This is a sophisticated detection system that goes beyond simple keyword matching.
It uses multiple detection strategies working together:

1. Lightweight intent classification (regex + keyword clusters)
2. Weighted keyword scoring with cumulative risk
3. Pattern combination analysis (multiple signals = exponential risk)
4. India-specific scam templates (RBI, Aadhaar, PAN, govt impersonation)
5. Stage-aware detection (GREETING -> RAPPORT -> SUSPICION -> EXTRACTION)
6. Confidence scoring (not just yes/no, but how confident we are)
7. Scam type classification (identifies the specific scam variant)

This multi-layered approach catches sophisticated scammers who try to
avoid obvious keywords while still exhibiting scam behavior patterns.
"""
import re
from typing import Tuple, Dict, List, Set, Optional
from dataclasses import dataclass, field
from enum import Enum


class Intent(Enum):
    """Detected intent types with weighted risk scores."""
    GREETING = "GREETING"
    SELF_INTRO = "SELF_INTRO"
    IDENTITY_PROBE = "IDENTITY_PROBE"
    SMALL_TALK = "SMALL_TALK"
    PAYMENT_REQUEST = "PAYMENT_REQUEST"
    BANK_DETAILS_REQUEST = "BANK_DETAILS_REQUEST"
    OTP_REQUEST = "OTP_REQUEST"
    UPI_REQUEST = "UPI_REQUEST"
    URGENCY = "URGENCY"
    LEGAL_THREAT = "LEGAL_THREAT"
    ACCOUNT_SUSPENSION = "ACCOUNT_SUSPENSION"
    UNKNOWN = "UNKNOWN"


class ConversationStage(Enum):
    """Conversation stages for stage-aware responses."""
    GREETING_STAGE = "GREETING_STAGE"
    RAPPORT_STAGE = "RAPPORT_STAGE"
    SUSPICION_STAGE = "SUSPICION_STAGE"
    EXTRACTION_STAGE = "EXTRACTION_STAGE"


# Intent weight scores per requirement
INTENT_WEIGHTS = {
    Intent.GREETING: 0,
    Intent.SELF_INTRO: 0,
    Intent.SMALL_TALK: 0,
    Intent.URGENCY: 25,
    Intent.PAYMENT_REQUEST: 40,
    Intent.UPI_REQUEST: 45,
    Intent.OTP_REQUEST: 50,
    Intent.BANK_DETAILS_REQUEST: 45,
    Intent.LEGAL_THREAT: 30,
    Intent.ACCOUNT_SUSPENSION: 35,
    Intent.IDENTITY_PROBE: 5,
    Intent.UNKNOWN: 0,
}


@dataclass
class DetectionResult:
    """Detailed result of scam analysis."""
    total_score: int = 0
    is_scam: bool = False
    confidence: float = 0.0  # 0.0 to 1.0
    risk_level: str = "low"  # low, medium, high, critical
    scam_type: str = "unknown"
    detected_patterns: List[str] = field(default_factory=list)
    triggered_categories: Set[str] = field(default_factory=set)
    detected_intents: List[Intent] = field(default_factory=list)
    conversation_stage: ConversationStage = ConversationStage.GREETING_STAGE


class ScamDetector:
    """
    Advanced multi-signal scam detection engine.
    
    Uses a layered approach:
    - Layer 1: Intent classification (regex + keywords)
    - Layer 2: Keyword scoring (base signals)
    - Layer 3: Pattern combinations (compound signals)
    - Layer 4: India-specific patterns (regional context)
    - Layer 5: Stage-aware detection
    - Layer 6: Confidence calibration (certainty scoring)
    """
    
    # =========================================================================
    # LAYER 0: INTENT CLASSIFICATION PATTERNS
    # =========================================================================
    
    # Greeting patterns (score: 0)
    GREETING_PATTERNS = [
        r'\b(hello|hi|hey|namaste|namaskar|good\s*(morning|afternoon|evening|day))\b',
        r'\b(greetings|howdy|hola|salaam|jai\s*hind)\b',
        r'^(hi|hello|hey|ji)\s*[,!.]?\s*$',
    ]
    
    # Self introduction patterns (score: 0)
    SELF_INTRO_PATTERNS = [
        r'\b(i\s*am|my\s*name\s*is|this\s*is|speaking|calling\s*from)\b',
        r'\b(mera\s*naam|main\s*bol\s*raha)\b',
        r'\b(officer|inspector|manager|executive|agent)\s+(speaking|here)\b',
    ]
    
    # Identity probe patterns (score: 5)
    IDENTITY_PROBE_PATTERNS = [
        r'\b(who\s*(is\s*this|are\s*you)|your\s*name|aap\s*kaun)\b',
        r'\b(confirm\s*your\s*(identity|name)|verify\s*yourself)\b',
        r'\b(is\s*this\s*mr|is\s*this\s*mrs|am\s*i\s*speaking\s*to)\b',
    ]
    
    # Small talk patterns (score: 0)
    SMALL_TALK_PATTERNS = [
        r'\b(how\s*are\s*you|kaise\s*ho|what\'?s\s*up|hope\s*you\'?re\s*well)\b',
        r'\b(nice\s*to\s*(meet|talk)|good\s*to\s*hear|hope\s*you\'?re\s*fine)\b',
        r'\b(weather|family\s*is\s*fine|doing\s*well)\b',
    ]
    
    # Payment request patterns (score: 40)
    PAYMENT_REQUEST_PATTERNS = [
        r'\b(send|transfer|pay)\s*(me|us|the|now|₹|\d+)\b',
        r'\b(payment|amount|money)\s*(of|is|due|required)\b',
        r'\b(processing\s*fee|registration\s*fee|advance\s*payment)\b',
        r'\b(pay\s*now|transfer\s*now|send\s*money)\b',
        r'\b(paisa\s*(bhejo|do)|paise\s*(transfer|send))\b',
    ]
    
    # Bank details request patterns (score: 45)
    BANK_DETAILS_PATTERNS = [
        r'\b(bank\s*account|account\s*number|a/c\s*(no|number))\b',
        r'\b(ifsc|cvv|card\s*number|debit\s*card|credit\s*card)\b',
        r'\b(share\s*(your\s*)?(bank|account|card))\b',
        r'\b(account\s*details|banking\s*details|passbook)\b',
    ]
    
    # OTP request patterns (score: 50)
    OTP_REQUEST_PATTERNS = [
        r'\b(otp|one\s*time\s*password|verification\s*code)\b',
        r'\b(share\s*(the\s*)?otp|send\s*(me\s*)?otp|tell\s*(me\s*)?otp)\b',
        r'\b(\d\s*digit\s*(code|otp|password))\b',
        r'\b(enter\s*(the\s*)?otp|otp\s*(bhejo|do|batao))\b',
    ]
    
    # UPI request patterns (score: 45)
    UPI_REQUEST_PATTERNS = [
        r'\b(upi\s*id|upi\s*address|bhim|phonepe|paytm|gpay|googlepay)\b',
        r'\b(send\s*(via|through|to)\s*upi)\b',
        r'\b(@paytm|@ybl|@oksbi|@okaxis|@okicici|@upi)\b',
        r'\b(scan\s*(the\s*)?(qr|code)|upi\s*transfer)\b',
    ]
    
    # Urgency patterns (score: 25)
    URGENCY_PATTERNS = [
        r'\b(urgent|urgently|immediate|immediately|right\s*now|asap)\b',
        r'\b(hurry|quickly|fast|jaldi|turant|abhi)\b',
        r'\b(within\s*\d+\s*(hour|minute|min)|today\s*only)\b',
        r'\b(last\s*chance|final\s*(notice|warning)|expire)\b',
        r'\b(deadline|time\s*(running|left)|before\s*\d+)\b',
    ]
    
    # Legal threat patterns (score: 30)
    LEGAL_THREAT_PATTERNS = [
        r'\b(legal\s*action|police|arrest|jail|court|case)\b',
        r'\b(warrant|fir|complaint|cyber\s*crime|fraud\s*case)\b',
        r'\b(cbi|ed|enforcement|investigation)\b',
        r'\b(penalty|fine|prosecution|imprison)\b',
        r'\b(digital\s*arrest|video\s*call\s*arrest)\b',
    ]
    
    # Account suspension patterns (score: 35)
    ACCOUNT_SUSPENSION_PATTERNS = [
        r'\b(account\s*(will\s*be\s*)?(suspend|block|deactivate|freeze))\b',
        r'\b((suspend|block|deactivat|terminat)(ed|ion|ing))\b',
        r'\b(kyc\s*(update|expire|fail)|re-?kyc|ekyc)\b',
        r'\b(sim\s*(block|deactivate)|number\s*(block|suspend))\b',
        r'\b(aadhaar\s*(block|suspend)|pan\s*(block|suspend))\b',
    ]
    
    # =========================================================================
    # LAYER 1: WEIGHTED KEYWORD SCORING
    # =========================================================================
    
    # Urgency tactics - scammers want you to act before you think
    URGENCY_KEYWORDS = {
        "urgent": 15, "immediately": 15, "right now": 12, "hurry": 12,
        "asap": 12, "quickly": 8, "fast action": 8,
        "expire": 15, "limited time": 15, "last chance": 18,
        "act now": 18, "don't wait": 12, "today only": 15,
        "within 24 hours": 18, "deadline": 12, "final notice": 20,
        "time sensitive": 15, "running out": 12, "expires today": 20,
        "hours left": 15, "minutes left": 18, "closing soon": 15,
        "jaldi karo": 12, "abhi karo": 10, "turant": 15  # Hindi urgency words
    }
    
    # Account/verification scams - pretending to be your bank
    VERIFICATION_KEYWORDS = {
        "verify": 12, "confirm": 10, "update": 8,
        "account suspended": 22, "account blocked": 22, "blocked": 15,
        "deactivated": 18, "suspended": 18, "secure your": 12,
        "validate": 12, "authentication": 10, "kyc": 18,
        "reactivate": 15, "unlock": 12, "restore": 10,
        "verification required": 20, "verify immediately": 25,
        "re-kyc": 20, "kyc update": 18, "kyc expired": 22,
        "ekyc": 15, "video kyc": 18, "complete kyc": 18,
        "link aadhaar": 20, "link pan": 18, "update aadhaar": 18
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
        "claim your": 18, "collect your": 15, "tax refund": 22,
        "income tax refund": 25, "gst refund": 22, "excess payment": 18,
        "double your money": 30, "guaranteed returns": 28, "investment scheme": 20,
        "crypto": 15, "bitcoin": 15, "trading profit": 22
    }
    
    # Threats and intimidation - creating fear
    THREAT_KEYWORDS = {
        "legal action": 25, "police complaint": 20, "arrest warrant": 25,
        "penalty": 18, "heavy fine": 15, "court case": 20,
        "jail time": 25, "under investigation": 18, "case filed": 22,
        "arrest you": 25, "fraud case": 22, "cyber crime": 20,
        "legal notice": 22, "fir registered": 20, "fir filed": 20,
        "cbi case": 25, "enforcement directorate": 25, "e.d. case": 22,
        "money laundering case": 28, "hawala": 25, "terror funding": 30,
        "your name is involved": 22, "case registered against": 22,
        "digital arrest": 28, "video call arrest": 30
    }
    
    # =========================================================================
    # LAYER 2: INDIA-SPECIFIC SCAM PATTERNS (NEW!)
    # =========================================================================
    
    # Government impersonation - extremely common in India
    GOVT_IMPERSONATION = {
        "rbi": 25, "reserve bank": 25, "income tax": 20,
        "it department": 22, "customs": 20, "telecom department": 22,
        "trai": 22, "dot": 18, "department of telecom": 22,
        "ministry": 18, "government of india": 20, "goi": 15,
        "uidai": 22, "npci": 20, "sebi": 20, "irda": 18,
        "passport office": 18, "embassy": 18, "consulate": 18,
        "pmo": 25, "prime minister office": 25, "cm office": 22,
        "police commissioner": 22, "dgp": 22, "ips officer": 22,
        "central government": 20, "state government": 18,
        "pradhan mantri": 20, "pm scheme": 18, "govt scheme": 18
    }
    
    # Aadhaar/PAN specific scams - huge in India
    IDENTITY_SCAM = {
        "aadhaar": 15, "aadhar": 15, "pan card": 15,
        "aadhaar linked": 20, "pan linked": 18,
        "aadhaar will be blocked": 28, "pan will be suspended": 25,
        "aadhaar deactivated": 25, "pan deactivated": 25,
        "update aadhaar": 18, "aadhaar otp": 22,
        "aadhaar number used": 22, "pan number misused": 22,
        "multiple pan": 22, "duplicate aadhaar": 22,
        "aadhaar verification": 20, "pan verification": 18,
        "12 digit": 12, "10 digit pan": 12
    }
    
    # Telecom/SIM scams - very prevalent
    TELECOM_SCAM = {
        "sim block": 22, "sim deactivate": 22, "number will be blocked": 22,
        "illegal activities from your number": 28,
        "your number used for fraud": 25, "trai notice": 22,
        "telecom violation": 22, "sim verification": 18,
        "port your number": 15, "airtel": 10, "jio": 10, "vi": 10,
        "bsnl": 10, "mobile number linked": 15
    }
    
    # Courier/delivery scams
    COURIER_SCAM = {
        "parcel": 15, "courier": 15, "package": 12,
        "parcel seized": 25, "drugs found": 30, "illegal items": 28,
        "customs duty": 22, "package held": 20, "delivery failed": 15,
        "address verification": 18, "fedex": 12, "dhl": 12,
        "bluedart": 12, "delhivery": 10, "delivery boy": 10
    }
    
    # Job/loan scams
    JOB_LOAN_SCAM = {
        "work from home": 18, "part time job": 18, "earn from home": 20,
        "typing job": 20, "data entry job": 18, "online job": 15,
        "instant loan": 22, "loan approved": 22, "pre-approved loan": 22,
        "processing charges": 20, "registration fee": 22,
        "advance payment": 22, "security deposit": 20,
        "earn daily": 20, "earn weekly": 18, "guaranteed income": 25,
        "no investment": 15, "investment required": 18
    }
    
    # =========================================================================
    # LAYER 3: PATTERN COMBINATIONS (COMPOUND SIGNALS)
    # =========================================================================
    
    # These patterns combine multiple signals - very high confidence when matched
    SCAM_TEMPLATES = [
        # RBI/Bank impersonation
        (r"(rbi|reserve bank|bank).{0,30}(kyc|verify|update|suspend|block)", 35, "bank_impersonation"),
        (r"(account|card).{0,20}(block|suspend|deactivat|terminat)", 30, "account_threat"),
        
        # Government impersonation + threat
        (r"(police|cbi|ed|cyber).{0,30}(case|arrest|warrant|investigation)", 40, "govt_threat"),
        (r"(aadhaar|aadhar|pan).{0,30}(block|suspend|deactivat|illegal|misuse)", 35, "identity_threat"),
        
        # Telecom scam pattern
        (r"(sim|number|mobile).{0,30}(block|deactivat|illegal|fraud)", 35, "telecom_scam"),
        (r"(trai|dot|telecom).{0,30}(notice|violation|complaint)", 32, "telecom_impersonation"),
        
        # Courier scam pattern
        (r"(parcel|courier|package).{0,30}(drugs|illegal|seiz|customs)", 40, "courier_scam"),
        
        # Money lure pattern
        (r"(won|winner|prize|lottery).{0,30}(claim|collect|receive|₹|\$)", 35, "lottery_scam"),
        (r"(refund|cashback).{0,30}(process|claim|receive|pending)", 30, "refund_scam"),
        
        # Job scam pattern
        (r"(job|work|earn).{0,30}(home|online|daily|weekly|guaranteed)", 28, "job_scam"),
        (r"(loan|credit).{0,30}(approved|sanction|instant|pre-approved)", 28, "loan_scam"),
        
        # OTP/credential fishing
        (r"(otp|password|pin|cvv).{0,20}(share|send|enter|provide)", 40, "credential_phishing"),
        (r"share.{0,20}(otp|password|pin|cvv)", 40, "credential_phishing"),
        
        # Urgency + action pattern
        (r"(urgent|immediate|asap).{0,30}(pay|transfer|send|click)", 32, "urgent_action"),
        
        # Digital arrest scam (trending in India)
        (r"(video|zoom|skype).{0,30}(arrest|custody|investigation)", 45, "digital_arrest"),
        (r"(digital|online).{0,20}arrest", 45, "digital_arrest"),
        
        # Investment scam
        (r"(invest|trading).{0,30}(guaranteed|double|triple|profit)", 35, "investment_scam"),
        (r"(crypto|bitcoin|forex).{0,30}(profit|return|guaranteed)", 35, "crypto_scam"),
    ]
    
    # =========================================================================
    # LAYER 4: BEHAVIORAL PATTERNS
    # =========================================================================
    
    # These detect escalation patterns across messages
    ESCALATION_SIGNALS = [
        "last warning", "final chance", "we tried to contact",
        "this is your last", "if you don't respond", "action will be taken",
        "we are forced to", "no other option", "compelled to proceed"
    ]
    
    # Pressure tactics in sequence
    PRESSURE_SEQUENCE = [
        ("request", "remind", "warn", "final"),
        ("inform", "alert", "urgent", "critical"),
        ("pending", "overdue", "final", "legal")
    ]
    
    # =========================================================================
    # LAYER 5: SUSPICIOUS LINK PATTERNS
    # =========================================================================
    
    LINK_PATTERNS = [
        r"https?://[^\s]+",  # Any URL
        r"bit\.ly", r"tinyurl", r"goo\.gl", r"t\.co",  # URL shorteners
        r"click here", r"click this", r"tap here", r"click below",
        r"link:", r"visit:", r"open this",
        r"wa\.me", r"whatsapp\.com",  # WhatsApp links
        r"t\.me", r"telegram",  # Telegram links
        r"[a-z0-9]{8,}\.xyz", r"[a-z0-9]{8,}\.top",  # Suspicious TLDs
        r"[a-z0-9]{8,}\.online", r"[a-z0-9]{8,}\.site",
    ]
    
    # =========================================================================
    # THRESHOLDS AND CONFIGURATION
    # =========================================================================
    
    SCAM_THRESHOLD = 60  # Updated: Only mark scam when risk_score >= 60
    HIGH_CONFIDENCE_THRESHOLD = 80  # Very confident it's a scam
    CRITICAL_THRESHOLD = 120  # Definitely a scam
    
    # Category bonuses (hitting multiple categories = higher confidence)
    MULTI_CATEGORY_BONUS = {
        2: 10,   # 2 categories hit = +10
        3: 25,   # 3 categories hit = +25
        4: 45,   # 4 categories hit = +45
        5: 70,   # 5+ categories hit = +70
    }
    
    def __init__(self):
        self.session_scores: Dict[str, int] = {}
        self.session_details: Dict[str, DetectionResult] = {}
        self.session_categories: Dict[str, Set[str]] = {}
        self.session_message_count: Dict[str, int] = {}
        # New: Track intents and stages per session
        self.session_intents: Dict[str, List[Intent]] = {}
        self.session_stages: Dict[str, ConversationStage] = {}
    
    def classify_intent(self, text: str) -> List[Intent]:
        """
        Classify message intent using regex patterns and keyword clusters.
        Returns list of detected intents (can have multiple).
        """
        intents = []
        text_lower = text.lower()
        
        # Check each intent pattern
        intent_patterns = [
            (Intent.GREETING, self.GREETING_PATTERNS),
            (Intent.SELF_INTRO, self.SELF_INTRO_PATTERNS),
            (Intent.IDENTITY_PROBE, self.IDENTITY_PROBE_PATTERNS),
            (Intent.SMALL_TALK, self.SMALL_TALK_PATTERNS),
            (Intent.PAYMENT_REQUEST, self.PAYMENT_REQUEST_PATTERNS),
            (Intent.BANK_DETAILS_REQUEST, self.BANK_DETAILS_PATTERNS),
            (Intent.OTP_REQUEST, self.OTP_REQUEST_PATTERNS),
            (Intent.UPI_REQUEST, self.UPI_REQUEST_PATTERNS),
            (Intent.URGENCY, self.URGENCY_PATTERNS),
            (Intent.LEGAL_THREAT, self.LEGAL_THREAT_PATTERNS),
            (Intent.ACCOUNT_SUSPENSION, self.ACCOUNT_SUSPENSION_PATTERNS),
        ]
        
        for intent, patterns in intent_patterns:
            for pattern in patterns:
                if re.search(pattern, text_lower, re.IGNORECASE):
                    if intent not in intents:
                        intents.append(intent)
                    break
        
        return intents if intents else [Intent.UNKNOWN]
    
    def get_intent_score(self, intents: List[Intent]) -> int:
        """Calculate weighted risk score from detected intents."""
        return sum(INTENT_WEIGHTS.get(intent, 0) for intent in intents)
    
    def determine_stage(self, session_id: str, risk_score: int, message_count: int) -> ConversationStage:
        """
        Determine conversation stage based on risk score and message count.
        
        Stage progression:
        - GREETING_STAGE: Initial contact (msg <= 2, score < 30)
        - RAPPORT_STAGE: Building rapport (msg <= 4 or score < 50)
        - SUSPICION_STAGE: Suspicious activity (score 50-80)
        - EXTRACTION_STAGE: High risk, extract intel (score >= 80)
        """
        if message_count <= 2 and risk_score < 30:
            return ConversationStage.GREETING_STAGE
        elif message_count <= 4 or risk_score < 50:
            return ConversationStage.RAPPORT_STAGE
        elif risk_score < 80:
            return ConversationStage.SUSPICION_STAGE
        else:
            return ConversationStage.EXTRACTION_STAGE
    
    def get_conversation_stage(self, session_id: str) -> ConversationStage:
        """Get current conversation stage for a session."""
        return self.session_stages.get(session_id, ConversationStage.GREETING_STAGE)
    
    def get_session_intents(self, session_id: str) -> List[Intent]:
        """Get all detected intents for a session."""
        return self.session_intents.get(session_id, [])
    
    def _check_keywords(self, text: str, keyword_dict: dict, category: str, 
                        categories: set) -> int:
        """Check keywords using word boundary matching to avoid false positives."""
        score = 0
        text_lower = text.lower()
        for keyword, weight in keyword_dict.items():
            # Use word boundary regex to match whole words only
            # This prevents "know" from matching "now", "need" from matching "ed"
            pattern = r'\b' + re.escape(keyword) + r'\b'
            if re.search(pattern, text_lower):
                score += weight
                categories.add(category)
        return score
    
    def _check_patterns(self, text: str) -> Tuple[int, List[str], str]:
        """Check compound patterns and return score, matches, and scam type."""
        score = 0
        matches = []
        scam_type = "unknown"
        text_lower = text.lower()
        
        for pattern, weight, ptype in self.SCAM_TEMPLATES:
            if re.search(pattern, text_lower, re.IGNORECASE):
                score += weight
                matches.append(pattern)
                if scam_type == "unknown":
                    scam_type = ptype
        
        return score, matches, scam_type
    
    def _check_links(self, text: str) -> int:
        """Check for suspicious links."""
        for pattern in self.LINK_PATTERNS:
            if re.search(pattern, text.lower()):
                return 15
        return 0
    
    def _check_escalation(self, text: str) -> int:
        """Check for escalation signals."""
        score = 0
        text_lower = text.lower()
        for signal in self.ESCALATION_SIGNALS:
            if signal in text_lower:
                score += 12
        return score
    
    def _calculate_confidence(self, score: int, categories_hit: int, 
                              pattern_matches: int) -> float:
        """Calculate confidence level (0.0 to 1.0)."""
        if score < self.SCAM_THRESHOLD:
            return min(score / self.SCAM_THRESHOLD * 0.5, 0.5)
        
        # Base confidence from score
        if score >= self.CRITICAL_THRESHOLD:
            base = 0.95
        elif score >= self.HIGH_CONFIDENCE_THRESHOLD:
            base = 0.85
        else:
            base = 0.7
        
        # Boost for multiple categories
        category_boost = min(categories_hit * 0.03, 0.15)
        
        # Boost for pattern matches
        pattern_boost = min(pattern_matches * 0.05, 0.1)
        
        return min(base + category_boost + pattern_boost, 0.99)
    
    def _get_risk_level(self, score: int, confidence: float) -> str:
        """Determine risk level based on score and confidence."""
        if score >= self.CRITICAL_THRESHOLD or confidence >= 0.9:
            return "critical"
        elif score >= self.HIGH_CONFIDENCE_THRESHOLD or confidence >= 0.75:
            return "high"
        elif score >= self.SCAM_THRESHOLD:
            return "medium"
        elif score >= 15:
            return "low"
        else:
            return "minimal"
    
    def calculate_risk_score(self, text: str, session_id: str) -> Tuple[int, bool]:
        """
        Analyze a message and return its risk score.
        
        This is the main entry point. It runs all detection layers
        and returns a comprehensive analysis.
        
        Args:
            text: The message content to analyze
            session_id: Unique ID for this conversation
            
        Returns:
            (cumulative_score, is_scam) - total score so far and whether it's a scam
        """
        # Initialize session tracking
        if session_id not in self.session_categories:
            self.session_categories[session_id] = set()
            self.session_message_count[session_id] = 0
            self.session_intents[session_id] = []
        
        self.session_message_count[session_id] += 1
        message_count = self.session_message_count[session_id]
        categories = self.session_categories[session_id]
        message_score = 0
        
        # LAYER 0: Intent classification (NEW - lightweight)
        detected_intents = self.classify_intent(text)
        self.session_intents[session_id].extend(detected_intents)
        intent_score = self.get_intent_score(detected_intents)
        message_score += intent_score
        
        # LAYER 1: Keyword scoring
        all_keyword_dicts = [
            (self.URGENCY_KEYWORDS, "urgency"),
            (self.VERIFICATION_KEYWORDS, "verification"),
            (self.PAYMENT_KEYWORDS, "payment"),
            (self.THREAT_KEYWORDS, "threat"),
            (self.GOVT_IMPERSONATION, "govt_impersonation"),
            (self.IDENTITY_SCAM, "identity_scam"),
            (self.TELECOM_SCAM, "telecom_scam"),
            (self.COURIER_SCAM, "courier_scam"),
            (self.JOB_LOAN_SCAM, "job_loan_scam"),
        ]
        
        for keyword_dict, category in all_keyword_dicts:
            message_score += self._check_keywords(text, keyword_dict, category, categories)
        
        # LAYER 2: Pattern combination analysis
        pattern_score, pattern_matches, scam_type = self._check_patterns(text)
        message_score += pattern_score
        
        # LAYER 3: Suspicious links
        message_score += self._check_links(text)
        
        # LAYER 4: Escalation detection
        message_score += self._check_escalation(text)
        
        # LAYER 5: Multi-category bonus
        num_categories = len(categories)
        if num_categories >= 5:
            message_score += self.MULTI_CATEGORY_BONUS[5]
        elif num_categories >= 2:
            message_score += self.MULTI_CATEGORY_BONUS.get(num_categories, 0)
        
        # Update session score
        if session_id not in self.session_scores:
            self.session_scores[session_id] = 0
        
        self.session_scores[session_id] += message_score
        total_score = self.session_scores[session_id]
        
        # LAYER 6: Stage-aware detection
        stage = self.determine_stage(session_id, total_score, message_count)
        self.session_stages[session_id] = stage
        
        # Calculate confidence and risk level
        confidence = self._calculate_confidence(
            total_score, num_categories, len(pattern_matches)
        )
        risk_level = self._get_risk_level(total_score, confidence)
        
        # IMPORTANT: Only mark as scam when risk_score >= 60 (SCAM_THRESHOLD)
        # This prevents false positives on greetings/small talk
        is_scam = total_score >= self.SCAM_THRESHOLD
        
        # Store detailed result with intents and stage
        self.session_details[session_id] = DetectionResult(
            total_score=total_score,
            is_scam=is_scam,
            confidence=confidence,
            risk_level=risk_level,
            scam_type=scam_type if scam_type != "unknown" else self._infer_scam_type(categories),
            detected_patterns=pattern_matches,
            triggered_categories=categories.copy(),
            detected_intents=list(set(self.session_intents[session_id])),
            conversation_stage=stage
        )
        
        return total_score, is_scam
    
    def _infer_scam_type(self, categories: Set[str]) -> str:
        """Infer scam type from triggered categories."""
        if "govt_impersonation" in categories:
            return "government_impersonation"
        elif "identity_scam" in categories:
            return "identity_theft"
        elif "telecom_scam" in categories:
            return "telecom_scam"
        elif "courier_scam" in categories:
            return "courier_scam"
        elif "job_loan_scam" in categories:
            return "job_loan_scam"
        elif "threat" in categories:
            return "intimidation_scam"
        elif "payment" in categories:
            return "payment_scam"
        elif "verification" in categories:
            return "phishing"
        else:
            return "generic_scam"
    
    def get_session_score(self, session_id: str) -> int:
        """Get the current risk score for a session."""
        return self.session_scores.get(session_id, 0)
    
    def get_detection_details(self, session_id: str) -> DetectionResult:
        """Get detailed detection result for a session."""
        return self.session_details.get(session_id, DetectionResult())
    
    def reset_session(self, session_id: str) -> None:
        """Clear score for a session (useful for testing)."""
        if session_id in self.session_scores:
            del self.session_scores[session_id]
        if session_id in self.session_details:
            del self.session_details[session_id]
        if session_id in self.session_categories:
            del self.session_categories[session_id]
        if session_id in self.session_message_count:
            del self.session_message_count[session_id]
        if session_id in self.session_intents:
            del self.session_intents[session_id]
        if session_id in self.session_stages:
            del self.session_stages[session_id]


# Single instance used across the app
detector = ScamDetector()
