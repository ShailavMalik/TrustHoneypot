"""
Phase 2 – Multi-Layer Risk Scoring Engine (RiskAccumulator).

Weighted, cumulative risk scoring with nine signal layers:
  1. Urgency words          2. Authority impersonation
  3. OTP / credential req.  4. Payment request
  5. Account suspension      6. Prize / lottery lures
  7. Suspicious URLs         8. Emotional pressure
  9. Legal threat tone

Design principles:
  - Accumulate risk across turns (never reset).
  - Apply escalation bonuses for compound patterns.
  - Suppress false positives on benign greetings.
  - Classify scam type generically (rule-based + weighted).
"""
import re
import threading
from typing import Tuple, Dict, List, Set
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Valid scam type labels (per scoring rubric)
# ---------------------------------------------------------------------------
VALID_SCAM_TYPES = frozenset([
    "bank_fraud", "upi_fraud", "phishing", "impersonation",
    "investment", "courier", "lottery", "unknown",
])


@dataclass
class RiskProfile:
    """Per-session accumulated risk state."""
    cumulative_score: float = 0.0
    turn_scores: List[float] = field(default_factory=list)
    triggered_signals: Set[str] = field(default_factory=set)
    signal_counts: Dict[str, int] = field(default_factory=dict)
    scam_detected: bool = False
    scam_type: str = "unknown"
    message_count: int = 0


class RiskAccumulator:
    """
    Production-grade multi-layer risk scoring engine.

    Public API
    ----------
    analyze_message(text, session_id) -> (cumulative_score, is_scam)
    get_profile(session_id) -> RiskProfile
    get_scam_type(session_id) -> str
    """

    SCAM_THRESHOLD = 50.0

    # =====================================================================
    # SIGNAL LAYER DEFINITIONS  (pattern, weight)
    # =====================================================================

    URGENCY_PATTERNS = [
        (r'\b(urgent|urgently|immediate(?:ly)?|right\s*now|asap)\b', 12),
        (r'\b(hurry|quickly|fast|jaldi|turant|abhi)\b', 10),
        (r'\b(within\s*\d+\s*(?:hour|minute|min|day)s?|today\s*only)\b', 14),
        (r'\b(last\s*chance|final\s*(?:notice|warning|chance)|expir(?:e|ing|ed))\b', 16),
        (r'\b(deadline|time\s*(?:running|left)|before\s*\d+)\b', 12),
        (r'\b(act\s*now|don.t\s*wait|limited\s*time)\b', 14),
    ]

    AUTHORITY_PATTERNS = [
        (r'\b(rbi|reserve\s*bank)\b', 18),
        (r'\b(income\s*tax|it\s*department)\b', 16),
        (r'\b(police|cbi|ed|enforcement\s*directorate)\b', 18),
        (r'\b(trai|dot|department\s*of\s*telecom)\b', 16),
        (r'\b(customs|ministry|government)\b', 14),
        (r'\b(officer|inspector|commissioner|superintendent)\b', 12),
        (r'\b(uidai|npci|sebi|irda)\b', 14),
        (r'\b(cyber\s*cell|cyber\s*crime|cyber\s*police)\b', 16),
        (r'\b(central\s*bureau|investigation\s*agency)\b', 18),
        (r'\b(supreme\s*court|high\s*court|court\s*order)\b', 16),
        (r'\b(pradhan\s*mantri|pm\s*scheme|govt\s*scheme)\b', 14),
    ]

    OTP_PATTERNS = [
        (r'\b(otp|one\s*time\s*password|verification\s*code)\b', 20),
        (r'\b(?:share|send|tell|give|provide)\s*(?:me\s*)?(?:the\s*)?(?:otp|code|pin)\b', 25),
        (r'\b\d\s*digit\s*(?:code|otp|pin|password)\b', 22),
        (r'\b(?:enter|type|input)\s*(?:the\s*)?(?:otp|code|pin)\b', 22),
        (r'\b(cvv|atm\s*pin|card\s*pin|mpin)\b', 22),
    ]

    PAYMENT_PATTERNS = [
        (r'\b(?:send|transfer|pay)\s*(?:me|us|the|now|rs|₹|\d+)\b', 18),
        (r'\b(processing\s*fee|registration\s*fee|advance\s*payment)\b', 20),
        (r'\b(pay\s*now|transfer\s*now|send\s*money)\b', 18),
        (r'\b(?:amount|money)\s*(?:of|is|due|required|pending)\b', 14),
        (r'\b(demand\s*draft|neft|rtgs|imps)\b', 10),
        (r'\b(?:refund|cashback|reward)\s*(?:of|is|amount|pending|process)\b', 16),
    ]

    SUSPENSION_PATTERNS = [
        (r'\b(?:account|a/c)\s*(?:will\s*be\s*)?(?:suspend|block|deactivat|freez|terminat)\w*\b', 18),
        (r'\b(?:suspend|block|deactivat|freez|terminat)(?:ed|ion|ing)\s*(?:your\s*)?(?:account|a/c|card|number|sim)?\b', 16),
        (r'\b(?:kyc|ekyc|re-?kyc)\s*(?:update|expir|fail|mandatory|required|pending)\b', 18),
        (r'\b(?:sim|number|mobile)\s*(?:will\s*be\s*)?(?:block|deactivat|suspend)\b', 16),
        (r'\b(?:aadhaar|aadhar|pan)\s*(?:block|suspend|deactivat|cancel)\b', 16),
    ]

    LURE_PATTERNS = [
        (r'\b(?:won|winner|winning|congratulat)\w*\b', 16),
        (r'\b(prize|lottery|lucky\s*draw|jackpot)\b', 18),
        (r'\b(?:cashback|cash\s*back|bonus|reward)\s*(?:of|is|amount)?\b', 14),
        (r'\b(?:claim|collect|receive|redeem)\s*(?:your\s*)?(?:prize|reward|money|amount)\b', 16),
        (r'\b(?:guaranteed\s*returns?|double\s*your\s*money|high\s*returns?)\b', 18),
    ]

    URL_PATTERNS = [
        (r'https?://[^\s<>"{}|\\^`\[\]]+', 12),
        (r'\b(?:bit\.ly|tinyurl|goo\.gl|t\.co|rb\.gy|is\.gd|cutt\.ly|shorturl)\b', 16),
        (r'\b(?:click\s*here|click\s*this|tap\s*here|click\s*below|open\s*this)\b', 14),
        (r'\b(?:wa\.me|whatsapp\.com|t\.me)\b', 10),
        (r'[a-z0-9]+\.(?:xyz|top|online|site|work|click)\b', 14),
    ]

    EMOTIONAL_PATTERNS = [
        (r'\b(scared|afraid|worried|danger|risk|destroy)\b', 10),
        (r'\b(?:your\s*(?:family|children|reputation))\b', 12),
        (r'\b(embarrass|shame|disgrace|ruin)\b', 12),
        (r'\b(?:save|protect)\s*yourself\b', 8),
        (r'\b(?:trust\s*me|believe\s*me|honest|genuine)\b', 6),
        (r'\b(confidential|secret|private|between\s*us)\b', 10),
    ]

    LEGAL_THREAT_PATTERNS = [
        (r'\b(legal\s*action|legal\s*notice|legal\s*proceedings?)\b', 16),
        (r'\b(arrest|warrant|fir|complaint)\b', 16),
        (r'\b(jail|prison|imprison|custody|detention)\b', 18),
        (r'\b(penalty|fine|prosecution|indictment)\b', 14),
        (r'\b(?:case\s*(?:filed|registered)|under\s*investigation)\b', 16),
        (r'\b(digital\s*arrest|video\s*call\s*arrest)\b', 20),
        (r'\b(money\s*laundering|terror\s*funding|hawala)\b', 20),
    ]

    # Benign greeting patterns – first-message suppression
    GREETING_ONLY = [
        r'^[\s]*(hello|hi|hey|namaste|namaskar|good\s*(?:morning|afternoon|evening|day))[\s!.,?]*$',
        r'^[\s]*(greetings|howdy|salam|jai\s*hind)[\s!.,?]*$',
        r'^[\s]*(how\s*are\s*you|hope\s*you.?re\s*well)[\s?.!]*$',
    ]

    # Escalation bonuses for multiple signal categories
    ESCALATION_BONUSES = {2: 8, 3: 18, 4: 30, 5: 45, 6: 55, 7: 65}

    # Courier / UPI / Investment – auxiliary layers
    COURIER_AUX = [
        (r'\b(?:parcel|courier|package|shipment)\s*.{0,20}(?:seiz|held|illegal|drugs|contraband)\b', 20),
        (r'\b(?:customs|customs\s*duty|import\s*duty)\b', 14),
        (r'\b(?:drugs|contraband|illegal\s*items?)\s*.{0,20}(?:found|detected|seized)\b', 20),
    ]
    UPI_AUX = [
        (r'\b(?:upi\s*id|upi\s*address|bhim\s*id)\b', 12),
        (r'[\w.-]+@(?:paytm|ybl|oksbi|okaxis|okicici|upi|phonepe|gpay)\b', 14),
        (r'\b(?:scan\s*(?:the\s*)?(?:qr|code)|upi\s*transfer)\b', 12),
    ]
    INVEST_AUX = [
        (r'\b(?:invest|trading|forex|crypto|bitcoin)\s*.{0,20}(?:guaranteed|profit|returns?|income)\b', 18),
        (r'\b(?:double|triple|10x)\s*(?:your\s*)?(?:money|investment|capital)\b', 20),
        (r'\b(?:mutual\s*fund|stock\s*tip|insider\s*info)\b', 14),
    ]

    # -----------------------------------------------------------------
    def __init__(self):
        self._profiles: Dict[str, RiskProfile] = {}
        self._lock = threading.Lock()

    # -----------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------

    def analyze_message(self, text: str, session_id: str) -> Tuple[float, bool]:
        """
        Score a single scammer message and accumulate risk.

        Returns (cumulative_score, is_scam).
        """
        if not text or not text.strip():
            p = self._get_profile(session_id)
            return p.cumulative_score, p.scam_detected

        profile = self._get_profile(session_id)
        profile.message_count += 1

        # Suppress scoring on pure greetings (first message only)
        if profile.message_count == 1 and self._is_pure_greeting(text):
            profile.turn_scores.append(0.0)
            return 0.0, False

        turn_score = 0.0
        turn_signals: Set[str] = set()

        # Core signal layers
        layers = [
            ("urgency",              self.URGENCY_PATTERNS),
            ("authority_impersonation", self.AUTHORITY_PATTERNS),
            ("otp_request",          self.OTP_PATTERNS),
            ("payment_request",      self.PAYMENT_PATTERNS),
            ("account_suspension",   self.SUSPENSION_PATTERNS),
            ("prize_lure",           self.LURE_PATTERNS),
            ("suspicious_url",       self.URL_PATTERNS),
            ("emotional_pressure",   self.EMOTIONAL_PATTERNS),
            ("legal_threat",         self.LEGAL_THREAT_PATTERNS),
        ]
        for name, patterns in layers:
            s = self._score_layer(text, patterns)
            if s > 0:
                turn_score += s
                turn_signals.add(name)
                profile.signal_counts[name] = profile.signal_counts.get(name, 0) + 1

        # Auxiliary layers
        for name, patterns in [("courier", self.COURIER_AUX),
                                ("upi_specific", self.UPI_AUX),
                                ("investment", self.INVEST_AUX)]:
            s = self._score_layer(text, patterns)
            if s > 0:
                turn_score += s
                turn_signals.add(name)
                profile.signal_counts[name] = profile.signal_counts.get(name, 0) + 1

        # Accumulate signals
        profile.triggered_signals.update(turn_signals)

        # Escalation bonus
        n_cat = len(profile.triggered_signals)
        esc = 0.0
        for threshold in sorted(self.ESCALATION_BONUSES.keys(), reverse=True):
            if n_cat >= threshold:
                esc = self.ESCALATION_BONUSES[threshold]
                break

        # Repeat-signal bonus (same category across multiple turns)
        repeat = sum(5 if c == 2 else (10 if c >= 3 else 0)
                     for c in profile.signal_counts.values())

        profile.turn_scores.append(turn_score)
        profile.cumulative_score += turn_score + esc + repeat

        # Threshold check
        if profile.cumulative_score >= self.SCAM_THRESHOLD:
            profile.scam_detected = True
            profile.scam_type = self._classify(profile)

        return profile.cumulative_score, profile.scam_detected

    def get_profile(self, session_id: str) -> RiskProfile:
        return self._get_profile(session_id)

    def get_scam_type(self, session_id: str) -> str:
        return self._get_profile(session_id).scam_type

    def get_triggered_signals(self, session_id: str) -> Set[str]:
        return self._get_profile(session_id).triggered_signals.copy()

    def reset_session(self, session_id: str) -> None:
        with self._lock:
            self._profiles.pop(session_id, None)

    # -----------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------

    def _get_profile(self, session_id: str) -> RiskProfile:
        with self._lock:
            if session_id not in self._profiles:
                self._profiles[session_id] = RiskProfile()
            return self._profiles[session_id]

    @staticmethod
    def _score_layer(text: str, patterns: list) -> float:
        score = 0.0
        t = text.lower()
        for pat, weight in patterns:
            if re.search(pat, t, re.IGNORECASE):
                score += weight
        return score

    def _is_pure_greeting(self, text: str) -> bool:
        for pat in self.GREETING_ONLY:
            if re.match(pat, text.strip(), re.IGNORECASE):
                return True
        return False

    def _classify(self, profile: RiskProfile) -> str:
        """Rule-based + weighted scam type classification."""
        t = profile.triggered_signals

        # Courier is distinctive
        if "courier" in t:
            return "courier"

        # Investment
        if "investment" in t:
            return "investment"

        # UPI fraud
        if "upi_specific" in t:
            return "upi_fraud"

        # Lottery / prize
        if "prize_lure" in t:
            return "lottery"

        # Authority impersonation (with or without legal threats)
        if "authority_impersonation" in t:
            return "impersonation"

        # Phishing (OTP / credential / URL driven)
        if "otp_request" in t or "suspicious_url" in t:
            return "phishing"

        # Bank fraud (suspension / generic payment)
        if "account_suspension" in t or "payment_request" in t:
            return "bank_fraud"

        # Legal threats alone
        if "legal_threat" in t:
            return "impersonation"

        return "unknown"


# Module-level singleton
risk_accumulator = RiskAccumulator()
