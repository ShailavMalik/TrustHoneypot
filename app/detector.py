"""
Multi-layer risk scoring engine for scam detection.

Analyses messages through 9 core + 3 auxiliary signal layers and
maintains a cumulative risk score per session. Score >= 50 triggers
scam confirmation. First-message greetings are suppressed.
"""

import re
import threading
from typing import Tuple, Dict, List, Set
from dataclasses import dataclass, field


VALID_SCAM_TYPES = frozenset([
    "bank_fraud", "upi_fraud", "phishing", "impersonation",
    "investment", "courier", "lottery", "unknown",
])


@dataclass
class RiskProfile:
    """Per-session risk accumulation state."""
    cumulative_score: float = 0.0
    turn_scores: List[float] = field(default_factory=list)
    triggered_signals: Set[str] = field(default_factory=set)
    signal_counts: Dict[str, int] = field(default_factory=dict)
    scam_detected: bool = False
    scam_type: str = "unknown"
    message_count: int = 0


class RiskAccumulator:
    """
    Scores scammer messages through multiple signal layers and accumulates
    risk per session. Thread-safe via lock on the session dict.
    """

    SCAM_THRESHOLD: float = 50.0
    # Signal layers — each is a list of (regex, weight) tuples

    URGENCY_PATTERNS = [
        (r'\b(urgent|urgently|immediate(?:ly)?|right\s*now|asap)\b',           12),
        (r'\b(hurry|quickly|fast|jaldi|turant|abhi)\b',                        10),
        (r'\b(within\s*\d+\s*(?:hour|minute|min|day)s?|today\s*only)\b',       14),
        (r'\b(last\s*chance|final\s*(?:notice|warning|chance)|expir(?:e|ing|ed))\b', 16),
        (r'\b(deadline|time\s*(?:running|left)|before\s*\d+)\b',               12),
        (r'\b(act\s*now|don.t\s*wait|limited\s*time)\b',                       14),
    ]

    AUTHORITY_PATTERNS = [
        (r'\b(rbi|reserve\s*bank)\b',                                          18),
        (r'\b(income\s*tax|it\s*department)\b',                                16),
        (r'\b(police|cbi|ed|enforcement\s*directorate)\b',                     18),
        (r'\b(trai|dot|department\s*of\s*telecom)\b',                          16),
        (r'\b(customs|ministry|government)\b',                                 14),
        (r'\b(officer|inspector|commissioner|superintendent)\b',               12),
        (r'\b(uidai|npci|sebi|irda)\b',                                        14),
        (r'\b(cyber\s*cell|cyber\s*crime|cyber\s*police)\b',                   16),
        (r'\b(central\s*bureau|investigation\s*agency)\b',                     18),
        (r'\b(supreme\s*court|high\s*court|court\s*order)\b',                  16),
        (r'\b(pradhan\s*mantri|pm\s*scheme|govt\s*scheme)\b',                  14),
    ]

    OTP_PATTERNS = [
        (r'\b(otp|one\s*time\s*password|verification\s*code)\b',               20),
        (r'\b(?:share|send|tell|give|provide)\s*(?:me\s*)?(?:the\s*)?(?:otp|code|pin)\b', 25),
        (r'\b\d\s*digit\s*(?:code|otp|pin|password)\b',                       22),
        (r'\b(?:enter|type|input)\s*(?:the\s*)?(?:otp|code|pin)\b',            22),
        (r'\b(cvv|atm\s*pin|card\s*pin|mpin)\b',                              22),
    ]

    PAYMENT_PATTERNS = [
        (r'\b(?:send|transfer|pay)\s*(?:me|us|the|now|rs|₹|\d+)\b',           18),
        (r'\b(processing\s*fee|registration\s*fee|advance\s*payment)\b',       20),
        (r'\b(pay\s*now|transfer\s*now|send\s*money)\b',                       18),
        (r'\b(?:amount|money)\s*(?:of|is|due|required|pending)\b',             14),
        (r'\b(demand\s*draft|neft|rtgs|imps)\b',                               10),
        (r'\b(?:refund|cashback|reward)\s*(?:of|is|amount|pending|process)\b', 16),
    ]

    SUSPENSION_PATTERNS = [
        (r'\b(?:account|a/c)\s*(?:will\s*be\s*)?(?:suspend|block|deactivat|freez|terminat)\w*\b', 18),
        (r'\b(?:suspend|block|deactivat|freez|terminat)(?:ed|ion|ing)\s*(?:your\s*)?(?:account|a/c|card|number|sim)?\b', 16),
        (r'\b(?:kyc|ekyc|re-?kyc)\s*(?:update|expir|fail|mandatory|required|pending)\b', 18),
        (r'\b(?:sim|number|mobile)\s*(?:will\s*be\s*)?(?:block|deactivat|suspend)\b', 16),
        (r'\b(?:aadhaar|aadhar|pan)\s*(?:block|suspend|deactivat|cancel)\b',  16),
    ]

    LURE_PATTERNS = [
        (r'\b(?:won|winner|winning|congratulat)\w*\b',                         16),
        (r'\b(prize|lottery|lucky\s*draw|jackpot)\b',                          18),
        (r'\b(?:cashback|cash\s*back|bonus|reward)\s*(?:of|is|amount)?\b',     14),
        (r'\b(?:claim|collect|receive|redeem)\s*(?:your\s*)?(?:prize|reward|money|amount)\b', 16),
        (r'\b(?:guaranteed\s*returns?|double\s*your\s*money|high\s*returns?)\b', 18),
    ]

    URL_PATTERNS = [
        (r'https?://[^\s<>"{}|\\^`\[\]]+',                                    12),
        (r'\b(?:bit\.ly|tinyurl|goo\.gl|t\.co|rb\.gy|is\.gd|cutt\.ly|shorturl)\b', 16),
        (r'\b(?:click\s*here|click\s*this|tap\s*here|click\s*below|open\s*this)\b', 14),
        (r'\b(?:wa\.me|whatsapp\.com|t\.me)\b',                               10),
        (r'[a-z0-9]+\.(?:xyz|top|online|site|work|click)\b',                  14),
    ]

    EMOTIONAL_PATTERNS = [
        (r'\b(scared|afraid|worried|danger|risk|destroy)\b',                   10),
        (r'\b(?:your\s*(?:family|children|reputation))\b',                     12),
        (r'\b(embarrass|shame|disgrace|ruin)\b',                               12),
        (r'\b(?:save|protect)\s*yourself\b',                                    8),
        (r'\b(?:trust\s*me|believe\s*me|honest|genuine)\b',                     6),
        (r'\b(confidential|secret|private|between\s*us)\b',                    10),
    ]

    LEGAL_THREAT_PATTERNS = [
        (r'\b(legal\s*action|legal\s*notice|legal\s*proceedings?)\b',          16),
        (r'\b(arrest|warrant|fir|complaint)\b',                                16),
        (r'\b(jail|prison|imprison|custody|detention)\b',                      18),
        (r'\b(penalty|fine|prosecution|indictment)\b',                         14),
        (r'\b(?:case\s*(?:filed|registered)|under\s*investigation)\b',         16),
        (r'\b(digital\s*arrest|video\s*call\s*arrest)\b',                      20),
        (r'\b(money\s*laundering|terror\s*funding|hawala)\b',                  20),
    ]

    # Greetings that shouldn't trigger any score on first message
    GREETING_ONLY = [
        r'^[\s]*(hello|hi|hey|namaste|namaskar|good\s*(?:morning|afternoon|evening|day))[\s!.,?]*$',
        r'^[\s]*(greetings|howdy|salam|jai\s*hind)[\s!.,?]*$',
        r'^[\s]*(how\s*are\s*you|hope\s*you.?re\s*well)[\s?.!]*$',
    ]

    # Extra points for triggering multiple distinct signal categories
    ESCALATION_BONUSES: Dict[int, float] = {
        2: 8,
        3: 18,
        4: 30,
        5: 45,
        6: 55,
        7: 65,
    }

    # Auxiliary pattern layers
    COURIER_AUX = [
        (r'\b(?:parcel|courier|package|shipment)\s*.{0,20}(?:seiz|held|illegal|drugs|contraband)\b', 20),
        (r'\b(?:customs|customs\s*duty|import\s*duty)\b',               14),
        (r'\b(?:drugs|contraband|illegal\s*items?)\s*.{0,20}(?:found|detected|seized)\b', 20),
    ]
    UPI_AUX = [
        (r'\b(?:upi\s*id|upi\s*address|bhim\s*id)\b',                  12),
        (r'[\w.-]+@(?:paytm|ybl|oksbi|okaxis|okicici|upi|phonepe|gpay)\b', 14),
        (r'\b(?:scan\s*(?:the\s*)?(?:qr|code)|upi\s*transfer)\b',      12),
    ]
    INVEST_AUX = [
        (r'\b(?:invest|trading|forex|crypto|bitcoin)\s*.{0,20}(?:guaranteed|profit|returns?|income)\b', 18),
        (r'\b(?:double|triple|10x)\s*(?:your\s*)?(?:money|investment|capital)\b', 20),
        (r'\b(?:mutual\s*fund|stock\s*tip|insider\s*info)\b',           14),
    ]

    def __init__(self) -> None:
        self._profiles: Dict[str, RiskProfile] = {}
        self._lock = threading.Lock()

    def analyze_message(self, text: str, session_id: str) -> Tuple[float, bool]:
        """Score a message and return (cumulative_score, is_scam)."""
        # Empty message — just return current state
        if not text or not text.strip():
            profile = self._get_profile(session_id)
            return profile.cumulative_score, profile.scam_detected

        profile = self._get_profile(session_id)
        profile.message_count += 1

        # Pure greeting on first message — don't bump score
        if profile.message_count == 1 and self._is_pure_greeting(text):
            profile.turn_scores.append(0.0)
            return 0.0, False

        # Score every signal layer
        turn_score: float = 0.0
        turn_signals: Set[str] = set()

        core_layers = [
            ("urgency",                self.URGENCY_PATTERNS),
            ("authority_impersonation", self.AUTHORITY_PATTERNS),
            ("otp_request",            self.OTP_PATTERNS),
            ("payment_request",        self.PAYMENT_PATTERNS),
            ("account_suspension",     self.SUSPENSION_PATTERNS),
            ("prize_lure",             self.LURE_PATTERNS),
            ("suspicious_url",         self.URL_PATTERNS),
            ("emotional_pressure",     self.EMOTIONAL_PATTERNS),
            ("legal_threat",           self.LEGAL_THREAT_PATTERNS),
        ]
        auxiliary_layers = [
            ("courier",      self.COURIER_AUX),
            ("upi_specific", self.UPI_AUX),
            ("investment",   self.INVEST_AUX),
        ]

        for name, patterns in core_layers + auxiliary_layers:
            layer_score = self._score_layer(text, patterns)
            if layer_score > 0:
                turn_score += layer_score
                turn_signals.add(name)
                profile.signal_counts[name] = (
                    profile.signal_counts.get(name, 0) + 1
                )

        # Accumulate session-level signals
        profile.triggered_signals.update(turn_signals)

        # Escalation bonus for compound patterns
        distinct_categories = len(profile.triggered_signals)
        escalation_bonus: float = 0.0
        for threshold in sorted(self.ESCALATION_BONUSES, reverse=True):
            if distinct_categories >= threshold:
                escalation_bonus = self.ESCALATION_BONUSES[threshold]
                break

        # Repeat-signal bonus — persistent tactics get extra points
        repeat_bonus: float = sum(
            5 if count == 2 else (10 if count >= 3 else 0)
            for count in profile.signal_counts.values()
        )

        # Update cumulative score
        profile.turn_scores.append(turn_score)
        profile.cumulative_score += turn_score + escalation_bonus + repeat_bonus

        # Check threshold
        if profile.cumulative_score >= self.SCAM_THRESHOLD:
            profile.scam_detected = True
            profile.scam_type = self._classify(profile)

        return profile.cumulative_score, profile.scam_detected

    def get_profile(self, session_id: str) -> RiskProfile:
        """Return the full risk profile for a session."""
        return self._get_profile(session_id)

    def get_scam_type(self, session_id: str) -> str:
        return self._get_profile(session_id).scam_type

    def get_triggered_signals(self, session_id: str) -> Set[str]:
        """Return a copy of the triggered signal names."""
        return self._get_profile(session_id).triggered_signals.copy()

    def reset_session(self, session_id: str) -> None:
        """Discard all state for a session."""
        with self._lock:
            self._profiles.pop(session_id, None)

    def _get_profile(self, session_id: str) -> RiskProfile:
        with self._lock:
            if session_id not in self._profiles:
                self._profiles[session_id] = RiskProfile()
            return self._profiles[session_id]

    @staticmethod
    def _score_layer(text: str, patterns: list) -> float:
        """Sum weights of all matching patterns."""
        total = 0.0
        lowered = text.lower()
        for pattern, weight in patterns:
            if re.search(pattern, lowered, re.IGNORECASE):
                total += weight
        return total

    def _is_pure_greeting(self, text: str) -> bool:
        """Check if text is just a greeting."""
        stripped = text.strip()
        return any(
            re.match(pat, stripped, re.IGNORECASE)
            for pat in self.GREETING_ONLY
        )

    def _classify(self, profile: RiskProfile) -> str:
        """Pick the most specific scam-type label based on triggered signals."""
        signals = profile.triggered_signals

        if "courier" in signals:
            return "courier"
        if "investment" in signals:
            return "investment"
        if "upi_specific" in signals:
            return "upi_fraud"
        if "prize_lure" in signals:
            return "lottery"
        if "authority_impersonation" in signals:
            return "impersonation"
        if "otp_request" in signals or "suspicious_url" in signals:
            return "phishing"
        if "account_suspension" in signals or "payment_request" in signals:
            return "bank_fraud"
        if "legal_threat" in signals:
            return "impersonation"

        return "unknown"


# Module-level singleton
risk_accumulator = RiskAccumulator()
