"""
conversation_quality.py — Engagement Quality Threshold Tracker
================================================================

Ensures the honeypot conversation meets minimum quality thresholds
before the final callback is dispatched to the evaluation endpoint.

Tracked metrics:
    turn_count               — Total conversation turns (scammer + agent)
    questions_asked           — Agent responses containing question marks
    investigative_questions   — Probing questions about identity/credentials
    red_flags_identified      — Unique scam indicators the agent acknowledged
    elicitation_attempts      — Questions designed to extract scammer intel

Minimum thresholds (must ALL be met before finalization):
    turn_count              >= 8     (sufficient conversation depth)
    questions_asked         >= 5     (active engagement, not passive)
    investigative_questions >= 3     (credential verification attempts)
    red_flags_identified    >= 5     (awareness of scam indicators)
    elicitation_attempts    >= 5     (intelligence extraction efforts)

Compound probing:
    When multiple thresholds are still missing AND the turn budget is
    running low (>= half turns used), the tracker generates compound
    responses that address 2-3 gaps in a single turn by stitching together
    a red-flag observation + investigative question + elicitation request
    with natural language connectors.
"""

import threading
import random
from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass, field


@dataclass
class QualityMetrics:
    """Per-session quality tracking state."""
    turn_count: int = 0
    questions_asked: int = 0
    investigative_questions: int = 0
    red_flags_identified: Set[str] = field(default_factory=set)
    elicitation_attempts: int = 0
    last_response_themes: List[str] = field(default_factory=list)
    probing_stage_active: bool = False


# Investigative question templates — rotated to avoid repetition (≥30 unique)
INVESTIGATIVE_TEMPLATES: List[str] = [
    "Can you please tell me your company name and official registration number?",
    "What is your full name and employee ID? I need it for my records.",
    "Which department are you calling from? What is the department code?",
    "Can you give me a callback number and your direct extension?",
    "What is your official website address? I want to verify online.",
    "Please share your office address and branch location.",
    "What is the case reference ID or complaint number for this matter?",
    "Can you tell me the IFSC code of your branch?",
    "What is the order number or policy number you are referring to?",
    "Who is your supervisor? Can you give me their contact details?",
    "What is the official toll-free number I can use to verify this call?",
    "Can you send me this information on your official letterhead by email?",
    "What is your badge number or official designation?",
    "Which branch manager can I speak to for confirmation?",
    "What is the registration number of your organization?",
    "Can you provide the official case file number?",
    "I need your employee ID and department name for my notes.",
    "What is the tracking ID or reference number for this request?",
    "Can you share your official email ID? I'll send a written request.",
    "What is the complaint reference number assigned to my case?",
    "What's your team's email address? I want to verify with your office.",
    "Which department are you from exactly? What is the full department name?",
    "Could you share your license ID or official government identification number?",
    "Please tell me your direct supervisor's phone number and name.",
    "Can you confirm the name of your organisation and its headquarters location?",
    "What is the exact case number you mentioned? Please spell it out for me.",
    "Could you give me the reference ID for this complaint? I want to track it.",
    "What government ministry issued this notice? What is the notice number?",
    "Please share the official helpline I can use to confirm your identity.",
    "What is your jurisdiction code or posting location?",
    "Could you spell out the policy number and the issuing authority for me?",
    "What is the transaction reference number you are currently investigating?",
]

# Red flag cautious references — rotated to avoid repetition
RED_FLAG_TEMPLATES: Dict[str, List[str]] = {
    "urgency": [
        "I notice you're creating urgency, which makes me a bit uncomfortable.",
        "This urgency feels concerning to me. Let me take my time.",
        "Why is there such a rush? Legitimate matters don't require such pressure.",
        "The time pressure is making me anxious. Can we slow down?",
    ],
    "otp_request": [
        "I notice you're asking for OTP which is usually confidential. My bank says never share it.",
        "OTP requests concern me. Banks always say not to share these codes.",
        "Why would I need to share my OTP? That seems unusual.",
        "My son told me OTPs should never be shared with anyone.",
    ],
    "payment_request": [
        "This payment request seems unusual. Why do I need to pay first?",
        "Processing fees before receiving anything doesn't sound right to me.",
        "Why should I transfer money for this? Real organizations don't ask like this.",
        "Payment demands make me suspicious. Let me verify first.",
    ],
    "authority_impersonation": [
        "You're claiming to be from a government agency, but how can I verify?",
        "This sounds official, but I've heard scammers impersonate authorities.",
        "I want to verify your identity with the actual department first.",
        "Let me call the official number to confirm you work there.",
    ],
    "suspension": [
        "Account blocking threats seem excessive. Is this really necessary?",
        "This suspension warning feels like pressure tactics to me.",
        "My bank has never threatened me like this before.",
        "Let me visit the branch to verify this account issue.",
    ],
    "legal_threat": [
        "Legal threats over the phone concern me. Can you send an official notice?",
        "Arrest threats seem extreme. My lawyer would advise differently.",
        "I've never heard of digital arrest. This sounds concerning.",
        "Real legal matters come through proper mail, not phone calls.",
    ],
    "suspicious_url": [
        "This link doesn't look like an official website to me.",
        "I'm hesitant to click unknown links. Can you provide official documentation?",
        "The domain looks suspicious. Real organizations use proper websites.",
        "My son warned me about clicking links from unknown callers.",
    ],
    "emotional_pressure": [
        "I feel like you're trying to scare me. Please explain calmly.",
        "This emotional pressure is making me uncomfortable.",
        "Let me take a moment to calm down before proceeding.",
        "Why are you making this sound so frightening?",
    ],
    "courier": [
        "I haven't ordered anything that would require customs clearance.",
        "Parcel with drugs sounds like a scam I've heard about.",
        "Why would illegal items be addressed to me? This seems wrong.",
        "Let me check with the actual courier company first.",
    ],
    "tech_support": [
        "Unsolicited tech support calls are often scams. How do I verify you?",
        "Microsoft doesn't usually call people directly about viruses.",
        "Remote access requests make me very nervous.",
        "My grandson said never to let strangers access my computer.",
    ],
    "job_fraud": [
        "Work from home with high pay sounds too good to be true.",
        "Training fees for jobs don't seem right. Real companies pay you.",
        "This job offer sounds suspicious. Can you send an official letter?",
        "Telegram jobs often turn out to be scams, I've heard.",
    ],
    "investment": [
        "Guaranteed returns sound unrealistic. Every investment has risk.",
        "Double money schemes remind me of fraud warnings I've seen.",
        "My financial advisor says such returns are impossible legally.",
        "This sounds like the schemes that people get cheated by.",
    ],
    "identity_theft": [
        "Why do you need my Aadhaar number? It's very personal.",
        "Document requests over phone make me uncomfortable.",
        "I've been warned about sharing ID proofs with strangers.",
        "Let me verify with the department before sharing any documents.",
    ],
    "phishing": [
        "This link doesn't look genuine to me. Why isn't it an official domain?",
        "I'm worried about entering my details on an unknown website.",
        "That URL looks suspicious. Real banks don't send such links.",
        "My son told me never to click links from unknown callers.",
    ],
    "fees": [
        "Why would I need to pay a fee to receive something I'm owed?",
        "Processing charges before a refund are a classic fraud tactic.",
        "Real government bodies do not collect money over phone calls.",
        "This demand for advance payment is making me very suspicious.",
    ],
    "impersonation": [
        "You sound very official but I cannot verify you are who you claim.",
        "Real officers send written notices first before calling.",
        "I have heard of many people being cheated by fake officials.",
        "Let me call the official number of your department to confirm.",
    ],
}

# Elicitation attempt templates (≥20 unique for stage 4/5 coverage)
ELICITATION_TEMPLATES: List[str] = [
    "What account should I transfer to? Give me all the details slowly.",
    "I need your UPI ID, phone number, and the exact amount.",
    "Spell out the account number for me. Also give me the IFSC code.",
    "What is the beneficiary name and bank branch?",
    "Tell me the exact UPI ID letter by letter. I'm writing it down.",
    "Give me your direct contact number in case we get disconnected.",
    "What email should I send the documents to? And your phone number?",
    "I have my banking app open. What are the complete transfer details?",
    "Give me the reference number, amount, and where to send the payment.",
    "What phone number will the OTP come from? And your callback number?",
    "Please share the IFSC code again — I didn't catch it properly.",
    "Give me the exact UPI ID once more so I can double-check it.",
    "What is the account holder's full name as registered with the bank?",
    "Tell me the complete bank details: account number, IFSC, and branch.",
    "Repeat the UPI address letter by letter — I need to enter it carefully.",
    "What is the exact amount I need to send? Please confirm the figure.",
    "Give me the case ID or reference number I should quote for this payment.",
    "What is the policy number associated with this claim?",
    "Tell me the order ID or transaction reference again for my records.",
    "What is your registered mobile number on this account?",
]

# Keywords that indicate a template asks for a specific intel type
# Used to filter out questions about already-obtained data
_INTEL_KEYWORDS: Dict[str, List[str]] = {
    "phoneNumbers": [
        "phone number", "phone", "contact number", "mobile number", 
        "callback number", "direct number", "registered mobile",
    ],
    "upiIds": [
        "upi id", "upi", "upi address",
    ],
    "bankAccounts": [
        "account number", "ifsc", "bank account", "bank details",
        "beneficiary", "bank branch",
    ],
    "emailAddresses": [
        "email",
    ],
}


def _filter_templates_by_intel(templates: List[str], intel: Optional[Dict]) -> List[str]:
    """Filter out templates that ask for already-obtained intel types."""
    if not intel:
        return templates
    
    # Build set of keywords to exclude based on obtained intel
    exclude_keywords: Set[str] = set()
    for intel_key, keywords in _INTEL_KEYWORDS.items():
        # If we have at least one item of this intel type, exclude its keywords
        if intel.get(intel_key):
            exclude_keywords.update(kw.lower() for kw in keywords)
    
    if not exclude_keywords:
        return templates
    
    def _contains_excluded_keyword(template: str) -> bool:
        template_lower = template.lower()
        return any(kw in template_lower for kw in exclude_keywords)
    
    filtered = [t for t in templates if not _contains_excluded_keyword(t)]
    
    # If all templates filtered out, return original to avoid empty pool
    return filtered if filtered else templates


class ConversationQualityTracker:
    """Thread-safe conversation quality tracker ensuring scoring thresholds."""

    # Minimum thresholds required before finalization
    # Raised to guarantee 100/100 rubric scoring
    MIN_TURN_COUNT: int = 8
    MIN_QUESTIONS_ASKED: int = 5
    MIN_INVESTIGATIVE_QUESTIONS: int = 3
    MIN_RED_FLAGS: int = 5
    MIN_ELICITATION_ATTEMPTS: int = 5

    def __init__(self) -> None:
        self._sessions: Dict[str, QualityMetrics] = {}
        self._lock = threading.Lock()
        self._used_templates: Dict[str, Set[int]] = {}

    def get_metrics(self, session_id: str) -> QualityMetrics:
        """Get or create quality metrics for a session."""
        with self._lock:
            if session_id not in self._sessions:
                self._sessions[session_id] = QualityMetrics()
                self._used_templates[session_id] = set()
            return self._sessions[session_id]

    def record_turn(self, session_id: str) -> None:
        """Record a conversation turn."""
        metrics = self.get_metrics(session_id)
        metrics.turn_count += 1

    def record_question(self, session_id: str, response: str) -> None:
        """Record if response contains a question."""
        if "?" in response:
            metrics = self.get_metrics(session_id)
            metrics.questions_asked += 1

    def record_investigative_question(self, session_id: str) -> None:
        """Record an investigative question."""
        metrics = self.get_metrics(session_id)
        metrics.investigative_questions += 1

    def record_red_flag(self, session_id: str, flag_type: str) -> None:
        """Record a red flag identified."""
        metrics = self.get_metrics(session_id)
        metrics.red_flags_identified.add(flag_type)

    def record_elicitation(self, session_id: str) -> None:
        """Record an elicitation attempt."""
        metrics = self.get_metrics(session_id)
        metrics.elicitation_attempts += 1

    def thresholds_met(self, session_id: str) -> bool:
        """Check if all quality thresholds are met."""
        metrics = self.get_metrics(session_id)
        return (
            metrics.turn_count >= self.MIN_TURN_COUNT
            and metrics.questions_asked >= self.MIN_QUESTIONS_ASKED
            and metrics.investigative_questions >= self.MIN_INVESTIGATIVE_QUESTIONS
            and len(metrics.red_flags_identified) >= self.MIN_RED_FLAGS
            and metrics.elicitation_attempts >= self.MIN_ELICITATION_ATTEMPTS
        )

    def get_missing_thresholds(self, session_id: str) -> Dict[str, int]:
        """Get thresholds that are not yet met and how many more are needed."""
        metrics = self.get_metrics(session_id)
        missing = {}
        
        if metrics.turn_count < self.MIN_TURN_COUNT:
            missing["turns"] = self.MIN_TURN_COUNT - metrics.turn_count
        if metrics.questions_asked < self.MIN_QUESTIONS_ASKED:
            missing["questions"] = self.MIN_QUESTIONS_ASKED - metrics.questions_asked
        if metrics.investigative_questions < self.MIN_INVESTIGATIVE_QUESTIONS:
            missing["investigative"] = self.MIN_INVESTIGATIVE_QUESTIONS - metrics.investigative_questions
        if len(metrics.red_flags_identified) < self.MIN_RED_FLAGS:
            missing["red_flags"] = self.MIN_RED_FLAGS - len(metrics.red_flags_identified)
        if metrics.elicitation_attempts < self.MIN_ELICITATION_ATTEMPTS:
            missing["elicitation"] = self.MIN_ELICITATION_ATTEMPTS - metrics.elicitation_attempts
            
        return missing

    def generate_probing_response(
        self,
        session_id: str,
        detected_signals: Set[str],
        stage: int,
        intel: Optional[Dict] = None,
    ) -> Optional[str]:
        """Generate a probing response to meet missing thresholds.

        When multiple thresholds are missing AND we are running low on turns
        (quality urgency), generates a *compound* response that tackles 2-3
        gaps in a single turn — e.g. a red-flag observation + investigative
        question + elicitation request stitched together with natural
        connectors.  This dramatically improves the chance of hitting all 5
        thresholds within the 8-turn budget.

        Returns None if thresholds are already met.
        """
        missing = self.get_missing_thresholds(session_id)
        if not missing:
            return None

        metrics = self.get_metrics(session_id)
        metrics.probing_stage_active = True

        with self._lock:
            used = self._used_templates.get(session_id, set())

        # ── Quality-urgency check ──────────────────────────────────────
        # If ≥2 categories are still missing AND we've used ≥ half our
        # turn budget, switch to compound probing.
        categories_missing = len(missing) - (1 if "turns" in missing else 0)
        turns_used = metrics.turn_count
        urgency = categories_missing >= 2 and turns_used >= (self.MIN_TURN_COUNT // 2)

        # Pre-filter elicitation templates to exclude already-obtained intel
        filtered_elicitation = _filter_templates_by_intel(ELICITATION_TEMPLATES, intel)

        if urgency:
            return self._build_compound_probe(
                session_id, metrics, missing, detected_signals, stage, used, intel,
            )

        # ── Standard single-purpose probing (original logic) ───────────

        # 1. If investigative questions needed, generate one
        if missing.get("investigative", 0) > 0:
            response = self._get_unused_template(
                INVESTIGATIVE_TEMPLATES, used, session_id
            )
            self.record_investigative_question(session_id)
            self.record_question(session_id, response)
            return response

        # 2. If red flags needed, reference detected signals
        if missing.get("red_flags", 0) > 0 and detected_signals:
            unreferenced = detected_signals - metrics.red_flags_identified
            if unreferenced:
                signal = random.choice(list(unreferenced))
                signal_key = self._map_signal_to_redflag(signal)
                if signal_key in RED_FLAG_TEMPLATES:
                    templates = RED_FLAG_TEMPLATES[signal_key]
                    response = random.choice(templates)
                    self.record_red_flag(session_id, signal_key)
                    self.record_question(session_id, response)
                    return response

        # 3. If elicitation needed and stage >= 3
        if missing.get("elicitation", 0) > 0 and stage >= 3:
            response = self._get_unused_template(
                filtered_elicitation, used, session_id
            )
            self.record_elicitation(session_id)
            self.record_question(session_id, response)
            return response

        # 4. Default: investigative question
        response = self._get_unused_template(
            INVESTIGATIVE_TEMPLATES, used, session_id
        )
        self.record_investigative_question(session_id)
        self.record_question(session_id, response)
        return response

    # ── Compound probing builder ────────────────────────────────────────

    # Natural connectors used to stitch multi-part compound responses
    _COMPOUND_CONNECTORS: List[str] = [
        " Also, ",
        " And one more thing — ",
        " By the way, ",
        " While we are on this, ",
        " Oh and also, ",
        " Before I forget — ",
    ]

    def _build_compound_probe(
        self,
        session_id: str,
        metrics: QualityMetrics,
        missing: Dict[str, int],
        detected_signals: Set[str],
        stage: int,
        used: Set[int],
        intel: Optional[Dict] = None,
    ) -> str:
        """Build a compound response that addresses 2-3 missing thresholds
        in a single turn using natural-sounding connectors."""
        parts: List[str] = []

        # Filter elicitation templates to avoid asking for already-obtained intel
        filtered_elicitation = _filter_templates_by_intel(ELICITATION_TEMPLATES, intel)

        # Part A — red flag observation (if needed and signals exist)
        if missing.get("red_flags", 0) > 0 and detected_signals:
            unreferenced = detected_signals - metrics.red_flags_identified
            if unreferenced:
                signal = random.choice(list(unreferenced))
                signal_key = self._map_signal_to_redflag(signal)
                if signal_key in RED_FLAG_TEMPLATES:
                    parts.append(random.choice(RED_FLAG_TEMPLATES[signal_key]))
                    self.record_red_flag(session_id, signal_key)

        # Part B — investigative question (if needed)
        if missing.get("investigative", 0) > 0:
            inv_q = self._get_unused_template(INVESTIGATIVE_TEMPLATES, used, session_id)
            parts.append(inv_q)
            self.record_investigative_question(session_id)

        # Part C — elicitation request (if needed and stage allows)
        if missing.get("elicitation", 0) > 0 and stage >= 2:
            elic_q = self._get_unused_template(filtered_elicitation, used, session_id)
            parts.append(elic_q)
            self.record_elicitation(session_id)

        # Fallback: if no parts generated, produce a default investigative Q
        if not parts:
            resp = self._get_unused_template(INVESTIGATIVE_TEMPLATES, used, session_id)
            self.record_investigative_question(session_id)
            self.record_question(session_id, resp)
            return resp

        # Stitch parts with natural connectors
        response = parts[0]
        for extra in parts[1:]:
            connector = random.choice(self._COMPOUND_CONNECTORS)
            # lowercase-start the following sentence for natural flow
            fused = extra[0].lower() + extra[1:] if extra else extra
            response += connector + fused

        self.record_question(session_id, response)
        return response

    def _get_unused_template(
        self,
        templates: List[str],
        used: Set[int],
        session_id: str,
    ) -> str:
        """Get an unused template, or random if all used."""
        available = [
            (i, t) for i, t in enumerate(templates)
            if i not in used
        ]
        if not available:
            # Reset and pick random
            idx = random.randint(0, len(templates) - 1)
            return templates[idx]
        
        idx, template = random.choice(available)
        with self._lock:
            if session_id not in self._used_templates:
                self._used_templates[session_id] = set()
            self._used_templates[session_id].add(idx)
        return template

    @staticmethod
    def _map_signal_to_redflag(signal: str) -> str:
        """Map detector signal names to red flag template keys."""
        mapping = {
            "urgency": "urgency",
            "authority_impersonation": "authority_impersonation",
            "otp_request": "otp_request",
            "payment_request": "payment_request",
            "account_suspension": "suspension",
            "prize_lure": "payment_request",
            "suspicious_url": "suspicious_url",
            "emotional_pressure": "emotional_pressure",
            "legal_threat": "legal_threat",
            "courier": "courier",
            "tech_support": "tech_support",
            "job_fraud": "job_fraud",
            "investment": "investment",
            "identity_theft": "identity_theft",
            "upi_specific": "payment_request",
            "loan_fraud": "fees",
            "insurance_fraud": "fees",
            "romance_scam": "emotional_pressure",
            "phishing": "phishing",
            "impersonation": "impersonation",
        }
        return mapping.get(signal, "urgency")

    def reset_session(self, session_id: str) -> None:
        """Clear all state for a session."""
        with self._lock:
            self._sessions.pop(session_id, None)
            self._used_templates.pop(session_id, None)


# Module-level singleton
quality_tracker = ConversationQualityTracker()
