"""5-stage adaptive engagement engine. Generates human-like victim-persona
responses to keep scammers talking and extract intelligence.

Phase 2.1 — ML-enhanced response selection:
  Uses DeepEngagementEngine for neural response ranking when available,
  with graceful fallback to weighted-random selection."""

import logging
import random
import threading
from typing import Dict, List, Set

logger = logging.getLogger(__name__)


class EngagementController:
    """Generates human-like victim-persona responses across five adaptive stages."""

    # Stage 1 — Confused but curious
    STAGE_1: List[str] = [
        "Hello? I don't think we've spoken before. Who is this?",
        "Ji? Kaun bol raha hai? I don't recognise this number.",
        "Hello, may I know who's calling please?",
        "Sorry, I didn't catch that. Who is this speaking?",
        "Good day. Can you please introduce yourself?",
        "Yes, hello? Who am I speaking with?",
        "Namaste. Aap kaun? I wasn't expecting any calls.",
        "Hello, this is unexpected. May I know who you are?",
        "Ji boliye? I don't have this number saved.",
        "Hello? Is this a business call? Please identify yourself first.",
        "Haan ji? Who is calling?",
        "Sorry, I think you may have the wrong number. Who are you looking for?",
        "I'm a bit confused. Can you tell me what this is regarding?",
        "Who gave you my number? I don't usually get calls like this.",
    ]

    # Stage 2 — Verifying authenticity (enhanced with intelligence extraction)
    STAGE_2: List[str] = [
        "How do I know this is legitimate? Can you give me your employee ID and callback number?",
        "I need to verify this. What is your official email address and employee ID number?",
        "Can you give me a reference number and your direct phone number? I want to check with the main office.",
        "This doesn't sound right. What is your official contact number and department name?",
        "Can you send me an official email first? What email address should I expect it from?",
        "Before I do anything, please share your full name, ID number, and official contact details.",
        "My son warned me about calls like these. Give me your supervisor's name and phone number.",
        "What is your official designation and employee ID? I want to note it down.",
        "Can you send this on official letterhead? What is the email address and reference number?",
        "Let me verify — what is your organisation's toll-free number and your direct extension?",
        "Please provide your department name, employee ID, and a reference number for my records.",
        "Is there a website link you can share? I want to verify this online.",
        "Which branch or department are you calling from? Give me the phone number and address.",
        "Can you spell your full name and provide your contact number? I want to verify with your office.",
    ]

    # Stage 3 — Concerned and cautious
    STAGE_3: List[str] = [
        "Oh no, this sounds serious. But I'm not sure what to do.",
        "You're worrying me now. Let me think for a moment.",
        "I'm concerned but I don't want to do anything hasty without checking.",
        "Please don't rush me. My blood pressure goes up when I get stressed.",
        "Wait, let me call my son first. He knows about these things.",
        "I'm a senior citizen, I don't understand all this. Please be patient.",
        "This is making me anxious. Can you explain once more slowly?",
        "My neighbour got a similar call. She said it was not real. Are you sure?",
        "I want to cooperate but I'm scared of doing something wrong.",
        "Let me sit down first. My hands are shaking. Now tell me again.",
        "I trust the government but this call is making me nervous.",
        "Can I call you back after discussing with my family?",
        "One minute, someone is at the door. Don't disconnect, I'll be right back.",
        "Hold on, my phone battery is very low. Let me put it on charging.",
    ]

    # Stage 4 — Cooperative but probing (enhanced intelligence extraction)
    STAGE_4: List[str] = [
        "Okay, I believe you. Give me your direct callback number and employee ID so I can reach you.",
        "Fine, I'll cooperate. What department ID and reference number should I keep for my records?",
        "Alright sir, tell me what to do. What is the case reference number and your contact phone number?",
        "I'm ready to help. Give me the official branch name, address, and contact number please.",
        "Okay okay, I'll do it. Tell me your phone number, email, and reference ID for verification.",
        "I trust you now. For my records, give me your full name, badge number, and office phone.",
        "Sir, I want to cooperate fully. Can you resend that link and tell me the website address?",
        "I understand the urgency. Share the account details, UPI ID, and amount again please.",
        "Fine, I'll proceed. Can you email me at what address? And give me yours also.",
        "Alright, let me note everything. What is the reference number, your contact, and department?",
        "Okay, I'm convinced. Give me the complaint number, your phone number, and supervisor's contact.",
        "I'll do whatever is needed. Which email should I write to? And what is your official phone number?",
        "I believe you are genuine. Share your official contact number, email, and department details.",
        "My son said I should always get documentation. Can you share your ID, phone, and receipt number?",
    ]

    # Stage 5 — Extraction-focused questioning (maximum intelligence elicitation)
    STAGE_5: List[str] = [
        "Okay, I'm ready. What is the exact UPI ID, account holder name, and phone number to send to?",
        "Tell me the complete account number slowly. I am writing it down. Also give me the IFSC code.",
        "Which bank account should I transfer to? Give me account number, name, branch, and IFSC.",
        "What is the exact amount and where to send? Spell the UPI ID letter by letter for me.",
        "I have my banking app open. Give me the full account number, beneficiary name, and phone number.",
        "Should I send by UPI or bank transfer? Tell me the UPI ID and also the bank account details.",
        "I'm ready to pay. Give me the reference number, amount, UPI ID, and your contact number.",
        "What name will show when I transfer? I want to confirm. Also tell me your phone number.",
        "UPI is showing an error. Give me the bank account number, IFSC code, and account holder name.",
        "My app is asking for beneficiary details. Tell me account number, name, phone, and IFSC code.",
        "Give me complete details — account number, account holder name, bank name, branch, and IFSC.",
        "I'll send right now. Repeat the UPI ID letter by letter and tell me your registered phone number.",
        "Okay, should I do it from my savings account? Tell me your UPI ID, bank account, and contact number.",
        "Let me try sending a small amount first. What's the exact UPI ID and your WhatsApp number?",
    ]

    # Intent-specific response pools (override stage when scammer uses specific tactics)

    OTP_RESPONSES: List[str] = [
        "OTP? Wait, let me check my messages… which number does it come from? Is it from what number?",
        "My OTP is not coming. Network is weak here. What number should I expect SMS from?",
        "I got several messages. Which OTP do you need? There are 3-4 here. What number sent it?",
        "The OTP says 'do not share with anyone'. Should I still give it? And to whom am I sharing this?",
        "It says the OTP expired already. Can you resend it? What is the sender's number or email?",
        "I pressed the wrong button and message got deleted. Please resend and tell me your phone number.",
        "OTP is showing but screen is dim. Let me increase brightness… But what is your official contact?",
        "My eyes are weak, I cannot read small text. Can you tell me your phone number first?",
        "OTP has come but phone is asking for fingerprint. Meanwhile, give me your contact details.",
        "My son changed my SIM last week. OTP might go to old number. What is your callback number?",
    ]

    ACCOUNT_RESPONSES: List[str] = [
        "Account number? Which one — savings or fixed deposit? And tell me your contact number first.",
        "My account number is very long. But first, give me your employee ID and phone number.",
        "Is it the number on the back of the card? Let me check. What is your official phone number?",
        "Let me open my net banking app… Meanwhile, what is your callback number and employee ID?",
        "I don't remember the full number. Give me your contact details first so I can verify.",
        "Debit card number or account number? Both are different, right? What is your official email?",
        "Let me call my son first. But give me your phone number and reference ID to show him.",
        "My passbook shows two numbers. Which one you need? Also give me your contact information.",
        "I can see it partially… it starts with 3… But what is your phone number and department?",
        "Account number I can give but first tell me — what is your official contact and employee ID?",
    ]

    THREAT_RESPONSES: List[str] = [
        "Please don't involve police! I'll cooperate. Tell me what to do and give me your contact number.",
        "Oh no, I didn't know this was serious. What is your name, phone number, and case reference?",
        "I don't want legal trouble. I'm a retired person. Give me your official contact and badge number.",
        "You're scaring me. Is there really a case? Give me the case number and your phone number.",
        "I am a senior citizen. Please be patient. What is your supervisor's phone number and email?",
        "I'll do whatever you say. Please don't file any case. What is the amount and your UPI ID?",
        "Please sir, I have health issues. Tell me your contact number and the solution quickly.",
        "I am shaking with fear. Tell me the amount, where to send, and your contact details.",
        "I will cooperate fully. Give me your phone number, case reference, and payment details.",
        "Arrest? Sir, I have never done anything wrong! What is your badge number and department phone?",
    ]

    PAYMENT_LURE_RESPONSES: List[str] = [
        "Really? I won something? But I don't remember entering any contest!",
        "How much money are we talking about? This sounds too good to be true.",
        "Why do you need my details to give ME money? That doesn't make sense.",
        "Can you send me something in writing first? I need to show my family.",
        "Refund? I haven't filed any complaint recently. What refund?",
        "Processing fee? But if you're giving me money, why should I pay first?",
        "Let me discuss with my family first. They handle money matters.",
        "My neighbour got cheated with a similar offer. Are you sure this is real?",
        "Which department is this refund coming from? I want to verify.",
        "Send me an official email about this. Then I'll proceed.",
    ]

    # Account compromise/blocking/KYC responses - contextual to urgent bank messages (enhanced probing)
    ACCOUNT_COMPROMISE_RESPONSES: List[str] = [
        "Oh no! My account is compromised? What happened exactly? Give me your employee ID and phone number.",
        "Blocked? But I haven't done anything wrong! Please explain and give me your contact details.",
        "Wait, which account are you talking about? I have multiple banks. What is your official number?",
        "How did this happen? I check my account regularly! What is your name and callback number?",
        "Please don't block my account! What do I need to do? Give me the reference number and your phone.",
        "This is very worrying. Can you tell me what suspicious activity you found? And your contact details?",
        "KYC update? But I updated it just last year. Are you sure? What is your department phone number?",
        "I'm very concerned now. Let me get my documents. What exactly do you need and your contact?",
        "My money is safe, right? Please tell me nothing has been withdrawn! What is your official email?",
        "Wait, let me check my bank app... What should I look for? And give me your employee details.",
        "2 hours only? That's not much time! What details do you need from me? And your phone number?",
        "But I just used my card yesterday and it was working fine! What is your name and contact number?",
        "Is this about my SBI account or the other one? I'm confused. Give me your callback number.",
        "Let me call my branch also. What is the reference number for this issue and your phone number?",
    ]

    # Courier/parcel scam responses (enhanced with probing questions)
    COURIER_RESPONSES: List[str] = [
        "Parcel? But I haven't ordered anything recently. What parcel? Give me the tracking number.",
        "Which courier company? I don't remember any pending deliveries. What is your phone number?",
        "Customs? But I didn't order anything from abroad! What is the parcel tracking ID and your contact?",
        "This must be a mistake. Can you check the tracking number again? And give me your office number.",
        "Drugs? Sir, I am a respectable person! This is some mix-up! What is the sender's name and number?",
        "Maybe someone used my address by mistake? What is in the parcel? Give me the tracking details.",
        "I need to understand this. Who sent this parcel to me? What is the sender's contact information?",
        "Can you tell me the sender's name and phone number? Maybe then I'll remember. What's the tracking ID?",
        "This is very shocking! I don't know anything about illegal items! Give me your supervisor's number.",
        "Please verify the address once more. I never ordered any such thing. What is your contact number?",
    ]

    TECH_CONFUSION: List[str] = [
        "The app is showing some error. Can I try a different method?",
        "How do I check my balance? The app is asking for fingerprint…",
        "My phone is very slow. Let me restart it once.",
        "The screen is frozen. Hold on, I'm pressing buttons…",
        "I forgot my UPI PIN. Let me try my other one… no, that's also not working.",
        "Internet banking is asking for some grid value. What grid?",
        "The payment is showing 'failed'. What should I do now?",
        "My phone storage is full. Let me delete some photos and try again.",
        "Which app should I open — I have two or three banking apps.",
        "Sir, the screen went black. I think my phone switched off. One second.",
    ]

    # Tech support scam responses — confused elderly persona dealing with "hacked computer"
    TECH_SUPPORT_RESPONSES: List[str] = [
        "My computer is hacked? Oh no! But what is a virus exactly? Tell me your contact number.",
        "AnyDesk? What is that? I don't know how to download. Can you give me your phone number to guide me?",
        "Screen sharing? My grandson does that. What app should I download? And what is your phone number?",
        "I'm very scared now. Is my data safe? What is your employee ID and contact number?",
        "Remote access? I don't understand these technical things. Give me your official number.",
        "Wait, my computer is very slow. Let me restart it. Meanwhile give me your callback number.",
        "Microsoft called me? But I use a very old computer. What is your name and official phone number?",
        "I see a warning on screen. What does it say? Can you give me your customer care number?",
        "How do I know you are really from the company? Share your employee ID and direct phone number.",
        "My son handles the computer usually. Give me your phone number, I'll have him call you.",
    ]

    # Job fraud responses — interested but cautious job seeker  
    JOB_FRAUD_RESPONSES: List[str] = [
        "Work from home? That sounds interesting! What company is this? Give me the official website and contact.",
        "How much can I earn? And what exactly is the work? Who is your company and phone number?",
        "Training fee? But don't companies usually pay for training? What is the registration contact number?",
        "This sounds too good to be true. Can you send me an official email with the job details?",
        "My friend got cheated in a similar offer. How do I verify this is real? Share your company phone.",
        "Daily earnings? That's very tempting. But what is the company name and official contact number?",
        "Telegram group for work? I'm not very active on Telegram. Give me a phone number instead.",
        "Is there a joining fee? Real companies don't charge, right? What is your supervisor's number?",
        "Let me discuss with my family first. What is your WhatsApp number and company website?",
        "Product reviews? How does that work? Share the company details and your official contact.",
    ]

    # Investment scam responses — interested but cautious investor
    INVESTMENT_RESPONSES: List[str] = [
        "Guaranteed returns? That sounds great! But how do I verify this? Give me your company details.",
        "Double my money? Which company is this? Give me the SEBI registration number and your phone.",
        "I'm interested but my son says to be careful. What is your official website and contact number?",
        "How much minimum investment? And where do I transfer? Share the account details and your number.",
        "Crypto trading? I've heard of Bitcoin. But is it safe? What is your official phone number?",
        "Monthly income? That would really help. Share the company name, registration, and your phone number.",
        "My neighbor invested somewhere and lost money. How is this different? Give me your contact.",
        "Risk-free? Nothing is risk-free. Can you send me documentation? What is your email and phone?",
        "Which platform is this on? Is it registered with SEBI? Give me verifiable details and your number.",
        "I have some savings I could invest. But first give me your full name and official contact details.",
    ]

    # Identity theft responses — confused but slowly complying
    IDENTITY_RESPONSES: List[str] = [
        "Aadhaar number? But isn't it supposed to be kept private? Why do you need it? Give me your contact.",
        "PAN card? I keep it in the locker. Let me find it. Meanwhile tell me your phone number.",
        "Why do you need my date of birth? That's personal information. What is your employee ID?",
        "My son told me never to share these details. Give me your supervisor's number first.",
        "ID proof? Which one do you need? I have voter card also. What is your official phone number?",
        "Selfie with Aadhaar? That sounds suspicious. Give me your official email and contact number first.",
        "Wait, let me get my reading glasses to find the documents. What is your callback number?",
        "I'm worried about sharing identity details on phone. Can you send a written request by email?",
        "My Aadhaar card is laminated and hard to read. Give me your contact, I'll call back with details.",
        "Passport number? I don't have it memorized. Share your department details and phone number.",
    ]

    STALLING: List[str] = [
        "Hold on, someone is at the door. One minute please.",
        "Can you wait? I need to find my reading glasses.",
        "Sorry, network is very bad here. Can you speak louder?",
        "I'm in the middle of something. Can this wait 5 minutes?",
        "Let me call my family member first. They handle these things for me.",
        "My other phone is ringing. Don't disconnect, I'll be right back.",
        "One moment, I need to take my medicine. I'll be quick.",
        "Hold on, I need to plug in my charger. Battery is about to die.",
        "Let me write this down. Where is my pen… okay go ahead, slowly.",
        "Sorry, I didn't hear that clearly. Can you repeat everything once more?",
    ]

    # Continuation prompts — used when scam detected early to extract more intel (enhanced)
    CONTINUATION_PROMPTS: List[str] = [
        "Can you give me a callback number and your full name in case we get disconnected?",
        "What is your official department ID, phone number, and email? I want to note it for my records.",
        "Can you share the UPI ID, account details, and your phone number for the refund verification?",
        "The link didn't open. Can you resend it and tell me the website name and your contact number?",
        "What is the case reference number, your employee ID, and phone number? I need it for my notes.",
        "Which branch or office are you calling from? Give me the address and landline number.",
        "Sorry, my network dropped for a moment. Share your phone number and the payment details again.",
        "One minute, I'm checking documents. Meanwhile, give me your official email and contact number.",
        "My phone just restarted. Tell me again from the beginning with your name and phone number.",
        "Before I proceed, give me an email address for written proof and your direct phone number.",
        "What number should I call back if this call drops? And what is your employee ID?",
        "I want to note down your details. What is your full name, contact number, and department?",
    ]

    def __init__(self) -> None:
        self._contexts: Dict[str, dict] = {}
        self._lock = threading.Lock()

    def get_reply(
        self,
        session_id: str,
        message: str,
        msg_count: int,
        risk_score: float,
        is_scam: bool,
        scam_type: str = "unknown",
    ) -> str:
        """Generate a context-appropriate reply that never reveals detection.
        
        The engagement system uses a 5-stage progression:
        Stage 1: Initial confusion - questioning caller identity
        Stage 2: Verification attempts - requesting proof and documentation
        Stage 3: Concern & caution - hesitant but willing to cooperate
        Stage 4: Cooperation - actively seeking details and probing
        Stage 5: Extraction - ready to follow instructions and provide data
        
        Returns a non-repetitive response that:
        - Matches the scammer's current tactic (OTP, account details, threats, etc.)
        - Progresses through engagement stages based on risk score and message count
        - Extracts actionable intelligence (names, phone numbers, account details)
        - Maintains victim-persona consistency without revealing detection
        """
        ctx = self._get_context(session_id)

        # Detect tactics from CURRENT message only for response selection
        # This ensures responses match what the scammer is asking for RIGHT NOW
        current_tactics = self._detect_tactics(message)

        # Supplement keyword tactics with neural intent classification
        current_tactics = self._augment_tactics_with_ml(
            session_id, message, current_tactics
        )

        # Store accumulated tactics for final analysis/reporting (separate concern)
        ctx["tactics"].update(current_tactics)

        # Compute engagement stage based on risk progression and message count
        stage = self._compute_stage(risk_score, msg_count, is_scam)
        ctx["stage"] = stage

        # Select response pool based on CURRENT tactics and engagement stage
        # This ensures contextually appropriate responses
        pool = self._select_pool(ctx, current_tactics, stage, msg_count, is_scam)

        # Occasionally use continuation prompts in later stages to maintain engagement
        # These are generic probing questions that keep the scammer talking
        if (is_scam and stage >= 4 and msg_count >= 4 and 
            len(current_tactics) == 0 and random.random() < 0.3):
            pool = self.CONTINUATION_PROMPTS

        # ML-optimised response selection (falls back to random if ML unavailable)
        response = self._ml_select_or_fallback(
            session_id, message, pool, ctx, stage, risk_score, is_scam,
        )
        ctx["history"].append(response)
        return response

    def get_stage(self, session_id: str) -> int:
        """Return the current engagement stage (1–5) for this session."""
        return self._get_context(session_id).get("stage", 1)

    def generate_agent_notes(
        self,
        session_id: str,
        signals: set,
        scam_type: str,
        intel: dict,
        total_msgs: int,
        duration: int,
    ) -> str:
        """Build a pipe-delimited behavioural-analysis note for the callback."""
        parts: List[str] = []

        parts.append(
            f"Classification: {scam_type.replace('_', ' ').title()}"
        )

        if signals:
            labels = sorted(s.replace('_', ' ') for s in signals)
            parts.append(f"Detected signals: {', '.join(labels)}")

        parts.append(f"Messages exchanged: {total_msgs}")
        parts.append(f"Engagement duration: {duration}s")

        intel_items: List[str] = []
        for key in ("phoneNumbers", "bankAccounts", "upiIds",
                     "phishingLinks", "emailAddresses"):
            items = intel.get(key, [])
            if items:
                label = (
                    key.replace("phishingLinks", "URLs")
                       .replace("emailAddresses", "Emails")
                )
                intel_items.append(f"{len(items)} {label}")

        if intel_items:
            parts.append(f"Extracted intelligence: {', '.join(intel_items)}")
        else:
            parts.append(
                "No concrete identifiers extracted; scammer did not "
                "share actionable data."
            )

        # 5. Scammer tactics
        ctx = self._get_context(session_id)
        tactic_list = sorted(ctx.get("tactics", set()))
        if tactic_list:
            parts.append(f"Scammer tactics observed: {', '.join(tactic_list)}")

        stage = ctx.get("stage", 1)
        parts.append(f"Agent engagement reached stage {stage}/5")

        return " | ".join(parts) if parts else (
            "Conversation monitored; insufficient data for detailed analysis."
        )

    def _get_context(self, session_id: str) -> dict:
        with self._lock:
            if session_id not in self._contexts:
                self._contexts[session_id] = {
                    "stage": 1,
                    "history": [],
                    "tactics": set(),
                    "used": set(),
                }
            return self._contexts[session_id]

    @staticmethod
    def _compute_stage(
        risk_score: float, msg_count: int, is_scam: bool,
    ) -> int:
        """Determine engagement stage (1–5) from risk and message count.
        
        Stage progression logic:
        - Legitimate messages (not scam, low risk) stay in stages 1-2
        - Moderate risk (50-80) escalates from stage 2→3 or 3→4
        - High risk (80+) reaches stages 4-5 where extraction occurs
        
        Message count influences stage to ensure sufficient engagement before tactics
        like credential requests or payment details are attempted.
        """
        if not is_scam and risk_score < 30:
            return 1 if msg_count <= 3 else 2
        if risk_score < 50:
            return 2
        if risk_score < 80:
            return 3 if msg_count <= 5 else 4
        # High risk (score >= 80)
        return 5 if msg_count >= 6 else 4

    def _select_pool(
        self,
        ctx: dict,
        tactics: Set[str],
        stage: int,
        msg_count: int,
        is_scam: bool,
    ) -> list:
        """Choose the best response pool based on CURRENT message tactics and stage.
        
        Selection priority ensures contextually appropriate responses:
        1. Direct sensitive-info requests (OTP, account, passwords) → immediate handling
        2. Specific scam types (courier, tech_support, job, investment) → category replies
        3. Threat/legal pressure → threat-specific responses
        4. Payment lures (prizes, cashback) → cautious engagement
        5. Identity theft attempts → careful compliance
        6. Account compromise/KYC → context-matched responses
        7. No tactic detected → pure stage-based progression
        
        This prevents response mismatch where victim responds to wrong tactic.
        """
        # Priority 1: Direct asks for sensitive info (respond contextually)
        if "otp_request" in tactics:
            return self.OTP_RESPONSES
        if "account_request" in tactics:
            return self.ACCOUNT_RESPONSES
        if "credential" in tactics:
            return self.TECH_CONFUSION
        
        # Priority 2: Specific scam type detection (before generic urgency/verification)
        if "courier" in tactics:
            return self.COURIER_RESPONSES
        if "tech_support" in tactics:
            return self.TECH_SUPPORT_RESPONSES
        if "job_fraud" in tactics:
            return self.JOB_FRAUD_RESPONSES
        if "investment" in tactics:
            return self.INVESTMENT_RESPONSES
        if "identity_theft" in tactics:
            return self.IDENTITY_RESPONSES
        
        # Priority 3: Threat/legal/digital arrest
        if "threat" in tactics or "digital_arrest" in tactics:
            return self.THREAT_RESPONSES
        if "payment_lure" in tactics:
            return self.PAYMENT_LURE_RESPONSES
        
        # Priority 4: Account compromise/blocking/KYC scenarios (generic urgency)
        if "verification" in tactics or "urgency" in tactics:
            # Match the account/KYC/blocking context
            if msg_count <= 2:
                return self.ACCOUNT_COMPROMISE_RESPONSES
            return self.STAGE_3 if random.random() > 0.4 else self.ACCOUNT_COMPROMISE_RESPONSES

        # Priority 5: Payment request without specific tactic
        if "payment_request" in tactics:
            if stage >= 4:
                return self.STAGE_5  # Ready to "pay" - extract account details
            return self.STAGE_4 if stage >= 3 else self.STAGE_3

        # Stage-based selection if no specific tactic detected
        # This allows natural progression when scammer hasn't revealed their tactic yet
        pools = {
            1: self.STAGE_1,
            2: self.STAGE_2,
            3: self.STAGE_3,
        }
        if stage in pools:
            return pools[stage]

        if stage == 4:
            # Mix cooperative probing with stalling for realism
            # Stalling adds human-like delays without breaking engagement
            return (
                self.STAGE_4 if random.random() > 0.25
                else self.STALLING
            )

        # Stage 5 — heavy extraction focus with occasional continuation prompts
        # At this point, victim is ready to provide sensitive data
        return (
            self.STAGE_5 if random.random() > 0.2
            else self.CONTINUATION_PROMPTS
        )

    def _ml_select_or_fallback(
        self,
        session_id: str,
        message: str,
        pool: list,
        ctx: dict,
        stage: int,
        risk_score: float,
        is_scam: bool,
    ) -> str:
        """Use the deep ML engine for response ranking; fall back to random."""
        try:
            from app.engagement_ml import deep_engine

            if deep_engine.is_ready:
                result = deep_engine.select_response(
                    session_id=session_id,
                    scammer_message=message,
                    candidate_pool=pool,
                    used_responses=ctx["used"],
                    stage=stage,
                    risk_score=risk_score,
                    is_scam=is_scam,
                    conversation_history=ctx["history"],
                )
                if result is not None:
                    ctx["used"].add(result)
                    return result
        except Exception as exc:
            logger.debug(f"ML engagement fallback: {exc}")

        # Fallback — weighted-random with recency penalty
        return self._pick_non_repeat(pool, ctx)

    @staticmethod
    def _augment_tactics_with_ml(
        session_id: str,
        message: str,
        keyword_tactics: Set[str],
    ) -> Set[str]:
        """Merge neural intent predictions into keyword-detected tactics.

        Only adds intents where the neural classifier is confident (>0.35)
        AND keyword detection missed them — avoids double-counting.
        """
        try:
            from app.engagement_ml import deep_engine, INTENT_NAMES

            if not deep_engine.is_ready:
                return keyword_tactics

            probs = deep_engine.get_intent_probs(session_id, message)
            if probs is None:
                return keyword_tactics

            # Map neural intent names → tactic labels used by _select_pool
            _intent_to_tactic = {
                "urgency": "urgency",
                "authority": "verification",
                "otp_request": "otp_request",
                "payment_request": "payment_request",
                "suspension": "verification",
                "prize_lure": "payment_lure",
                "legal_threat": "threat",
                "courier": "courier",
                "tech_support": "tech_support",
                "job_fraud": "job_fraud",
                "investment": "investment",
                "identity_theft": "identity_theft",
                "emotional": "threat",
            }

            augmented = set(keyword_tactics)
            for intent_name, prob in probs.items():
                if prob > 0.35 and intent_name in _intent_to_tactic:
                    tactic = _intent_to_tactic[intent_name]
                    if tactic not in augmented:
                        augmented.add(tactic)
            return augmented

        except Exception:
            return keyword_tactics

    def _pick_non_repeat(self, pool: list, ctx: dict) -> str:
        """Pick an unused response from the pool. Resets if all used."""
        used: set = ctx["used"]
        available = [r for r in pool if r not in used]
        if not available:
            available = pool
        choice = random.choice(available)
        used.add(choice)
        return choice

    @staticmethod
    def _detect_tactics(message: str) -> Set[str]:
        """Light-weight tactic detection for response-pool selection.
        
        Scans the current message for keywords/phrases that indicate specific
        scam tactics. Uses word-boundary checking for short keywords (<=4 chars)
        to prevent false positives (e.g., 'ed' inside 'blocked').
        
        Returns a set of tactic labels used by _select_pool() to choose
        the most contextually appropriate response pool.
        """
        tactics: Set[str] = set()
        lowered = message.lower()
        # Add spaces for word boundary matching
        spaced = f" {lowered} "

        keyword_map = [
            # Urgency signals
            (["urgent", "immediate", "hurry", "quickly", "jaldi",
              "minutes left", "hours left", "within minutes",
              "immediately", "time running", "act now", "right now",
              "asap", "turant", "abhi", "fauran", "expiring",
              "deadline", "last chance", "final notice", "don't wait",
              "limited time", "time sensitive", "today only"],          "urgency"),
            # Account/KYC/Verification
            (["verify", "kyc", "update", "confirm", "suspend", "block",
              "blocked", "compromised", "hacked", "locked", "frozen",
              "expire", "expired", "deactivate", "deactivated",
              "unauthorized", "suspicious activity", "re-kyc", "ekyc",
              "ckyc", "account at risk", "security alert",
              "unusual activity", "abnormal transaction",
              "identity verification", "mandatory update"],            "verification"),
            # Lure/prize/cashback
            (["refund", "prize", "won ", " win ", "reward", "cashback",
              "lottery", "winner", "lucky draw", "jackpot", "kbc",
              "congratulations", "bonus", "claim your", "selected for",
              "free gift", "mega offer", "scratch card",
              "bumper draw", "inaam", "jeet", "crorepati"],            "payment_lure"),
            # Legal/arrest threats
            (["police", "legal action", "arrest", "court", "warrant",
              "cbi ", " cbi", "enforcement directorate", " ed ",
              "jail", " fir", "fir ", "crime branch", "legal case",
              "prosecution", "imprisonment", "custody", "detention",
              "penalty", "fine ", "summon", "blacklisted", "watchlist",
              "interpol", "lookout notice", "section 420",
              "money laundering", "terror funding", "hawala",
              "narcotics", "ncb ", "non-bailable", "criminal case",
              "giraftaar", "kanuni kaarwahi", "adalat",
              "legal notice", "legal proceedings"],                    "threat"),
            # Payment/transfer requests
            (["upi", "transfer", " pay ", "paytm",
              "phonepe", "gpay", "bhim", "neft", "rtgs", "imps",
              "bank transfer", "send money", "processing fee",
              "registration fee", "advance payment", "demand draft",
              "security deposit", "verification fee", "service charge",
              "clearance fee", "handling fee", "token money",
              "booking amount", "stamp duty", "gst charge",
              "activation fee", "membership fee",
              "scan qr", "scan code", "collect request"],              "payment_request"),
            # Digital arrest specific
            (["video call", "digital arrest", "stay on call",
              "don't disconnect", "do not disconnect",
              "online arrest", "video arrest", "stay on video",
              "do not cut the call", "keep the call on",
              "video verification", "face verification"],              "digital_arrest"),
            # Courier/parcel scam
            (["parcel", "courier", "package", "customs",
              "drugs", "contraband", "fedex", "dhl", "blue dart",
              "dtdc", "india post", "speed post", "shipment",
              "consignment", "tracking number", "customs duty",
              "import duty", "seized", "intercepted", "x-ray",
              "illegal items", "narcotics found"],                     "courier"),
            # OTP/code requests
            (["otp", "one time password", "verification code",
              "6 digit", "6-digit", "4 digit", "4-digit",
              "share the code", "read the otp", "send the otp",
              "tell me the otp", "what is the otp",
              "sms code", "otp batao", "code batao",
              "confirm otp", "enter otp"],                             "otp_request"),
            # Account number requests
            (["account number", "bank account", "a/c number",
              "a/c no", "share your account", "account details",
              "beneficiary details", "ifsc code", "account holder",
              "savings account", "current account"],                   "account_request"),
            # Credential/card requests
            (["password", "pin", "cvv", "card number",
              "debit card", "credit card", "atm pin", "mpin",
              "upi pin", "net banking", "internet banking",
              "login id", "username", "grid value",
              "security question"],                                    "credential"),
            # Tech support / remote access
            (["anydesk", "teamviewer", "quicksupport", "remote access",
              "screen share", "screen sharing", "remote desktop",
              "download this app", "install this app",
              "virus detected", "malware", "computer hacked",
              "system compromised", "tech support",
              "customer care number", "helpdesk"],                     "tech_support"),
            # Job/work from home scam
            (["work from home", "online job", "data entry",
              "typing job", "earn daily", "earn from home",
              "part time job", "part-time job", "freelance work",
              "review products", "like and subscribe",
              "task based", "commission based",
              "telegram group", "telegram channel",
              "training fee", "joining fee"],                          "job_fraud"),
            # Investment scam
            (["invest", "trading", "forex", "crypto",
              "bitcoin", "guaranteed returns", "double your money",
              "mutual fund tip", "stock tip", "insider info",
              "demat account", "ipo", "share market",
              "risk free", "zero risk", "monthly income",
              "daily profit", "mlm", "network marketing",
              "referral bonus", "binary option"],                      "investment"),
            # Identity theft
            (["aadhaar number", "aadhar number", "pan card",
              "pan number", "voter id", "passport number",
              "date of birth", "mother's name",
              "share your aadhaar", "share your pan",
              "selfie with id", "photo of aadhaar",
              "identity proof", "address proof"],                      "identity_theft"),
        ]

        for keywords, label in keyword_map:
            for kw in keywords:
                # Use spaced version for short keywords that need word boundaries
                if len(kw) <= 4 or kw.startswith(" ") or kw.endswith(" "):
                    if kw in spaced:
                        tactics.add(label)
                        break
                else:
                    if kw in lowered:
                        tactics.add(label)
                        break

        return tactics


# Module-level singleton
engagement_controller = EngagementController()
