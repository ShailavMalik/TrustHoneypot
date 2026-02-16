"""5-stage adaptive engagement engine. Generates human-like victim-persona
responses to keep scammers talking and extract intelligence."""

import random
import threading
from typing import Dict, List, Set


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
        """Generate a context-appropriate reply that never reveals detection."""
        ctx = self._get_context(session_id)

        # Detect tactics from CURRENT message only for response selection
        current_tactics = self._detect_tactics(message)
        # Store accumulated tactics for analysis/reporting (separate from response selection)
        ctx["tactics"].update(current_tactics)

        stage = self._compute_stage(risk_score, msg_count, is_scam)
        ctx["stage"] = stage

        # Use CURRENT message tactics for pool selection, not accumulated
        pool = self._select_pool(ctx, current_tactics, stage, msg_count, is_scam)

        # Only mix in continuation prompts when:
        # 1. It's a confirmed scam
        # 2. We're in later stages (4+) with enough engagement (msg_count >= 4)
        # 3. No strong tactic was detected (empty tactics = generic stage-based response)
        # 4. Random 30% chance to keep it natural
        if (is_scam and stage >= 4 and msg_count >= 4 and 
            len(current_tactics) == 0 and random.random() < 0.3):
            pool = self.CONTINUATION_PROMPTS

        response = self._pick_non_repeat(pool, ctx)
        ctx["history"].append(response)
        return response

    def get_stage(self, session_id: str) -> int:
        """Return the current engagement stage (1–5)."""
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
        """Determine engagement stage (1–5) from risk and message count."""
        if not is_scam and risk_score < 30:
            return 1 if msg_count <= 3 else 2
        if risk_score < 50:
            return 2
        if risk_score < 80:
            return 3 if msg_count <= 5 else 4
        # High risk
        return 5 if msg_count >= 6 else 4

    def _select_pool(
        self,
        ctx: dict,
        tactics: Set[str],
        stage: int,
        msg_count: int,
        is_scam: bool,
    ) -> list:
        """Choose the best response pool based on CURRENT message tactics and stage."""
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
        if "threat" in tactics or "digital_arrest" in tactics:
            return self.THREAT_RESPONSES
        if "payment_lure" in tactics:
            return self.PAYMENT_LURE_RESPONSES
        
        # Priority 3: Account compromise/blocking/KYC scenarios (generic urgency)
        if "verification" in tactics or "urgency" in tactics:
            # Match the account/KYC/blocking context
            if msg_count <= 2:
                return self.ACCOUNT_COMPROMISE_RESPONSES
            return self.STAGE_3 if random.random() > 0.4 else self.ACCOUNT_COMPROMISE_RESPONSES

        # Stage-based selection if no specific tactic detected
        pools = {
            1: self.STAGE_1,
            2: self.STAGE_2,
            3: self.STAGE_3,
        }
        if stage in pools:
            return pools[stage]

        if stage == 4:
            # Mix cooperative probing with stalling for realism
            return (
                self.STAGE_4 if random.random() > 0.25
                else self.STALLING
            )

        # Stage 5 — heavy extraction, occasional continuation prompts
        return (
            self.STAGE_5 if random.random() > 0.2
            else self.CONTINUATION_PROMPTS
        )

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
        """Light-weight tactic detection for response-pool selection."""
        tactics: Set[str] = set()
        lowered = message.lower()
        # Add spaces for word boundary matching
        spaced = f" {lowered} "

        keyword_map = [
            (["urgent", "immediate", "hurry", "quickly", "jaldi",
              "minutes left", "hours left", "within minutes",
              "immediately"],                                           "urgency"),
            (["verify", "kyc", "update", "confirm", "suspend", "block",
              "blocked", "compromised", "hacked", "locked", "frozen",
              "expire", "expired", "deactivate"],                       "verification"),
            (["refund", "prize", "won ", " win ", "reward", "cashback",
              "lottery", "winner"],                                     "payment_lure"),
            (["police", "legal action", "arrest", "court", "warrant",
              "cbi ", " cbi", "enforcement directorate", " ed ",
              "jail", " fir", "fir ", "crime branch", "legal case"],    "threat"),
            (["upi", "transfer", " pay ", "paytm",
              "phonepe", "gpay", "bhim"],                               "payment_request"),
            (["video call", "digital arrest", "stay on call",
              "don't disconnect", "do not disconnect"],                 "digital_arrest"),
            (["parcel", "courier", "package", "customs",
              "drugs", "contraband", "fedex", "dhl"],                   "courier"),
            (["otp", "one time password", "verification code",
              "6 digit", "6-digit"],                                    "otp_request"),
            (["account number", "bank account", "a/c number",
              "a/c no", "share your account"],                          "account_request"),
            (["password", "pin", "cvv", "card number",
              "debit card", "credit card"],                             "credential"),
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
