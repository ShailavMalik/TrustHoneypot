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

    # Stage 2 — Verifying authenticity
    STAGE_2: List[str] = [
        "How do I know this is legitimate? Can you provide some proof?",
        "I need to verify this. What is your official employee ID?",
        "Can you give me a reference number? I want to check with the main office.",
        "This doesn't sound right. My bank never calls me like this.",
        "Can you send me an official letter or email first?",
        "Before I do anything, I need something in writing.",
        "My son warned me about calls like these. Give me your supervisor's number.",
        "What is your official designation? I want to note it down.",
        "Can you send this on official letterhead? I need proper documentation.",
        "Let me verify — what is your organisation's toll-free number?",
        "I'm sorry, but I cannot take action without seeing official documentation.",
        "Is there a website where I can check this myself?",
        "Which department exactly are you calling from? I will cross-check.",
        "Can you spell your full name for me? I want to verify with your office.",
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

    # Stage 4 — Cooperative but probing
    STAGE_4: List[str] = [
        "Okay, I believe you. But can you give me your direct callback number?",
        "Fine, I'll cooperate. What department ID should I reference?",
        "Alright sir, tell me what to do. But first, what is the case reference number?",
        "I'm ready to help. Can you give me the official branch or office name?",
        "Okay okay, I'll do it. Just tell me which number should I call back to verify?",
        "I trust you now. But for my records, what is your badge or ID number?",
        "Sir, I want to cooperate fully. Can you resend that link once more?",
        "I understand the urgency. Please share the details again, my network dropped.",
        "Fine, I'll proceed. But can you email me the instructions also?",
        "Alright, let me note everything down. What is the reference number again?",
        "Okay, I'm convinced. Just tell me — is there a complaint number I should save?",
        "I'll do whatever is needed. Which email can I write to for confirmation?",
        "I believe you are genuine. Can you share an official contact for future reference?",
        "My son said I should always get a receipt number. Can you give me one?",
    ]

    # Stage 5 — Extraction-focused questioning
    STAGE_5: List[str] = [
        "Okay, I'm ready. What is the UPI ID I should send to?",
        "Tell me the account number slowly. I am writing it down.",
        "Which bank account should I transfer to? Give me the full details.",
        "What is the exact amount and where to send? Spell the UPI ID for me.",
        "I have my banking app open. Give me the account number and name.",
        "Should I send by UPI or bank transfer? Tell me the details for both.",
        "I'm ready to pay. Just tell me the reference number and amount clearly.",
        "What name will show when I transfer? I want to confirm it's correct.",
        "UPI is showing an error. Can you give me the bank account number instead?",
        "My app is asking for beneficiary name and account number. Please tell me.",
        "Give me the full details — account number, name, and branch.",
        "I'll send right now. Repeat the UPI ID letter by letter please.",
        "Okay, should I do it from my savings account? Tell me where to send.",
        "Let me try sending a small amount first. What's the UPI ID again?",
    ]

    # Intent-specific response pools (override stage when scammer uses specific tactics)

    OTP_RESPONSES: List[str] = [
        "OTP? Wait, let me check my messages… which number does it come from?",
        "My OTP is not coming. Network is weak here. Can you wait a few minutes?",
        "I got several messages. Which OTP do you need? There are 3-4 here.",
        "The OTP says 'do not share with anyone'. Should I still give it?",
        "It says the OTP expired already. Can you send a new one?",
        "I pressed the wrong button and the message got deleted. Please resend.",
        "OTP is showing but the screen is dim. Let me increase brightness…",
        "My eyes are weak, I cannot read small text. It's showing 4… 7… wait…",
        "OTP has come but phone is asking for fingerprint. One second…",
        "My son changed my SIM last week. OTP might be going to old number.",
    ]

    ACCOUNT_RESPONSES: List[str] = [
        "Account number? Which one — savings or fixed deposit? Let me find the passbook.",
        "My account number is very long. Let me read slowly… where did I keep that paper?",
        "Is it the number on the back of the card? It's scratched, I can't read it.",
        "Let me open my net banking app… it's asking for password… one moment.",
        "I don't remember the full number. It's in the passbook upstairs. Give me 5 minutes.",
        "Debit card number or account number? Both are different, right?",
        "Let me call my son first. He has all the details noted in his phone.",
        "My passbook shows two numbers — account number and something called CIF. Which one?",
        "I can see it partially… it starts with 3… wait, let me get my glasses.",
        "Account number I can give but the book is locked in the almirah. Just a minute.",
    ]

    THREAT_RESPONSES: List[str] = [
        "Please don't involve police! I'll cooperate fully. Just tell me what to do.",
        "Oh no, I didn't know this was serious. Please help me fix it!",
        "I don't want legal trouble. I'm a retired person. Please guide me.",
        "You're scaring me. Is there really a case against me?",
        "I am a senior citizen. Please have patience with me.",
        "I'll do whatever you say. Please don't file any case.",
        "Please sir, I have health issues. Just tell me the solution.",
        "I am shaking with fear. Please tell me the amount and where to send.",
        "I will cooperate fully. My family doesn't know about this. Please help.",
        "Arrest? Sir, I have never done anything wrong in my life!",
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

    # Continuation prompts — used when scam detected early to extract more intel
    CONTINUATION_PROMPTS: List[str] = [
        "Can you give me a callback number in case we get disconnected?",
        "What is your official department ID? I want to note it for my records.",
        "Can you share the UPI ID for the refund verification?",
        "The link didn't open. Can you resend it please?",
        "What is the case reference number? I need it for my notes.",
        "Which branch or office are you calling from?",
        "Sorry, my network dropped for a moment. Can you repeat that?",
        "One minute, I'm checking my documents. Please wait.",
        "My phone just restarted. Can you tell me again from the beginning?",
        "Before I proceed, can you give me an email address for written proof?",
        "What number should I call back if this call drops?",
        "I want to note down your details. What is your full name and designation?",
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

        tactics = self._detect_tactics(message)
        ctx["tactics"].update(tactics)

        stage = self._compute_stage(risk_score, msg_count, is_scam)
        ctx["stage"] = stage

        pool = self._select_pool(ctx, tactics, stage, msg_count, is_scam)

        # Mix in continuation prompts ~40% to proactively extract intel
        if is_scam and msg_count < 10 and stage >= 3:
            if msg_count < 8 and random.random() < 0.4:
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
        """Choose the best response pool based on tactics and stage."""
        # Intent overrides
        if "otp_request" in tactics and msg_count > 1:
            return self.OTP_RESPONSES
        if "account_request" in tactics and msg_count > 1:
            return self.ACCOUNT_RESPONSES
        if "threat" in tactics or "digital_arrest" in tactics:
            return self.THREAT_RESPONSES
        if "credential" in tactics:
            return self.TECH_CONFUSION
        if "payment_lure" in tactics and stage < 4:
            return self.PAYMENT_LURE_RESPONSES

        # Stage-based selection
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

        keyword_map = [
            (["urgent", "immediate", "hurry", "quickly", "jaldi",
              "minutes left"],                                          "urgency"),
            (["verify", "kyc", "update", "confirm", "suspend", "block"], "verification"),
            (["refund", "prize", "won", "reward", "cashback",
              "lottery", "winner"],                                     "payment_lure"),
            (["police", "legal", "arrest", "court", "case",
              "warrant", "cbi", "ed", "jail"],                          "threat"),
            (["upi", "transfer", "pay", "send", "paytm",
              "phonepe", "gpay", "bhim"],                               "payment_request"),
            (["video call", "digital arrest", "stay on call",
              "don't disconnect"],                                      "digital_arrest"),
            (["parcel", "courier", "package", "customs",
              "drugs", "contraband"],                                   "courier"),
            (["otp", "one time password", "verification code",
              "6 digit"],                                               "otp_request"),
            (["account number", "bank account", "a/c number",
              "a/c no"],                                                "account_request"),
            (["password", "pin", "cvv", "card number",
              "debit card", "credit card"],                             "credential"),
        ]

        for keywords, label in keyword_map:
            if any(kw in lowered for kw in keywords):
                tactics.add(label)

        return tactics


# Module-level singleton
engagement_controller = EngagementController()
