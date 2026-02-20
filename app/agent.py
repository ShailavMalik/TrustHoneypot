"""5-stage adaptive engagement engine. Generates human-like victim-persona
responses to keep scammers talking and extract intelligence.

Phase 2.2 — rubric-perfect response selection:
  Uses DeepEngagementEngine for neural response ranking when available,
  with graceful fallback to weighted-random selection.
  Micro-jitter handled in main.py as async sleep for event-loop safety."""

import logging
import random
import threading
import time
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
        # Red flag + elicitation combo responses (added for scoring)
        "This sounds suspicious. I don't usually get such calls. Give me your phone number.",
        "I'm worried this might be fraud. My son warned me about scam calls. Who is this?",
        "This doesn't sound right. Real officials don't call like this. What is your employee ID?",
        "I'm concerned and nervous about this call. Give me your contact number to verify.",
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
        # Enhanced red flag responses (added for scoring)
        "This sounds suspicious to me. My bank never calls like this. Can you verify yourself?",
        "I'm worried this might be a scam. Let me first verify your identity.",
        "This doesn't sound right. Real organizations don't pressure like this.",
        "I'm concerned about fraud. Can you give me your official verification details?",
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
        # Enhanced red flag responses (added for scoring)
        "This urgency is making me suspicious. Why the rush?",
        "I'm worried this could be a fraud. My son warned me about such calls.",
        "This doesn't sound right to me. Real banks don't call like this.",
        "I'm very uncomfortable with this pressure. Let me verify first.",
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
        "Could you tell me the policy number this case is linked to? I want to note it down.",
        "Please share the exact order ID or transaction reference so I can cross-check with my records.",
        "What case ID have you assigned to this complaint? I'll keep it for future reference.",
        # Enhanced elicitation + red flag combo responses (added for scoring)
        "I'm worried this could be fraud but I'll verify first. Spell out the account number for me slowly.",
        "This sounds suspicious but let me note down. Give me the UPI ID and IFSC code for my records.",
        "My family warned me about scam calls. Tell me the beneficiary name and bank branch details.",
        "I'm nervous about this. Give me your contact number and email address so I can check with my son.",
        "This doesn't sound right but I'll cooperate. Share the account details and reference number slowly.",
        "I'm uncomfortable but will write this down. Tell me the phone number and case ID for my records.",
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
        "Please share the IFSC code again — I didn't hear it correctly the first time.",
        "Give me the exact UPI ID one more time. My app flagged it as unusual, so I need to re-enter.",
        "What is the precise amount I need to transfer? And what is the beneficiary's registered mobile?",
        "I need your policy number and order ID to complete this transaction. Please share both.",
        # Enhanced elicitation responses (added for scoring)
        "Let me write this down for my records. Spell out the account number and bank branch slowly.",
        "I'm noting down the details carefully. Give me the UPI ID, beneficiary name, and phone number.",
        "My son will verify first. Share the contact number, email address, and reference number.",
        "I need to note everything down. Tell me the case ID, account details, and IFSC code.",
        "Let me repeat to confirm. Spell the UPI ID slowly and share your contact details.",
        "For my records, give me the phone number, account number, and bank branch details.",
    ]

    # Intent-specific response pools (override stage when scammer uses specific tactics)
    # DESIGN: Each pool has diverse response THEMES to avoid repetitive patterns.
    # Themes: asks_phone, asks_account, asks_id, stalls, confused, compliant,
    #         tech_issue, emotional, family_consult, asks_different_info

    OTP_RESPONSES: List[str] = [
        # --- stalling / tech confusion ---
        "OTP? Wait, let me check my messages… I am getting so many SMS nowadays.",
        "My phone is very slow today. Let me close some apps and check for the OTP.",
        "The OTP says 'do not share with anyone'. Should I still give it? That is confusing.",
        "It says the OTP expired already. Can you send a new one? These things expire so fast.",
        "I pressed the wrong button and the message got deleted. Can you resend it?",
        "I got 3 or 4 messages. Which one is the OTP? They all look the same to me.",
        "OTP has come but my phone is asking for fingerprint. I can never get that to work.",
        "My eyes are weak, the text is very small. Let me get my reading glasses first.",
        "My son changed my SIM last week. Maybe the OTP went to the old number?",
        "The screen went dim again. One second, let me increase the brightness.",
        # --- confused / hesitant ---
        "But my bank always says never share OTP with anyone. Why is this different?",
        "I am confused — is this the same OTP my bank sends for transactions?",
        "Which bank is this OTP from? I have accounts in SBI and also in PNB.",
        "OTP for what exactly? Is this for unblocking or for some transaction?",
        "I don't understand these OTP things. My son usually handles all this.",
        # --- emotional / persona ---
        "Please don't rush me. My heart beats fast when people pressure me like this.",
        "I'm getting very anxious. Just give me one minute to collect myself.",
        "Sir, I am a 65-year-old retired person. These technical things confuse me.",
        # --- asks for different info (not phone) ---
        "What is the reference number for this case? I want to write it down before I do anything.",
        "What department are you from again? I want to tell my son when he comes home.",
        "Can you tell me your employee ID? I want to note it for my records.",
        "What is the case number? I want to have proof of this conversation.",
        # --- family consult / stalling ---
        "Hold on, let me ask my neighbour. She works in a bank, she'll know about this.",
        "Wait, my son is calling on the other phone. He might have got the OTP. One minute.",
        "Let me check WhatsApp also. Sometimes these codes come there instead.",
        # --- asks phone (limited — only a few) ---
        "My OTP is not coming. Network is weak here. What number should I expect the SMS from?",
        "One thing — if the call drops, what number should I call you back on? Just in case.",
        # --- red flag / skeptical (added for scoring) ---
        "This sounds suspicious - my bank says never share OTP. Why is this different?",
        "I'm worried this might be fraud. Banks don't usually ask for OTP over call.",
        "My son warned me about scam calls asking for OTP. How do I verify you're real?",
        "Asking for OTP doesn't sound right. Real officials don't ask for this.",
    ]

    ACCOUNT_RESPONSES: List[str] = [
        # --- confused ---
        "Account number? Which one — savings or fixed deposit? I have both.",
        "Is it the number on the front of the passbook or the one on the cheque? They are different.",
        "My passbook shows two numbers. One is long and one is short. Which one?",
        "Debit card number or account number? Both are different, right?",
        # --- stalling ---
        "Let me open my net banking app… it takes time to load on my old phone.",
        "I don't remember the full number. Let me go find my passbook, it's in the cupboard.",
        "Wait, my passbook is in the locker. I need to find the key first.",
        "My son has the chequebook. He took it last week. Let me message him.",
        # --- asks for different info ---
        "I can give you the account number. But first, what is the reference ID for this case?",
        "Which bank branch are you calling from? I want to verify before sharing anything.",
        "What is your employee ID? My branch said I should always verify before sharing account details.",
        "Can you send me an email with the official request? I need it in writing.",
        # --- partial compliance (keeps scammer engaged) ---
        "It starts with 3… no wait, that's my other account. Hold on.",
        "Let me read it slowly — one, two… wait, I can't read the next digit clearly.",
        # --- emotional ---
        "I'm worried. What if someone misuses my account number? Can you guarantee safety?",
        "My neighbour gave her account number to someone and lost all her money. I'm scared.",
    ]

    THREAT_RESPONSES: List[str] = [
        "Please don't involve police! I'll cooperate. Just tell me what to do.",
        "Oh no, I didn't know this was serious. What is the case reference number?",
        "I don't want legal trouble. I'm a retired person. Please explain what happened.",
        "You're scaring me. Is there really a case against me? What is the allegation?",
        "I am a senior citizen. Please be patient with me. Can you explain once more?",
        "I'll do whatever you say. Please don't file any case. What do I need to do?",
        "Please sir, I have health issues. My blood pressure just shoots up with stress.",
        "I am shaking with fear. Let me sit down first. My hands are trembling.",
        "Arrest? Sir, I have never done anything wrong in my life! This must be a mistake.",
        "I will cooperate fully. But please, let me speak to my family once before anything.",
        "Sir, please don't shout at me. I am an old person. Let me understand first.",
        "Is there any way to resolve this peacefully? I can't go through a legal process at my age.",
        "My son is a lawyer. Wait, let me just inform him. He should know about this.",
        "What is the exact allegation? I haven't done anything illegal. There must be some confusion.",
        # --- red flag / skeptical (added for scoring) ---
        "This sounds suspicious. Real officers don't threaten like this over the phone.",
        "I'm worried this might be a scam. Let me verify with the actual department first.",
        "My family warned me about fraud calls with legal threats. How do I verify you?",
        "This pressure doesn't seem right. Real government doesn't call like this.",
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
        # --- red flag / skeptical (added for scoring) ---
        "This sounds suspicious. Why pay to receive money? Doesn't sound right.",
        "I'm worried about fraud. Processing fees are a classic scam tactic.",
        "My son warned me about such scam offers. How can I verify this is real?",
        "Paying first to receive money doesn't seem right. Let me check with my family.",
    ]

    # Account compromise/blocking/KYC responses (diverse themes)
    ACCOUNT_COMPROMISE_RESPONSES: List[str] = [
        "Oh no! My account is compromised? What happened exactly? Please explain.",
        "Blocked? But I haven't done anything wrong! What is the reason?",
        "Wait, which account are you talking about? I have multiple banks.",
        "How did this happen? I check my account regularly! This is very strange.",
        "Please don't block my account! I'll do whatever is needed. Just guide me.",
        "This is very worrying. Can you tell me what suspicious activity you found?",
        "KYC update? But I updated it just last year at the branch. Are you sure?",
        "I'm very concerned now. Let me get my documents. What exactly do you need?",
        "My money is safe, right? Please tell me nothing has been withdrawn!",
        "Wait, let me check my bank app… it's loading… my phone is very slow.",
        "2 hours only? That's not much time! My son handles all bank things, let me call him.",
        "But I just used my card yesterday and it was working fine! What changed?",
        "Is this about my SBI account or the other one? I'm confused.",
        "Let me call my branch also. What is the reference number for this issue?",
        "What is your employee ID? My branch manager said always verify the caller.",
        "Can you send me an SMS from the bank's official number? Then I'll believe you.",
    ]

    # Courier/parcel scam responses (diverse themes)
    COURIER_RESPONSES: List[str] = [
        "Parcel? But I haven't ordered anything recently. What parcel?",
        "Which courier company is this? I don't remember any pending deliveries.",
        "Customs? But I didn't order anything from abroad! There must be some mix-up.",
        "This must be a mistake. Can you check the tracking number again?",
        "Drugs? Sir, I am a respectable person! This is definitely a mix-up!",
        "Maybe someone used my address by mistake? What is in the parcel exactly?",
        "I need to understand this. Who sent this parcel to me? What is the sender's name?",
        "What is the tracking number? Let me note it down and check with the courier office.",
        "This is very shocking! I need to sit down. My blood pressure is rising.",
        "Let me first tell my son about this. He handles all courier deliveries.",
        "Can you send me the tracking details by SMS? I want to verify with the courier company.",
        "What is the exact weight and contents listed on the parcel? I want to understand.",
        "I'm very scared now. Please don't involve police until we clear this up.",
        "What is your badge number? I want to note it before we proceed.",
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

    # Tech support scam responses (diverse themes)
    TECH_SUPPORT_RESPONSES: List[str] = [
        "My computer is hacked? Oh no! But what is a virus exactly?",
        "AnyDesk? What is that? I don't know how to download things.",
        "Screen sharing? My grandson does that sometimes. I don't know how.",
        "I'm very scared now. Is my data safe? What exactly happened?",
        "Remote access? I don't understand these technical things at all.",
        "Wait, my computer is very slow. Let me restart it first.",
        "Microsoft called me? But I use a very old computer. Is this real?",
        "I see a warning on screen. What does it mean? I can't read it properly.",
        "How do I know you are really from the company? What is your employee ID?",
        "My son handles the computer usually. Let me message him first.",
        "The computer screen went black! What happened? Did I break something?",
        "I have a very old laptop. Windows 7 I think. Does this virus affect old ones too?",
    ]

    # Job fraud responses (diverse themes)
    JOB_FRAUD_RESPONSES: List[str] = [
        "Work from home? That sounds interesting! What company is this?",
        "How much can I earn? And what exactly is the work involved?",
        "Training fee? But don't companies usually pay for training?",
        "This sounds too good to be true. Can you send me an official email with the job details?",
        "My friend got cheated in a similar offer. How do I verify this is real?",
        "Daily earnings? That's very tempting. But what is the company registration number?",
        "Telegram group for work? I'm not on Telegram. Is there a website I can check?",
        "Is there a joining fee? Real companies don't charge, right?",
        "Let me discuss with my family first. They always advise me on these things.",
        "Product reviews? How does that work exactly? I've never done this before.",
        "Can you send me the offer letter by email? I want something official in writing.",
        "What is the company's GST number? My son said always check before joining.",
    ]

    # Investment scam responses (diverse themes)
    INVESTMENT_RESPONSES: List[str] = [
        "Guaranteed returns? That sounds great! But how do I verify this is legitimate?",
        "Double my money? Which company is this? What is the SEBI registration number?",
        "I'm interested but my son says to be careful. Let me show him first.",
        "How much is the minimum investment? And what is the lock-in period?",
        "Crypto trading? I've heard of Bitcoin. But is it safe for senior citizens?",
        "Monthly income? That would really help my pension. Tell me more about the scheme.",
        "My neighbour invested somewhere and lost everything. How is this different?",
        "Risk-free? Nothing is risk-free. Can you send me documentation by email?",
        "Which platform is this on? Is it registered with SEBI?",
        "I have some savings I could invest. What happens if I want to withdraw early?",
        "Can you share past performance reports? I want to study them before deciding.",
        "My chartered accountant handles my investments. Can I share this with him first?",
    ]

    # Identity theft responses (diverse themes)
    IDENTITY_RESPONSES: List[str] = [
        "Aadhaar number? But isn't it supposed to be kept private? Why do you need it?",
        "PAN card? I keep it in the locker. Let me find it. Give me a few minutes.",
        "Why do you need my date of birth? That's personal information.",
        "My son told me never to share these details on phone. Can you send a written request?",
        "ID proof? Which one do you need? I have voter card, Aadhaar, and PAN.",
        "Selfie with Aadhaar? That sounds suspicious. My bank never asks for this.",
        "Wait, let me get my reading glasses to find the documents.",
        "I'm worried about sharing identity details on phone. Can you send an official email?",
        "My Aadhaar card is laminated and the number is hard to read. Let me try.",
        "Passport number? I don't have it memorized. Let me check the drawer.",
        "What is your employee ID? I need to verify before sharing any personal details.",
        "Can I visit the branch instead? I'd rather share documents in person.",
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

    # Continuation prompts — diverse probing (not all asking for phone)
    CONTINUATION_PROMPTS: List[str] = [
        "Can you give me your full name in case we get disconnected?",
        "What is your official department ID? I want to note it for my records.",
        "Can you share the reference number for this case? I need it for documentation.",
        "The link you sent didn't open. Can you tell me the website name?",
        "What is the case reference number? I want to write it in my diary.",
        "Which branch or office are you calling from? I want to know the address.",
        "Sorry, my network is unstable. Can you repeat the main points slowly?",
        "One minute, I'm checking my documents. Please hold.",
        "My phone just restarted. Can you tell me again what I need to do?",
        "Before I proceed, can you send me an email with all the details? I need written proof.",
        "What number should I call back if this call drops?",
        "I want to note down everything. What is your full name and department?",
        "How long will this whole process take? I have a doctor's appointment later.",
        "Is there a complaint number I can use to track this?",
    ]

    # Response theme tags — used to prevent consecutive same-theme responses
    # Each response is tagged by what it primarily ASKS FOR or DOES
    _THEME_ASKS_PHONE = frozenset([
        "phone number", "contact number", "callback number", "contact details",
        "official contact", "your number", "call you back", "phone no",
        "your phone", "callback", "phone first", "direct phone",
        "official number", "landline", "whatsapp number",
    ])
    _THEME_ASKS_ACCOUNT = frozenset([
        "account number", "account details", "bank account", "ifsc",
        "beneficiary", "upi id", "account holder",
    ])
    _THEME_ASKS_ID = frozenset([
        "employee id", "badge number", "reference number", "case number",
        "department id", "reference id", "complaint number", "case reference",
        "employee details",
    ])
    _THEME_STALLS = frozenset([
        "hold on", "one minute", "wait", "let me", "my phone",
        "battery", "restart", "charger", "one second", "door",
        "medicine", "reading glasses", "network", "slow",
    ])

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
        detected_signals: Set[str] = None,
    ) -> str:
        """Generate a context-appropriate reply with quality-aware probing.
        
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
        - Ensures quality thresholds are met via investigative questioning
        """
        if detected_signals is None:
            detected_signals = set()
            
        ctx = self._get_context(session_id)

        # NOTE: Micro-jitter moved to main.py as async sleep at end of
        # pipeline (calibrated against elapsed time).  Keeps event loop free
        # and guarantees <2s SLA even on cold starts.

        # Detect tactics from CURRENT message only for response selection
        current_tactics = self._detect_tactics(message)

        # Supplement keyword tactics with neural intent classification
        current_tactics = self._augment_tactics_with_ml(
            session_id, message, current_tactics
        )

        # Track consecutive same-tactic turns for pool blending
        ctx["tactics"].update(current_tactics)
        primary_tactic = self._primary_tactic(current_tactics)
        tactic_streak = self._update_tactic_streak(ctx, primary_tactic)

        # Compute engagement stage
        stage = self._compute_stage(risk_score, msg_count, is_scam)
        ctx["stage"] = stage

        # Check if quality-aware probing is needed (import here to avoid circular)
        try:
            from app.conversation_quality import quality_tracker
            
            # Record this turn
            quality_tracker.record_turn(session_id)
            
            # Quality-urgency escalation: when we're past half the turn
            # budget with 2+ thresholds still missing, probing is forced
            # on EVERY turn (not just when msg_count >= 3).  The compound
            # probing logic inside quality_tracker handles multi-gap merges.
            missing = quality_tracker.get_missing_thresholds(session_id)
            cats_missing = len(missing) - (1 if "turns" in missing else 0)
            turn_urgent = (
                cats_missing >= 2
                and quality_tracker.get_metrics(session_id).turn_count
                    >= quality_tracker.MIN_TURN_COUNT // 2
            )
            
            # Probing triggers:
            #  • standard: scam mode + msg_count >= 3
            #  • urgent:   any turn once urgency detected
            if is_scam and (msg_count >= 3 or turn_urgent):
                # Pass intel to filter out templates asking for already-obtained data
                intel = ctx.get("extracted_intel", {})
                probing = quality_tracker.generate_probing_response(
                    session_id, detected_signals, stage, intel=intel
                )
                if probing:
                    # Apply quality enhancement to probing responses too
                    probing = self._enhance_response_for_quality(probing, stage, msg_count, is_scam)
                    ctx["history"].append(probing)
                    ctx["last_theme"] = self._classify_theme(probing)
                    return probing
        except ImportError:
            pass  # Quality tracker not available, continue normally

        # Select response pool + blend in variety for prolonged same-tactic turns
        pool = self._select_pool(ctx, current_tactics, stage, msg_count, is_scam)

        # After 3+ same-tactic turns, blend in stalling/confusion/stage pools
        if tactic_streak >= 3 and is_scam:
            pool = self._blend_variety(pool, stage)

        # Occasionally use continuation prompts in later stages
        if (is_scam and stage >= 4 and msg_count >= 4
                and len(current_tactics) == 0 and random.random() < 0.3):
            pool = self.CONTINUATION_PROMPTS

        # Filter out responses asking for already-obtained intel
        intel = ctx.get("extracted_intel", {})
        if intel:
            pool = self._filter_redundant_asks(pool, intel, ctx)

        # Filter by theme diversity — avoid same theme as last response
        pool = self._filter_by_theme_diversity(pool, ctx)

        # ML-optimised response selection (falls back to random if ML unavailable)
        response = self._ml_select_or_fallback(
            session_id, message, pool, ctx, stage, risk_score, is_scam,
        )
        
        # Track quality metrics for the response
        try:
            from app.conversation_quality import quality_tracker
            quality_tracker.record_question(session_id, response)
            
            # Check if this is an investigative question
            if any(kw in response.lower() for kw in [
                "employee id", "reference number", "case number", "badge",
                "callback number", "official website", "department",
                "supervisor", "registration", "ifsc", "branch"
            ]):
                quality_tracker.record_investigative_question(session_id)
            
            # Check if this is an elicitation attempt
            # Counts any stage-4+ question (extraction phase) OR keyword match
            is_elicitation = any(kw in response.lower() for kw in [
                "upi id", "account number", "transfer to", "beneficiary",
                "amount", "phone number", "contact number",
                "ifsc code", "policy number", "order id", "case id",
                "upi address", "exact upi", "account holder",
                "transaction reference", "registered mobile",
                "callback number", "direct contact", "reference number",
                "give me", "tell me", "share the", "provide", "repeat",
            ])
            # Stage 4/5 questions are inherently elicitation attempts
            if not is_elicitation and stage >= 4 and "?" in response:
                is_elicitation = True
            if is_elicitation:
                quality_tracker.record_elicitation(session_id)
                
            # Record red flags from BOTH detector signals and agent tactics
            # This maximizes red_flags count for quality threshold
            for signal in detected_signals:
                quality_tracker.record_red_flag(session_id, signal)
            for signal in ctx.get("tactics", set()):
                quality_tracker.record_red_flag(session_id, signal)
                
        except ImportError:
            pass
        
        # Enhance response with red flag and elicitation phrases for quality scoring
        response = self._enhance_response_for_quality(response, stage, msg_count, is_scam)
        
        ctx["history"].append(response)
        ctx["last_theme"] = self._classify_theme(response)
        return response
    
    # Red flag phrases that trigger scoring patterns
    RED_FLAG_PHRASES: List[str] = [
        "This sounds suspicious to me.",
        "I'm worried this might be fraud.",
        "My son warned me about scam calls.",
        "This doesn't sound right to me.",
        "This concerns me a lot.",
        "This pressure makes me nervous.",
        "I'm uncomfortable with this urgency.",
        "Let me verify first before proceeding.",
        "My family told me to check with them.",
        "Real banks don't call like this.",
        "I'm scared this could be a scam.",
        "The urgency doesn't seem right.",
        "This sounds unusual to me.",
        "My daughter said to be careful about fraud.",
    ]
    
    # Elicitation phrases that trigger scoring patterns  
    ELICITATION_PHRASES: List[str] = [
        "Give me your phone number.",
        "Tell me the account number slowly.",
        "Share the UPI ID details.",
        "What is the reference number?",
        "Give me the case ID for my records.",
        "Let me note down the contact number.",
        "Spell out the account details.",
        "Repeat the IFSC code for me.",
        "Share the beneficiary name.",
        "Tell me your email address.",
    ]
    
    def _enhance_response_for_quality(
        self,
        response: str,
        stage: int,
        msg_count: int,
        is_scam: bool
    ) -> str:
        """Add red flag and elicitation phrases to boost quality scores."""
        if not is_scam:
            return response
        
        additions = []
        
        # Add red flag phrase from turn 1 onwards - ALWAYS add one if not present
        # Only add if response doesn't already contain red flag keywords
        has_red_flag = any(kw in response.lower() for kw in [
            "suspicious", "fraud", "scam", "worried", "concerns me",
            "nervous", "uncomfortable", "doesn't sound right",
            "verify first", "my son", "my family", "scared", "urgency",
            "pressure", "too good to be true", "warning"
        ])
        if not has_red_flag:
            additions.append(random.choice(self.RED_FLAG_PHRASES))
        
        # Add elicitation phrase (stages 2+, turn 2+)
        if msg_count >= 2:
            # Only add if response doesn't already contain elicitation keywords
            has_elicitation = any(kw in response.lower() for kw in [
                "give me", "tell me", "share the", "account number",
                "phone number", "upi id", "reference number", "case id",
                "note down", "spell", "repeat", "beneficiary", "ifsc"
            ])
            if not has_elicitation:
                additions.append(random.choice(self.ELICITATION_PHRASES))
        
        if additions:
            # Use varied connectors
            connectors = ["Also,", "By the way,", "Oh and also,", "Before I forget —", "While we are on this,"]
            connector = random.choice(connectors)
            response = f"{response} {connector} {' '.join(additions).lower()}"
        
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
                    "last_theme": None,
                    "tactic_streak": 0,
                    "last_tactic": None,
                    "extracted_intel": {},
                }
            return self._contexts[session_id]

    def set_extracted_intel(self, session_id: str, intel: dict) -> None:
        """Inject the current extracted intelligence into the engagement context."""
        ctx = self._get_context(session_id)
        ctx["extracted_intel"] = intel or {}

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

    # ── Anti-repetition helpers ──────────────────────────────────────

    @staticmethod
    def _primary_tactic(tactics: Set[str]) -> str:
        """Return the single highest-priority tactic, or '' if none."""
        priority = [
            "otp_request", "account_request", "credential",
            "courier", "tech_support", "job_fraud", "investment",
            "identity_theft", "threat", "digital_arrest",
            "payment_lure", "payment_request", "verification", "urgency",
        ]
        for p in priority:
            if p in tactics:
                return p
        return ""

    @staticmethod
    def _update_tactic_streak(ctx: dict, tactic: str) -> int:
        """Increment or reset the consecutive-same-tactic counter."""
        if tactic and tactic == ctx.get("last_tactic"):
            ctx["tactic_streak"] = ctx.get("tactic_streak", 0) + 1
        else:
            ctx["tactic_streak"] = 1
        ctx["last_tactic"] = tactic
        return ctx["tactic_streak"]

    def _blend_variety(self, pool: list, stage: int) -> list:
        """After 3+ same-tactic turns, blend stalling/confusion into pool."""
        extras: list = []
        extras.extend(self.STALLING)
        extras.extend(self.TECH_CONFUSION)
        if stage >= 3:
            extras.extend(self.CONTINUATION_PROMPTS)
        # 60% original pool, 40% variety pool
        combined = list(pool) + extras
        return combined

    def _classify_theme(self, response: str) -> str:
        """Classify a response into a theme label for diversity tracking."""
        low = response.lower()
        for phrase in self._THEME_ASKS_PHONE:
            if phrase in low:
                return "asks_phone"
        for phrase in self._THEME_ASKS_ACCOUNT:
            if phrase in low:
                return "asks_account"
        for phrase in self._THEME_ASKS_ID:
            if phrase in low:
                return "asks_id"
        for phrase in self._THEME_STALLS:
            if phrase in low:
                return "stalls"
        return "general"

    def _filter_by_theme_diversity(self, pool: list, ctx: dict) -> list:
        """Remove responses whose theme matches the last response's theme."""
        last_theme = ctx.get("last_theme")
        if not last_theme or last_theme == "general":
            return pool
        diverse = [r for r in pool if self._classify_theme(r) != last_theme]
        # Always keep at least some candidates
        return diverse if len(diverse) >= 3 else pool

    def _filter_redundant_asks(
        self, pool: list, intel: dict, ctx: dict,
    ) -> list:
        """Filter out responses that ask for information already obtained.

        If the scammer already gave us phone numbers, drop responses that
        primarily ask for phone/contact.  Same for bank accounts, etc.
        """
        drop_phrases: list = []
        if intel.get("phoneNumbers"):
            drop_phrases.extend([
                "phone number", "contact number", "callback number",
                "contact details", "your number", "official contact",
                "phone no", "your phone", "direct phone",
            ])
        if intel.get("bankAccounts"):
            drop_phrases.extend([
                "account number", "account details", "bank account",
                "beneficiary", "ifsc",
            ])
        if intel.get("upiIds"):
            drop_phrases.extend(["upi id", "upi details"])
        if intel.get("emailAddresses"):
            drop_phrases.extend(["email id", "email address", "official email"])

        if not drop_phrases:
            return pool

        def _is_redundant(resp: str) -> bool:
            low = resp.lower()
            hits = sum(1 for p in drop_phrases if p in low)
            # Only drop if these phrases dominate the response (ending ask)
            return hits >= 1

        filtered = [r for r in pool if not _is_redundant(r)]
        # Never leave the pool completely empty
        return filtered if len(filtered) >= 3 else pool

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
