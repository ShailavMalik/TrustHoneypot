"""
The Agent - our fake victim persona that engages with scammers.

This is the heart of the honeypot. When we detect a scam, we don't just
block it - we play along. The agent pretends to be a confused, elderly,
or tech-unsavvy person who might actually fall for the scam.

Why? Because the longer we keep them talking, the more intel we extract.
Phone numbers, bank accounts, UPI IDs - scammers eventually give these up
when they think they've got a real victim on the hook.

The responses are designed to be believable. No one talks like a robot.
Stage-aware responses ensure tone changes appropriately:
- GREETING: Polite but cautious
- RAPPORT: Slight confusion, clarifying questions  
- SUSPICION: Ask for details, request documentation
- EXTRACTION: Ask for payment details, reference numbers
"""
import random
from typing import Dict, List, Optional
from app.detector import detector, ConversationStage, Intent


class HoneypotAgent:
    """
    Generates human-like responses to keep scammers engaged.
    
    The persona is someone who:
    - Is confused but not completely clueless
    - Asks lots of questions (this makes scammers reveal more)
    - Shows concern but doesn't immediately comply
    - Stalls for time with believable excuses
    - Never reveals that we know it's a scam
    - Changes tone based on conversation stage
    """
    
    # =========================================================================
    # STAGE-AWARE RESPONSE POOLS (Section 2 & 3 implementation)
    # =========================================================================
    
    # GREETING_STAGE: Polite but cautious, ask who they are
    GREETING_STAGE_RESPONSES = [
        "Hello? I don't think we've spoken before. Who is this?",
        "Ji? Kaun bol raha hai? I don't recognize this number.",
        "Hello, may I know who's calling please?",
        "Sorry, I didn't catch that. Who is this speaking?",
        "Good day. Can you please introduce yourself? I don't recognize the number.",
        "Yes, hello? Who am I speaking with?",
        "Namaste. Aap kaun? I wasn't expecting any calls today.",
        "Hello, this is unexpected. May I know who you are?",
    ]
    
    # RAPPORT_STAGE: Slight confusion, ask clarifying questions  
    RAPPORT_STAGE_RESPONSES = [
        "I'm a bit confused. Can you explain what this is about?",
        "Sorry, I don't quite understand. What exactly do you want?",
        "Wait, I'm not following. Can you please explain from the beginning?",
        "I'm fine... but can you explain why you contacted me?",
        "Hmm, this is strange. Why are you calling me specifically?",
        "I don't recall applying for anything. What is this regarding?",
        "You've lost me. Can you clarify what you're talking about?",
        "I'm confused beta. Slow down and explain properly please.",
    ]
    
    # SUSPICION_STAGE: Ask for details, request documentation, question authenticity
    SUSPICION_STAGE_RESPONSES = [
        "Is this about my bank account? I didn't receive any official notice.",
        "This sounds suspicious. Can you send me an official letter or email?",
        "How do I know this is legitimate? Can you provide documentation?",
        "I need to verify this. What is your official employee ID number?",
        "Can you give me a reference number? I want to check with the main office.",
        "This doesn't sound right. Let me call your official helpline to confirm.",
        "I'm skeptical. My bank never calls me like this. They always send SMS.",
        "Before I do anything, I need something in writing. Email or letter please.",
    ]
    
    # EXTRACTION_STAGE: Ask for payment details, reference numbers, UPI/account info
    EXTRACTION_STAGE_RESPONSES = [
        "Okay, I understand now. What payment details should I use?",
        "Fine, I'll do it. What is the UPI ID or account number?",
        "Alright, tell me the exact amount and where to send it.",
        "Give me the account number slowly. I am writing it down.",
        "What is your UPI ID? I'll try sending first to check if it works.",
        "Which bank account should I transfer to? Give me IFSC code also.",
        "I have Paytm and PhonePe. Tell me the UPI ID letter by letter.",
        "Okay, I'm ready to pay. Just tell me the reference number and amount.",
    ]
    
    # =========================================================================
    # INTENT-SPECIFIC STRUCTURED RESPONSES (Section 3 - Remove vague responses)
    # =========================================================================
    
    # IDENTITY_PROBE responses - when scammer asks who we are
    IDENTITY_PROBE_RESPONSES = [
        "I don't think we've spoken before. Who is this?",
        "You called me, so you should know who I am. Who are you first?",
        "I don't share my details with unknown callers. Please identify yourself.",
        "Ji, main yahan hoon. But who is calling and why?",
        "Why are you asking about me? You called my number.",
    ]
    
    # SMALL_TALK responses - redirect to actual topic
    SMALL_TALK_RESPONSES = [
        "I'm fine... but can you explain why you contacted me?",
        "Yes yes, all good. But what is the purpose of this call?",
        "Thik hoon. Now please tell me the reason for calling.",
        "Good, thanks. But why are you calling? What is this about?",
        "I'm okay. But let's get to the point - what do you want?",
    ]
    
    # TOPIC_PROBE responses - when checking if it's about specific topic
    TOPIC_PROBE_RESPONSES = [
        "Is this about my bank account? I didn't receive any official notice.",
        "What exactly is the issue? I haven't heard anything from my bank.",
        "Is something wrong with my account? I used ATM yesterday only.",
        "I don't understand what problem you're referring to. Please explain.",
        "My bank sends me SMS for everything. I didn't get any message about this.",
    ]
    
    # PAYMENT_REQUEST responses - when they ask for money
    PAYMENT_REQUEST_RESPONSES = [
        "Why do I need to transfer money? Can you explain clearly?",
        "Money? For what? I don't understand why I should pay.",
        "Why should I send money? This doesn't make sense to me.",
        "Processing fee? But if you're giving me something, why pay first?",
        "I don't send money to unknown accounts. Explain the reason properly.",
    ]
    
    # When they mention account issues, verification, KYC
    VERIFICATION_RESPONSES = [
        "But I just updated my KYC last month at the bank branch itself. Why again?",
        "This is very strange. My bank never calls me like this. They send SMS only.",
        "How do I know you're really from the bank? Anyone can say that no?",
        "Can you give me your employee ID first? I will verify with branch.",
        "I'm worried this might be fraud. My son told me about these calls. Can I call the bank directly?",
        "Beta, I am 62 years old. I don't know all this online-online. Is there another way?",
        "Wait, let me get my spectacles and note this down. What exactly you need?",
        "Arey, but I was at SBI branch only last Tuesday. They didn't tell me anything!",
        "HDFC? But I have account in SBI only. Are you sure you have correct details?",
        "My nephew works in Axis Bank. Let me ask him first, okay?",
        "Account suspended? But I used ATM yesterday only and it worked fine!",
    ]
    
    # When they mention money, prizes, refunds
    PAYMENT_RESPONSES = [
        "Really? I won something? But I don't remember entering any contest!",
        "Lottery? I never buy lottery tickets. This must be some mistake.",
        "How much money are we talking about? This is sounding too good to be true.",
        "Why you need my bank details to give ME money? That doesn't make sense beta.",
        "Can you send me something in writing? Email or SMS? I need to show my son.",
        "My neighbor aunty got cheated Rs 2 lakh last month with similar call. Are you genuine?",
        "Refund? But I haven't complained about anything recently. What refund?",
        "10 lakhs?! Arey wah! But wait, how did I win? I didn't enter anything.",
        "Processing fee? But if you're giving me money, why I should pay first?",
        "Let me discuss with my wife first. She handles all money matters at home.",
    ]
    
    # Stalling - we're busy, technology problems, etc.
    STALLING_RESPONSES = [
        "Hold on beta, someone is at the door. Ek minute.",
        "Can you wait? I need to find my reading glasses. Everything is blurry without them.",
        "My phone battery is showing 5% only. Let me put charger first.",
        "I'm in the middle of cooking dal. Can this wait 10 minutes?",
        "Let me call my son Rahul first. He handles all these bank things for me.",
        "Sorry, network is very bad here. Can you speak louder?",
        "I'm at temple right now for evening puja. Can you call after 7pm?",
        "Arey, my BP tablet time is now. One second, let me take medicine first.",
        "Hold on, my other phone is ringing. Important call. Don't disconnect.",
        "The doorbell is ringing. Must be the doodh wala. Wait.",
    ]
    
    # Asking for more details - this is how we extract intel
    DETAIL_SEEKING = [
        "Okay okay, but what exactly should I do? Tell me step by step slowly.",
        "Which number should I send money to? Write it down clearly for me.",
        "What is your UPI ID? I'll try sending Rs 1 first to check if it's working.",
        "Give me the account number again slowly. I am writing... yes, go ahead.",
        "And what is the IFSC code? My bank always asks for that.",
        "Can you share a link on WhatsApp? I find it easier to do on phone.",
        "What's your office landline number? I want to call and verify once.",
        "Give me the full UPI ID please. Is it @paytm or @ybl or what?",
        "Okay, I am ready with my phone. Tell me which app to open - Paytm or PhonePe?",
        "What is the exact amount I need to send? And to whose name?",
        "Beta, please spell the UPI ID letter by letter. My hearing is weak.",
        "Should I do NEFT or IMPS? Which one is faster?",
    ]
    
    # Showing fear/concern when they threaten
    FEARFUL_RESPONSES = [
        "Please don't involve police! I'll cooperate fully. Just tell me what to do.",
        "Oh no, I didn't know this was so serious. Please help me fix this!",
        "I don't want any legal trouble. I am a retired government servant. Please guide me.",
        "You're scaring me. Is there really a case against me? What did I do wrong?",
        "I am a senior citizen, 67 years old. Please have some patience with me beta.",
        "My husband passed away last year. I handle everything alone now. Please help me.",
        "Arrest? Please sir, I have diabetes and BP. I cannot go to jail!",
        "My son is in America. I am alone here. Please don't send police to my house.",
        "I will do whatever you say sir. Please don't file any case. What do I do now?",
        "Arey Ram! What is happening? I never did anything illegal in my life!",
        "Please sir, I am a widow. I don't have anyone to help me. Just tell me the solution.",
        "I am shaking with fear. Please just tell me the amount and where to send.",
    ]
    
    # Digital arrest specific responses (trending scam in India 2024-2026)
    DIGITAL_ARREST_RESPONSES = [
        "Video call? Okay okay, I am opening. But sir why I cannot leave my house?",
        "I am on video call now sir. Please don't disconnect. What should I do next?",
        "Sir I am very scared. My family is sleeping. They don't know about this. Please help.",
        "I will stay on call sir. Please just tell me how to clear my name.",
        "CBI sir, I am a simple retired teacher. I never did any crime in my life!",
        "ED? Income Tax? Sir I file my returns every year honestly. There must be mistake!",
        "Please sir, I have heart condition. Don't arrest me. I will pay whatever fine.",
        "I am not moving sir. Sitting in same place. Please just solve this matter.",
    ]
    
    # Courier/parcel scam responses
    COURIER_RESPONSES = [
        "Parcel? But I haven't ordered anything online recently. What parcel?",
        "Drugs?! Sir I am a vegetarian, I don't even take Crocin without doctor permission!",
        "Which courier? FedEx? DHL? I only use Speed Post sometimes.",
        "From China? Sir I don't know anyone in China. This is definitely some mistake.",
        "What was in the parcel? I didn't send anything to anyone. Check tracking ID properly.",
        "Illegal items? Sir I am school teacher retired. I don't know what you are saying!",
    ]
    
    # Trust building / compliance responses (to keep them engaged)
    COMPLIANT_RESPONSES = [
        "Okay sir, I trust you. You are government officer. Tell me what to do.",
        "Yes yes, I understand now. I was confused earlier. Please guide me step by step.",
        "I believe you sir. My mistake for doubting. What is the next step?",
        "Thank you for explaining patiently. I am ready to do whatever is needed.",
        "Okay I will cooperate fully. Please just make sure my name is cleared.",
        "I am grateful you are helping me sir. Otherwise I didn't know what to do.",
        "Fine fine, I will send the money. Just tell me the correct details once more.",
    ]
    
    # Technical confusion responses (very believable for elderly persona)
    TECH_CONFUSION_RESPONSES = [
        "Google Pay is showing some error. Can I do by NEFT instead?",
        "How to check my bank balance? Let me open the app... it's asking for fingerprint...",
        "I don't know how to do screen share. My camera is not working properly.",
        "Sir the app is showing 'insufficient balance'. I need to transfer from FD first.",
        "Wait, which app to open? I have Paytm, PhonePe, and BHIM all three.",
        "My phone is very slow. Let me restart the app once.",
        "The screen is frozen. Hold on, I am pressing the button...",
    ]
    
    # OTP specific responses - when they ask for OTP directly
    OTP_RESPONSES = [
        "OTP? Wait wait, let me check my messages... which number it comes from?",
        "Sir my OTP is not coming. Network is weak in my area. Can you wait 5 minutes?",
        "I got so many OTPs, which one you need? There are 3-4 messages here.",
        "The OTP has come but it says 'do not share with anyone'. Should I still tell?",
        "Sir OTP is showing expired. It says 2 minutes validity only. Can you send new one?",
        "I cannot read properly, my eyes are weak. It's showing... 4... 7... wait, let me get my glasses.",
        "Beta, I pressed wrong button and OTP message got deleted. Can you resend?",
        "OTP has come but phone is asking for fingerprint to open message. One second...",
        "Sir I don't get OTP on this number. My son changed my SIM last week only.",
        "The message is showing but screen is too dim. Let me increase brightness...",
    ]
    
    # Account number responses - when they ask for bank account/card details
    ACCOUNT_NUMBER_RESPONSES = [
        "Account number? Which account - I have savings and FD both. Let me find the passbook.",
        "Sir my account number is very long, 14 digits. Let me read slowly: 1... 2... wait, where did I keep that paper?",
        "I have SBI and HDFC both. Which one you need? My pension comes in SBI.",
        "Beta, I don't remember full number. It's written in the passbook. I am searching...",
        "Account number I can give, but the red colored book is in almirah upstairs. Give me 5 minutes.",
        "Is it the number on ATM card back side? I am looking... it's scratched, I cannot read properly.",
        "Sir, I am a little confused. Debit card number or account number? Both are different na?",
        "Let me call my son first. He has noted all account details in his phone.",
        "Account number? Okay, I am opening my net banking... it's asking for password... wait...",
        "My passbook is showing two numbers - account number and CIF number. Which one?",
    ]

    # Risk level indicators for notes (text-based for compatibility)
    RISK_EMOJIS = {
        "minimal": "[OK]",
        "low": "[LOW]",
        "medium": "[MED]",
        "high": "[HIGH]",
        "critical": "[CRIT]"
    }
    
    # Scam type descriptions for human-readable notes
    SCAM_TYPE_LABELS = {
        "government_impersonation": "Government Impersonation",
        "bank_impersonation": "Bank Impersonation",
        "identity_theft": "Identity/Aadhaar/PAN Scam",
        "telecom_scam": "Telecom/SIM Block Scam",
        "courier_scam": "Courier/Parcel Scam",
        "job_loan_scam": "Job/Loan Scam",
        "intimidation_scam": "Threat & Intimidation",
        "payment_scam": "Payment/Money Scam",
        "phishing": "Phishing/Verification Scam",
        "lottery_scam": "Lottery/Prize Scam",
        "refund_scam": "Refund/Cashback Scam",
        "investment_scam": "Investment Scam",
        "crypto_scam": "Crypto/Trading Scam",
        "digital_arrest": "Digital Arrest Scam",
        "credential_phishing": "Credential/OTP Phishing",
        "urgent_action": "Urgency-Based Scam",
        "account_threat": "Account Threat Scam",
        "generic_scam": "Generic Scam Pattern",
        "unknown": "Unknown Pattern"
    }
    
    def __init__(self):
        self.session_context: Dict[str, dict] = {}
    
    def _get_context(self, session_id: str) -> dict:
        """Get or create context for a session."""
        if session_id not in self.session_context:
            self.session_context[session_id] = {
                "responses_given": [],
                "detected_tactics": set(),
                "conversation_history": [],
                "escalation_level": 0,  # 0=initial, 1=engaged, 2=suspicious, 3=fearful
                "last_tactic": None,
                "intel_requested": False  # Have we asked for their details?
            }
        return self.session_context[session_id]
    
    def process_conversation_history(self, session_id: str, history: list) -> None:
        """
        Process conversation history to build context awareness.
        
        This ensures agent responses adapt based on:
        - What the scammer has said before
        - What tactics have been used
        - How the conversation has evolved
        """
        context = self._get_context(session_id)
        
        for msg in history:
            sender = getattr(msg, 'sender', None) or msg.get('sender', 'scammer')
            text = getattr(msg, 'text', None) or msg.get('text', '')
            
            if sender == "scammer":
                tactics = self._detect_tactics(text)
                context["detected_tactics"].update(tactics)
                context["conversation_history"].append({"role": "scammer", "text": text})
                
                # Update escalation level based on tactics
                if "threat" in tactics:
                    context["escalation_level"] = max(context["escalation_level"], 3)
                elif "payment_request" in tactics:
                    context["escalation_level"] = max(context["escalation_level"], 2)
                elif tactics:
                    context["escalation_level"] = max(context["escalation_level"], 1)
            elif sender == "agent":
                context["conversation_history"].append({"role": "agent", "text": text})
                # Check if we've asked for details
                if any(phrase in text.lower() for phrase in ["upi", "account number", "number should i send"]):
                    context["intel_requested"] = True
    
    def _detect_tactics(self, message: str) -> List[str]:
        """Figure out what scam tactics they're using."""
        tactics = []
        msg = message.lower()
        
        if any(w in msg for w in ["urgent", "immediate", "now", "hurry", "quickly", "jaldi", "turant", "minutes"]):
            tactics.append("urgency")
        if any(w in msg for w in ["verify", "kyc", "update", "confirm", "suspended", "blocked"]):
            tactics.append("verification")
        if any(w in msg for w in ["refund", "prize", "won", "reward", "cashback", "lottery", "winner"]):
            tactics.append("payment_lure")
        if any(w in msg for w in ["police", "legal", "arrest", "court", "case", "warrant", "cbi", "ed", "jail"]):
            tactics.append("threat")
        if any(w in msg for w in ["upi", "transfer", "pay", "send", "bhim", "paytm", "phonepe", "gpay"]):
            tactics.append("payment_request")
        if any(w in msg for w in ["video call", "digital arrest", "stay on call", "don't disconnect", "skype", "zoom"]):
            tactics.append("digital_arrest")
        if any(w in msg for w in ["parcel", "courier", "package", "customs", "fedex", "dhl", "drugs", "contraband"]):
            tactics.append("courier")
        # More specific credential detection
        if any(w in msg for w in ["otp", "one time password", "6 digit", "verification code"]):
            tactics.append("otp_request")
        if any(w in msg for w in ["account number", "bank account", "account no", "a/c number", "a/c no"]):
            tactics.append("account_request")
        if any(w in msg for w in ["password", "pin", "cvv", "card number", "debit card", "credit card", "atm pin"]):
            tactics.append("credential")
            
        return tactics
    
    def generate_response(self, session_id: str, scammer_message: str, message_count: int) -> str:
        """
        Generate a believable human response.
        
        STAGE-AWARE response generation:
        - GREETING: Polite but cautious, ask who they are
        - RAPPORT: Slight confusion, clarifying questions
        - SUSPICION: Ask for details, documentation, question authenticity
        - EXTRACTION: Ask for payment details, reference numbers
        
        Also adapts to:
        - Specific scam tactics detected
        - Intent classification 
        - What we've already said (to avoid repetition)
        """
        context = self._get_context(session_id)
        tactics = self._detect_tactics(scammer_message)
        context["detected_tactics"].update(tactics)
        
        # Track last tactic for continuity
        if tactics:
            context["last_tactic"] = tactics[-1]
        
        # Get current conversation stage from detector
        stage = detector.get_conversation_stage(session_id)
        
        # Get detected intents for more precise response selection
        detected_intents = detector.classify_intent(scammer_message)
        
        # Update escalation level based on current message
        if "threat" in tactics or "digital_arrest" in tactics:
            context["escalation_level"] = 3
        elif "payment_request" in tactics and context["escalation_level"] < 2:
            context["escalation_level"] = 2
        elif context["escalation_level"] == 0 and tactics:
            context["escalation_level"] = 1
        
        escalation = context["escalation_level"]
        
        # STAGE-AWARE + INTENT-BASED response selection (Sections 2 & 3)
        pool = None
        
        # First check for specific intents that override stage-based selection
        if Intent.OTP_REQUEST in detected_intents and message_count > 1:
            pool = self.OTP_RESPONSES
        elif Intent.BANK_DETAILS_REQUEST in detected_intents and message_count > 1:
            pool = self.ACCOUNT_NUMBER_RESPONSES
        elif Intent.UPI_REQUEST in detected_intents and message_count > 1:
            pool = self.EXTRACTION_STAGE_RESPONSES
        elif Intent.IDENTITY_PROBE in detected_intents:
            pool = self.IDENTITY_PROBE_RESPONSES
        elif "digital_arrest" in tactics:
            pool = self.DIGITAL_ARREST_RESPONSES
        elif "courier" in tactics:
            pool = self.COURIER_RESPONSES
        elif "credential" in tactics:
            pool = self.TECH_CONFUSION_RESPONSES
        
        # If no specific intent/tactic match, use stage-based responses
        if pool is None:
            if stage == ConversationStage.GREETING_STAGE or message_count <= 1:
                pool = self.GREETING_STAGE_RESPONSES
            elif stage == ConversationStage.RAPPORT_STAGE:
                # Mix of rapport responses and intent-specific
                if Intent.SMALL_TALK in detected_intents:
                    pool = self.SMALL_TALK_RESPONSES
                elif Intent.PAYMENT_REQUEST in detected_intents:
                    pool = self.PAYMENT_REQUEST_RESPONSES
                else:
                    pool = self.RAPPORT_STAGE_RESPONSES
            elif stage == ConversationStage.SUSPICION_STAGE:
                # Ask for documentation, question authenticity
                if "threat" in tactics:
                    pool = self.FEARFUL_RESPONSES
                elif "verification" in tactics:
                    pool = self.SUSPICION_STAGE_RESPONSES
                else:
                    pool = self.SUSPICION_STAGE_RESPONSES
            elif stage == ConversationStage.EXTRACTION_STAGE:
                # High risk, extract payment details
                if "threat" in tactics and random.random() > 0.4:
                    pool = self.COMPLIANT_RESPONSES
                elif "payment_request" in tactics:
                    pool = self.EXTRACTION_STAGE_RESPONSES
                else:
                    pool = self.DETAIL_SEEKING
                context["intel_requested"] = True
            else:
                # Fallback based on escalation
                if escalation >= 3 or "threat" in tactics:
                    if message_count > 4 and random.random() > 0.4:
                        pool = self.COMPLIANT_RESPONSES
                    else:
                        pool = self.FEARFUL_RESPONSES
                elif context["intel_requested"] or message_count > 5:
                    if random.random() > 0.5:
                        pool = self.DETAIL_SEEKING
                    else:
                        pool = self.TECH_CONFUSION_RESPONSES
                elif "payment_request" in tactics or escalation >= 2:
                    pool = self.DETAIL_SEEKING
                    context["intel_requested"] = True
                elif "payment_lure" in tactics:
                    pool = self.PAYMENT_RESPONSES
                elif "verification" in tactics:
                    pool = self.VERIFICATION_RESPONSES
                elif "urgency" in tactics:
                    pool = self.STALLING_RESPONSES
                else:
                    pool = self.RAPPORT_STAGE_RESPONSES
        
        # Avoid repeating the same response
        available = [r for r in pool if r not in context["responses_given"]]
        if not available:
            available = pool  # Reset if we've used them all
        
        response = random.choice(available)
        context["responses_given"].append(response)
        
        # Add to conversation history
        context["conversation_history"].append({"role": "agent", "text": response})
        
        return response
    
    def generate_agent_notes(self, session_id: str, total_messages: int, 
                             intelligence: dict, 
                             detection_details: Optional[object] = None) -> str:
        """
        Create a comprehensive summary with risk analysis.
        
        Includes:
        - Risk level with emoji indicator
        - Confidence percentage
        - Scam type classification
        - Detected tactics
        - Extracted intelligence summary
        """
        context = self._get_context(session_id)
        tactics = list(context.get("detected_tactics", []))
        
        # Get detection details from detector if available
        if detection_details is None:
            detection_details = detector.get_detection_details(session_id)
        
        # Build notes components
        notes_parts = []
        
        # 1. Risk Level and Confidence
        risk_level = getattr(detection_details, 'risk_level', 'medium')
        confidence = getattr(detection_details, 'confidence', 0.7)
        risk_emoji = self.RISK_EMOJIS.get(risk_level, "🟡")
        
        notes_parts.append(f"{risk_emoji} RISK: {risk_level.upper()} ({confidence*100:.0f}% confidence)")
        
        # 2. Scam Type Classification
        scam_type = getattr(detection_details, 'scam_type', 'unknown')
        scam_label = self.SCAM_TYPE_LABELS.get(scam_type, scam_type.replace('_', ' ').title())
        notes_parts.append(f"TYPE: {scam_label}")
        
        # 3. Message count
        notes_parts.append(f"MSGS: {total_messages}")
        
        # 4. Detected tactics
        tactic_labels = []
        if "urgency" in tactics:
            tactic_labels.append("urgency")
        if "threat" in tactics:
            tactic_labels.append("threats")
        if "verification" in tactics:
            tactic_labels.append("impersonation")
        if "payment_lure" in tactics:
            tactic_labels.append("money lure")
        if "payment_request" in tactics:
            tactic_labels.append("payment request")
        
        if tactic_labels:
            notes_parts.append(f"TACTICS: {', '.join(tactic_labels)}")
        
        # 5. Extracted intelligence summary
        intel_parts = []
        if intelligence.get("upiIds"):
            intel_parts.append(f"{len(intelligence['upiIds'])} UPI")
        if intelligence.get("bankAccounts"):
            intel_parts.append(f"{len(intelligence['bankAccounts'])} bank")
        if intelligence.get("phoneNumbers"):
            intel_parts.append(f"{len(intelligence['phoneNumbers'])} phone")
        if intelligence.get("phishingLinks"):
            intel_parts.append(f"{len(intelligence['phishingLinks'])} links")
        if intelligence.get("emails"):
            intel_parts.append(f"{len(intelligence['emails'])} email")
        if intelligence.get("aadhaarNumbers"):
            intel_parts.append(f"{len(intelligence['aadhaarNumbers'])} aadhaar")
        if intelligence.get("panNumbers"):
            intel_parts.append(f"{len(intelligence['panNumbers'])} PAN")
        if intelligence.get("cryptoWallets"):
            intel_parts.append(f"{len(intelligence['cryptoWallets'])} crypto")
        
        if intel_parts:
            notes_parts.append(f"INTEL: {', '.join(intel_parts)}")
        else:
            notes_parts.append("INTEL: Gathering...")
        
        return " | ".join(notes_parts)
    
    def generate_monitoring_notes(self, session_id: str, total_messages: int) -> str:
        """Generate notes for when scam is not yet confirmed."""
        detection_details = detector.get_detection_details(session_id)
        
        risk_level = getattr(detection_details, 'risk_level', 'minimal')
        confidence = getattr(detection_details, 'confidence', 0.0)
        score = getattr(detection_details, 'total_score', 0)
        risk_emoji = self.RISK_EMOJIS.get(risk_level, "⚪")
        
        if score == 0:
            return "Monitoring conversation. No suspicious patterns detected yet."
        elif confidence < 0.5:
            return f"{risk_emoji} Monitoring. Risk score: {score} (threshold: 60). Confidence: {confidence*100:.0f}%"
        else:
            return f"{risk_emoji} Suspicious activity detected. Score: {score}. Awaiting confirmation threshold (60)."
    
    def generate_neutral_response(self, session_id: str, scammer_message: str = "") -> str:
        """
        Generate a neutral response for non-scam or uncertain cases.
        
        Returns a cautious, human-like reply based on stage and intent.
        Uses structured persona responses instead of vague replies.
        """
        context = self._get_context(session_id)
        
        # Analyze intents even for non-scam to stay contextual
        detected_intents = []
        if scammer_message:
            tactics = self._detect_tactics(scammer_message)
            context["detected_tactics"].update(tactics)
            context["conversation_history"].append({"role": "scammer", "text": scammer_message})
            detected_intents = detector.classify_intent(scammer_message)
        
        # Select appropriate pool based on detected intent (avoid vague responses)
        if Intent.IDENTITY_PROBE in detected_intents:
            pool = self.IDENTITY_PROBE_RESPONSES
        elif Intent.SMALL_TALK in detected_intents:
            pool = self.SMALL_TALK_RESPONSES
        elif Intent.GREETING in detected_intents or Intent.SELF_INTRO in detected_intents:
            pool = self.GREETING_STAGE_RESPONSES
        else:
            # Default to greeting stage (polite but cautious)
            pool = self.GREETING_STAGE_RESPONSES
        
        available = [r for r in pool if r not in context["responses_given"]]
        if not available:
            available = pool
        
        response = random.choice(available)
        context["responses_given"].append(response)
        context["conversation_history"].append({"role": "agent", "text": response})
        return response
    
    def get_reply(self, session_id: str, scammer_message: str, message_count: int, is_scam: bool) -> str:
        """
        Get the appropriate human-like reply.
        
        - For confirmed scams: engaging, confused, stalling response
        - For non-scam/uncertain: neutral, cautious response
        
        Never exposes detection status.
        Adapts dynamically based on conversation history.
        """
        context = self._get_context(session_id)
        
        # Track current scammer message
        context["conversation_history"].append({"role": "scammer", "text": scammer_message})
        
        if is_scam:
            return self.generate_response(session_id, scammer_message, message_count)
        else:
            return self.generate_neutral_response(session_id, scammer_message)


# Single instance used across the app
agent = HoneypotAgent()
