"""
The Agent - our fake victim persona that engages with scammers.

This is the heart of the honeypot. When we detect a scam, we don't just
block it - we play along. The agent pretends to be a confused, elderly,
or tech-unsavvy person who might actually fall for the scam.

Why? Because the longer we keep them talking, the more intel we extract.
Phone numbers, bank accounts, UPI IDs - scammers eventually give these up
when they think they've got a real victim on the hook.

The responses are designed to be believable. No one talks like a robot.
"""
import random
from typing import Dict, List, Optional
from app.detector import detector


class HoneypotAgent:
    """
    Generates human-like responses to keep scammers engaged.
    
    The persona is someone who:
    - Is confused but not completely clueless
    - Asks lots of questions (this makes scammers reveal more)
    - Shows concern but doesn't immediately comply
    - Stalls for time with believable excuses
    - Never reveals that we know it's a scam
    """
    
    # Neutral responses for non-scam / uncertain cases
    NEUTRAL_RESPONSES = [
        "Hello? I think you may have the wrong number.",
        "Sorry, I'm not sure what this is about. Can you explain?",
        "I don't recognize this. Who is this?",
        "I'm not sure I understand. What are you referring to?",
        "Hmm, I don't recall anything about this. Are you sure you have the right person?",
        "Ji? Kaun bol raha hai?",
        "Aap kaun? Main samjha nahi.",
        "Sorry, wrong number I think. Please check once.",
    ]
    
    # First contact - we're confused, who is this?
    INITIAL_RESPONSES = [
        "Hello? Who is this calling?",
        "Sorry, I don't understand. What is this regarding?",
        "I didn't get any notification about this. Are you sure you have the right person?",
        "What? My account? Which account are you talking about?",
        "I'm confused. Can you please explain from the beginning?",
        "Ji? Kaun bol raha hai? Main samjha nahi.",
        "Wait wait, please speak slowly. I am not understanding properly.",
        "Hello? Is this some kind of company call? What do you want?",
        "Arey, I didn't apply for anything. What are you saying?",
        "One minute, let me sit down first. My knees are paining. Now tell me clearly.",
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
        "UPI? Is that same as BHIM app? My grandson installed something on my phone.",
        "Google Pay is showing some error. Can I do by NEFT instead?",
        "Sir my OTP is not coming. Network is weak in my area. Can you wait?",
        "How to check my bank balance? Let me open the app... it's asking for fingerprint...",
        "I don't know how to do screen share. My camera is not working properly.",
        "Can you send me the UPI ID on WhatsApp? I can't hear properly on call.",
        "Sir the app is showing 'insufficient balance'. I need to transfer from FD first.",
        "Wait, which app to open? I have Paytm, PhonePe, and BHIM all three.",
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
        
        if any(w in msg for w in ["urgent", "immediate", "now", "hurry", "quickly", "jaldi", "turant"]):
            tactics.append("urgency")
        if any(w in msg for w in ["verify", "kyc", "update", "confirm", "suspended", "blocked"]):
            tactics.append("verification")
        if any(w in msg for w in ["refund", "prize", "won", "reward", "cashback", "lottery", "winner"]):
            tactics.append("payment_lure")
        if any(w in msg for w in ["police", "legal", "arrest", "court", "case", "warrant", "cbi", "ed", "jail"]):
            tactics.append("threat")
        if any(w in msg for w in ["upi", "account", "transfer", "pay", "send", "bhim", "paytm", "phonepe", "gpay"]):
            tactics.append("payment_request")
        if any(w in msg for w in ["video call", "digital arrest", "stay on call", "don't disconnect", "skype", "zoom"]):
            tactics.append("digital_arrest")
        if any(w in msg for w in ["parcel", "courier", "package", "customs", "fedex", "dhl", "drugs", "contraband"]):
            tactics.append("courier")
        if any(w in msg for w in ["otp", "password", "pin", "cvv", "card number", "debit card", "credit card"]):
            tactics.append("credential")
            
        return tactics
    
    def generate_response(self, session_id: str, scammer_message: str, message_count: int) -> str:
        """
        Generate a believable human response.
        
        The response depends on:
        - How many messages we've exchanged
        - What tactics the scammer is using
        - What we've already said (to avoid repetition)
        - Conversation escalation level (adapts dynamically)
        - Previous context from conversation history
        - Specific scam type detected
        """
        context = self._get_context(session_id)
        tactics = self._detect_tactics(scammer_message)
        context["detected_tactics"].update(tactics)
        
        # Track last tactic for continuity
        if tactics:
            context["last_tactic"] = tactics[-1]
        
        # Update escalation level based on current message
        if "threat" in tactics or "digital_arrest" in tactics:
            context["escalation_level"] = 3
        elif "payment_request" in tactics and context["escalation_level"] < 2:
            context["escalation_level"] = 2
        elif context["escalation_level"] == 0 and tactics:
            context["escalation_level"] = 1
        
        escalation = context["escalation_level"]
        
        # Dynamic response selection based on context and scam type
        if message_count <= 1:
            # First message - always confused
            pool = self.INITIAL_RESPONSES
        elif "digital_arrest" in tactics:
            # Digital arrest scam - very common, show extreme fear and compliance
            pool = self.DIGITAL_ARREST_RESPONSES
        elif "courier" in tactics:
            # Courier/parcel scam - deny knowledge, show confusion
            pool = self.COURIER_RESPONSES
        elif "credential" in tactics:
            # They want OTP/credentials - technical confusion
            pool = self.TECH_CONFUSION_RESPONSES
        elif escalation >= 3 or "threat" in tactics:
            # They're threatening - show fear
            if message_count > 4 and random.random() > 0.4:
                # Sometimes show compliance after extended fear
                pool = self.COMPLIANT_RESPONSES
            else:
                pool = self.FEARFUL_RESPONSES
        elif context["intel_requested"] or message_count > 5:
            # We've been engaging a while - mix of detail seeking and tech confusion
            if random.random() > 0.5:
                pool = self.DETAIL_SEEKING
            else:
                pool = self.TECH_CONFUSION_RESPONSES
        elif "payment_request" in tactics or escalation >= 2:
            # They want money/payment - time to extract intel
            pool = self.DETAIL_SEEKING
            context["intel_requested"] = True
        elif "payment_lure" in tactics:
            # They're offering money - be skeptical but curious
            pool = self.PAYMENT_RESPONSES
        elif "verification" in tactics:
            # They want to verify something - be cautious
            pool = self.VERIFICATION_RESPONSES
        elif "urgency" in tactics and escalation >= 1:
            # Urgent but not threatening - stall
            pool = self.STALLING_RESPONSES
        else:
            # Default - mix of stalling and verification
            if random.random() > 0.5:
                pool = self.STALLING_RESPONSES
            else:
                pool = self.VERIFICATION_RESPONSES
        
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
            return f"{risk_emoji} Monitoring. Risk score: {score} (threshold: 30). Confidence: {confidence*100:.0f}%"
        else:
            return f"{risk_emoji} Suspicious activity detected. Score: {score}. Awaiting confirmation threshold."
    
    def generate_neutral_response(self, session_id: str, scammer_message: str = "") -> str:
        """
        Generate a neutral response for non-scam or uncertain cases.
        
        Returns a cautious, human-like reply without revealing detection status.
        """
        context = self._get_context(session_id)
        
        # Still analyze tactics even for non-scam to stay contextual
        if scammer_message:
            tactics = self._detect_tactics(scammer_message)
            context["detected_tactics"].update(tactics)
            context["conversation_history"].append({"role": "scammer", "text": scammer_message})
        
        available = [r for r in self.NEUTRAL_RESPONSES if r not in context["responses_given"]]
        if not available:
            available = self.NEUTRAL_RESPONSES
        
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
