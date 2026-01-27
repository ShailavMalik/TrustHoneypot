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
    
    # First contact - we're confused, who is this?
    INITIAL_RESPONSES = [
        "Hello? Who is this?",
        "Sorry, I don't understand. What is this about?",
        "I didn't get any notification about this. Are you sure you have the right person?",
        "What? My account? Which account are you talking about?",
        "I'm confused. Can you explain from the beginning?",
        "Is this some kind of prank? Who gave you my number?"
    ]
    
    # When they mention account issues, verification, KYC
    VERIFICATION_RESPONSES = [
        "But I just updated my KYC last month at the bank branch. Why again?",
        "This is very strange. My bank never calls me like this.",
        "How do I know you're really from the bank? Anyone could say that.",
        "Can you give me your employee ID? I want to verify first.",
        "I'm worried this might be fraud. Can I call the bank directly?",
        "My son told me never to share details on phone. Is there another way?",
        "Wait, let me note this down. What exactly do you need?"
    ]
    
    # When they mention money, prizes, refunds
    PAYMENT_RESPONSES = [
        "Really? I won something? I don't remember entering any contest.",
        "A refund? But I haven't complained about anything recently.",
        "How much money are we talking about? This sounds too good to be true.",
        "Why do you need my bank details to give ME money? That doesn't make sense.",
        "Can you send me something in writing first? An email maybe?",
        "My neighbor got cheated last week with a similar call. Are you genuine?",
        "I need to think about this. Can you call back tomorrow?"
    ]
    
    # Stalling - we're busy, technology problems, etc.
    STALLING_RESPONSES = [
        "Hold on, someone is at the door.",
        "Can you wait? I need to find my reading glasses.",
        "My phone battery is very low. Let me put it on charge first.",
        "I'm in the middle of cooking. Can this wait 10 minutes?",
        "Let me call my son first. He handles all these things for me.",
        "Sorry, the network is bad here. Can you repeat that?",
        "I'm not at home right now. When can you call back?"
    ]
    
    # Asking for more details - this is how we extract intel
    DETAIL_SEEKING = [
        "Okay, but what exactly should I do? Give me step by step.",
        "Which number should I send the money to? Write it clearly.",
        "What is your UPI ID? I'll try to send a small amount first to check.",
        "Give me the account number again slowly. I'm writing it down.",
        "And what is the IFSC code? I need that too right?",
        "Can you share a link? I find it easier to do online.",
        "What's your office number? I want to call and verify."
    ]
    
    # Showing fear/concern when they threaten
    FEARFUL_RESPONSES = [
        "Please don't involve police! I'll cooperate. What do I do?",
        "Oh no, I didn't know this was so serious. Please help me fix this.",
        "I don't want any legal trouble. Just tell me what to do.",
        "You're scaring me. Is there really a case against me?",
        "I'm a senior citizen, please have some patience with me.",
        "My husband passed away last year. I handle everything alone now. Please guide me."
    ]
    
    # Risk level emojis for notes
    RISK_EMOJIS = {
        "minimal": "⚪",
        "low": "🟢",
        "medium": "🟡",
        "high": "🟠",
        "critical": "🔴"
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
                "detected_tactics": set()
            }
        return self.session_context[session_id]
    
    def _detect_tactics(self, message: str) -> List[str]:
        """Figure out what scam tactics they're using."""
        tactics = []
        msg = message.lower()
        
        if any(w in msg for w in ["urgent", "immediate", "now", "hurry", "quickly"]):
            tactics.append("urgency")
        if any(w in msg for w in ["verify", "kyc", "update", "confirm", "suspended", "blocked"]):
            tactics.append("verification")
        if any(w in msg for w in ["refund", "prize", "won", "reward", "cashback", "lottery"]):
            tactics.append("payment_lure")
        if any(w in msg for w in ["police", "legal", "arrest", "court", "case", "warrant"]):
            tactics.append("threat")
        if any(w in msg for w in ["upi", "account", "transfer", "pay", "send"]):
            tactics.append("payment_request")
            
        return tactics
    
    def generate_response(self, session_id: str, scammer_message: str, message_count: int) -> str:
        """
        Generate a believable human response.
        
        The response depends on:
        - How many messages we've exchanged
        - What tactics the scammer is using
        - What we've already said (to avoid repetition)
        """
        context = self._get_context(session_id)
        tactics = self._detect_tactics(scammer_message)
        context["detected_tactics"].update(tactics)
        
        # Pick the right response category
        if message_count <= 1:
            pool = self.INITIAL_RESPONSES
        elif "threat" in tactics:
            pool = self.FEARFUL_RESPONSES
        elif "payment_request" in tactics or message_count > 4:
            # Time to ask for their details
            pool = self.DETAIL_SEEKING
        elif "payment_lure" in tactics:
            pool = self.PAYMENT_RESPONSES
        elif "verification" in tactics:
            pool = self.VERIFICATION_RESPONSES
        else:
            pool = self.STALLING_RESPONSES
        
        # Avoid repeating the same response
        available = [r for r in pool if r not in context["responses_given"]]
        if not available:
            available = pool  # Reset if we've used them all
        
        response = random.choice(available)
        context["responses_given"].append(response)
        
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


# Single instance used across the app
agent = HoneypotAgent()
