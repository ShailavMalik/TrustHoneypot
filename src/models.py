"""
models.py — Pydantic Request/Response Schemas
===============================================

Defines the data models for the Honeypot API's HTTP interface and
internal callback payload structure.

Request flow:
    Client → HoneypotRequest (POST /honeypot) → Pipeline → HoneypotResponse

Callback flow:
    Pipeline → FinalOutput → GUVI Evaluation Endpoint

Design decisions:
    - All models use ConfigDict(extra="ignore") to silently drop unknown fields,
      ensuring forward compatibility with evolving evaluator payloads.
    - Timestamps accept both string and int (epoch) formats for flexibility.
    - Response model is kept minimal (status + reply only) — no internal
      state leaks to the caller.
"""

from pydantic import BaseModel, Field, field_validator, ConfigDict
from typing import List, Optional, Union


# ═══════════════════════════════════════════════════════════════════════
# REQUEST MODELS — Incoming data from the evaluator / scammer client
# ═══════════════════════════════════════════════════════════════════════

class Message(BaseModel):
    """A single chat message within a conversation.
    
    Attributes:
        sender:    Who sent this message ('scammer' or 'agent'). Defaults to 'scammer'.
        text:      The actual message content. Required field.
        timestamp: Optional timestamp — accepts epoch ints (auto-coerced to string).
    """
    model_config = ConfigDict(extra="ignore")  # Ignore unexpected fields gracefully

    sender: Optional[str] = Field(default="scammer")
    text: str = Field(...)  # Required — the message body
    timestamp: Optional[Union[str, int]] = Field(default=None)

    @field_validator("timestamp", mode="before")
    @classmethod
    def _coerce_timestamp(cls, value):
        """Normalize epoch int timestamps to strings for consistent handling."""
        if isinstance(value, (int, float)):
            return str(int(value))
        return value


class Metadata(BaseModel):
    """Optional channel and locale context provided by the evaluator.
    
    Purely informational — does not affect pipeline behavior.
    """
    model_config = ConfigDict(extra="ignore")

    channel: str = Field(default="SMS")       # Communication channel (SMS, WhatsApp, etc.)
    language: str = Field(default="English")   # Primary language of the conversation
    locale: str = Field(default="IN")          # Geographic locale code


class HoneypotRequest(BaseModel):
    """Incoming POST /honeypot request payload.
    
    Attributes:
        sessionId:            Unique session identifier (required).
        message:              The current scammer message to process (required).
        conversationHistory:  Prior messages in this session for context replay.
        metadata:             Optional channel/locale info.
        timestamp:            Optional request-level timestamp.
    """
    model_config = ConfigDict(extra="ignore")

    sessionId: str = Field(...)                                  # Session tracking ID
    message: Message = Field(...)                                # Current message to process
    conversationHistory: List[Message] = Field(default_factory=list)  # Prior conversation turns
    metadata: Optional[Metadata] = Field(default=None)           # Channel context (optional)
    timestamp: Optional[Union[str, int]] = Field(default=None)   # Request timestamp (optional)


# ═══════════════════════════════════════════════════════════════════════
# RESPONSE MODEL — Returned to the caller
# ═══════════════════════════════════════════════════════════════════════

class HoneypotResponse(BaseModel):
    """Response returned to the caller — only status + reply, nothing internal.
    
    The evaluator expects exactly this format:
        {"status": "success", "reply": "<agent_response>"}
    """
    status: str = Field(...)   # Always "success" (even on internal errors)
    reply: str = Field(...)    # The honeypot agent's response to the scammer


# ═══════════════════════════════════════════════════════════════════════
# CALLBACK PAYLOAD MODELS — Sent to the GUVI evaluation endpoint
# ═══════════════════════════════════════════════════════════════════════

class ExtractedIntelligence(BaseModel):
    """Intelligence extracted from scammer messages during the conversation.
    
    Contains 8 categories of identifiers that the agent successfully
    elicited from the scammer throughout the engagement.
    """
    phoneNumbers: List[str] = Field(default_factory=list)    # Indian mobile numbers (+91 format)
    bankAccounts: List[str] = Field(default_factory=list)    # Bank account numbers (9-18 digits)
    upiIds: List[str] = Field(default_factory=list)          # UPI VPAs (e.g., user@paytm)
    phishingLinks: List[str] = Field(default_factory=list)   # Suspicious URLs sent by scammer
    emailAddresses: List[str] = Field(default_factory=list)  # Email addresses provided by scammer
    caseIds: List[str] = Field(default_factory=list)         # Fake case/reference IDs
    policyNumbers: List[str] = Field(default_factory=list)   # Fake insurance/loan policy numbers
    orderNumbers: List[str] = Field(default_factory=list)    # Fake order/transaction references


class EngagementMetrics(BaseModel):
    """Quantitative metrics about the honeypot's engagement with the scammer."""
    totalMessagesExchanged: int = Field(default=0)       # Total messages in both directions
    engagementDurationSeconds: int = Field(default=0)    # Seconds the scammer was kept engaged


class FinalOutput(BaseModel):
    """Full callback payload sent to the GUVI evaluation endpoint.
    
    EXACT format required by the scoring rubric:
        - sessionId: string (unique session identifier)
        - scamDetected: boolean (was a scam detected?)
        - scamType: string (classification label, e.g., 'bank_fraud')
        - confidenceLevel: float [0.0, 1.0] (normalized risk score)
        - totalMessagesExchanged: number (>= 10 for rubric compliance)
        - extractedIntelligence: object with 8 identifier arrays
        - engagementMetrics: object with message count and duration
        - agentNotes: string (behavioral analysis summary)
    """
    sessionId: str                                                           # Session ID
    confidenceLevel: Optional[float] = Field(default=None, ge=0.0, le=1.0)  # Normalized confidence
    scamDetected: bool = False                                               # Scam detection flag
    scamType: str = "unknown"                                                # Scam classification type
    totalMessagesExchanged: int = 0                                          # Message count (top-level)
    extractedIntelligence: ExtractedIntelligence = Field(default_factory=ExtractedIntelligence)
    engagementMetrics: EngagementMetrics = Field(default_factory=EngagementMetrics)
    agentNotes: str = ""                                                     # Behavioral analysis notes
