"""
Data models for the Honeypot API.
Using Pydantic for validation - it catches bad data before it causes problems.
"""
from pydantic import BaseModel, Field, field_validator
from pydantic import ConfigDict
from typing import List, Optional, Union


class Message(BaseModel):
    """A single message in the conversation.
    
    Notes:
    - Some external testers may omit `sender` in history items. We default to
      'scammer' to be permissive and avoid 422s for missing keys.
    - `sender` can be 'scammer' or 'agent' (we only act on 'scammer').
    - `timestamp` can be int (Unix millis) or str (ISO-8601); we convert to str.
    """
    model_config = ConfigDict(extra="ignore")  # ignore unexpected fields
    sender: Optional[str] = Field(default="scammer")  # default for leniency
    text: str
    timestamp: Optional[Union[str, int]] = None  # Accept both string and int
    
    @field_validator('timestamp', mode='before')
    @classmethod
    def convert_timestamp(cls, v):
        """Convert numeric timestamps to string for consistency."""
        if isinstance(v, (int, float)):
            return str(int(v))
        return v


class Metadata(BaseModel):
    """Optional context about the message channel."""
    channel: str = "SMS"  # SMS, WhatsApp, Email, Chat
    language: str = "English"
    locale: str = "IN"


class HoneypotRequest(BaseModel):
    """
    Incoming request from the GUVI evaluation platform.
    
    The platform sends scam messages here for our system to analyze
    and respond to. Each request has a sessionId to track multi-turn
    conversations with the same scammer.
    """
    model_config = ConfigDict(extra="ignore")  # tolerate extra fields from testers
    sessionId: str
    message: Message
    conversationHistory: List[Message] = Field(default_factory=list)
    metadata: Optional[Metadata] = None  # Optional as per GUVI docs


class ExtractedIntelligence(BaseModel):
    """
    All the useful info we managed to extract from the scammer.
    This is what helps authorities track these guys down.
    """
    bankAccounts: List[str] = Field(default_factory=list)
    upiIds: List[str] = Field(default_factory=list)
    phishingLinks: List[str] = Field(default_factory=list)
    phoneNumbers: List[str] = Field(default_factory=list)
    suspiciousKeywords: List[str] = Field(default_factory=list)


class EngagementMetrics(BaseModel):
    """How well did we keep the scammer talking?"""
    engagementDurationSeconds: int
    totalMessagesExchanged: int


class HoneypotResponse(BaseModel):
    """Response format matching GUVI's expected schema exactly."""
    status: str
    scamDetected: bool
    engagementMetrics: EngagementMetrics
    extractedIntelligence: ExtractedIntelligence
    agentNotes: str


class CallbackPayload(BaseModel):
    """
    Payload for the mandatory GUVI callback.
    We send this when we've gathered enough intel on a confirmed scam.
    """
    sessionId: str
    scamDetected: bool
    totalMessagesExchanged: int
    extractedIntelligence: ExtractedIntelligence
    agentNotes: str
