"""
Data models for the Honeypot API.
Using Pydantic for validation - it catches bad data before it causes problems.
"""
from pydantic import BaseModel, Field
from typing import List, Optional


class Message(BaseModel):
    """A single message in the conversation."""
    sender: str  # Either 'scammer' or 'user'
    text: str
    timestamp: Optional[str] = None  # ISO-8601 format, optional for flexibility


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
