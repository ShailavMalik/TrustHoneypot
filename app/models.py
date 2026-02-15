"""
Pydantic data models for the Honeypot API (Phase 2).
Strict validation with permissive defaults for evaluation compatibility.
"""
from pydantic import BaseModel, Field, field_validator, ConfigDict
from typing import List, Optional, Union


class Message(BaseModel):
    """A single message in the conversation."""
    model_config = ConfigDict(extra="ignore")
    sender: Optional[str] = Field(default="scammer")
    text: str
    timestamp: Optional[Union[str, int]] = None

    @field_validator("timestamp", mode="before")
    @classmethod
    def convert_timestamp(cls, v):
        if isinstance(v, (int, float)):
            return str(int(v))
        return v


class Metadata(BaseModel):
    """Optional context about the message channel."""
    model_config = ConfigDict(extra="ignore")
    channel: str = "SMS"
    language: str = "English"
    locale: str = "IN"


class HoneypotRequest(BaseModel):
    """Incoming request from the evaluation platform."""
    model_config = ConfigDict(extra="ignore")
    sessionId: str
    message: Message
    conversationHistory: List[Message] = Field(default_factory=list)
    metadata: Optional[Metadata] = None
    timestamp: Optional[Union[str, int]] = None


class ExtractedIntelligence(BaseModel):
    """Intelligence gathered from the scammer during engagement."""
    phoneNumbers: List[str] = Field(default_factory=list)
    bankAccounts: List[str] = Field(default_factory=list)
    upiIds: List[str] = Field(default_factory=list)
    phishingLinks: List[str] = Field(default_factory=list)
    emailAddresses: List[str] = Field(default_factory=list)


class EngagementMetrics(BaseModel):
    """Engagement quality metrics."""
    totalMessagesExchanged: int = 0
    engagementDurationSeconds: int = 0


class HoneypotResponse(BaseModel):
    """Simplified API response – never exposes detection internals."""
    status: str
    reply: str


class FinalOutput(BaseModel):
    """Complete analysis payload sent via callback."""
    sessionId: str
    status: str = "success"
    scamDetected: bool = False
    scamType: str = "unknown"
    extractedIntelligence: ExtractedIntelligence = Field(default_factory=ExtractedIntelligence)
    engagementMetrics: EngagementMetrics = Field(default_factory=EngagementMetrics)
    agentNotes: str = ""
