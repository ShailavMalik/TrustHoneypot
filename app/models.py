"""Pydantic request/response models for the Honeypot API."""

from pydantic import BaseModel, Field, field_validator, ConfigDict
from typing import List, Optional, Union


class Message(BaseModel):
    """Single chat message in a conversation."""

    model_config = ConfigDict(extra="ignore")

    sender: Optional[str] = Field(default="scammer")
    text: str = Field(...)
    timestamp: Optional[Union[str, int]] = Field(default=None)

    @field_validator("timestamp", mode="before")
    @classmethod
    def _coerce_timestamp(cls, value):
        """Evaluator sometimes sends epoch ints — normalize to string."""
        if isinstance(value, (int, float)):
            return str(int(value))
        return value


class Metadata(BaseModel):
    """Optional channel/locale context (informational only)."""

    model_config = ConfigDict(extra="ignore")

    channel: str = Field(default="SMS")
    language: str = Field(default="English")
    locale: str = Field(default="IN")


class HoneypotRequest(BaseModel):
    """Incoming payload on POST /honeypot."""

    model_config = ConfigDict(extra="ignore")

    sessionId: str = Field(...)
    message: Message = Field(...)
    conversationHistory: List[Message] = Field(default_factory=list)
    metadata: Optional[Metadata] = Field(default=None)
    timestamp: Optional[Union[str, int]] = Field(default=None)


class HoneypotResponse(BaseModel):
    """Response returned to the caller — only status + reply, nothing internal."""

    status: str = Field(...)
    reply: str = Field(...)


# Callback payload models (used internally)

class ExtractedIntelligence(BaseModel):
    phoneNumbers: List[str] = Field(default_factory=list)
    bankAccounts: List[str] = Field(default_factory=list)
    upiIds: List[str] = Field(default_factory=list)
    phishingLinks: List[str] = Field(default_factory=list)
    emailAddresses: List[str] = Field(default_factory=list)


class EngagementMetrics(BaseModel):
    totalMessagesExchanged: int = Field(default=0)
    engagementDurationSeconds: int = Field(default=0)


class FinalOutput(BaseModel):
    """Full callback payload sent to the GUVI evaluation endpoint."""

    sessionId: str
    status: str = "success"
    scamDetected: bool = False
    scamType: str = "unknown"
    extractedIntelligence: ExtractedIntelligence = Field(default_factory=ExtractedIntelligence)
    engagementMetrics: EngagementMetrics = Field(default_factory=EngagementMetrics)
    agentNotes: str = ""
