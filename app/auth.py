"""API key authentication via the x-api-key header."""

from fastapi import Security, HTTPException, status
from fastapi.security import APIKeyHeader
import os
from dotenv import load_dotenv

load_dotenv()

API_KEY_NAME = "x-api-key"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)
VALID_API_KEY: str = os.getenv("API_KEY", "default-hackathon-key-2026")


async def verify_api_key(api_key: str = Security(api_key_header)) -> str:
    """Validate x-api-key header. Returns 401 if missing or wrong."""
    if api_key is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API key. Please provide the 'x-api-key' header.",
        )

    if api_key != VALID_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key.",
        )

    return api_key
