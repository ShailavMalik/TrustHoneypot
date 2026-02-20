"""
auth.py — API Key Authentication Middleware
============================================

Provides x-api-key header-based authentication for the /honeypot endpoint.
The API key is loaded from the API_KEY environment variable (via .env file).

Usage:
    @app.post("/honeypot")
    async def endpoint(api_key: str = Depends(verify_api_key)):
        ...

Security notes:
    - Returns HTTP 401 if key is missing or invalid
    - Key comparison is exact string match (timing-safe optional for production)
    - Default key provided for local development only
"""

from fastapi import Security, HTTPException, status
from fastapi.security import APIKeyHeader
import os
from dotenv import load_dotenv

# Load environment variables from .env file (if present)
load_dotenv()

# Header name expected by the evaluator / client
API_KEY_NAME = "x-api-key"

# FastAPI security dependency — extracts the key from the request header
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

# The valid API key loaded from environment; falls back to default for local dev
VALID_API_KEY: str = os.getenv("API_KEY", "default-hackathon-key-2026")


async def verify_api_key(api_key: str = Security(api_key_header)) -> str:
    """Validate x-api-key header against the configured VALID_API_KEY.
    
    Args:
        api_key: The API key extracted from the request header by FastAPI.
    
    Returns:
        The validated API key string.
    
    Raises:
        HTTPException(401): If the key is missing or does not match.
    """
    # Check if the header was provided at all
    if api_key is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API key. Please provide the 'x-api-key' header.",
        )

    # Validate the key matches our expected value
    if api_key != VALID_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key.",
        )

    return api_key  # Pass the validated key downstream
