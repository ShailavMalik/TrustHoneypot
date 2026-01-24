"""
API Key authentication middleware
Keeps our honeypot secure - only authorized users can access it!
"""
from fastapi import Security, HTTPException, status
from fastapi.security import APIKeyHeader
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# The header name we're looking for in requests
API_KEY_NAME = "x-api-key"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

# Get the valid API key from environment (or use a default for testing)
VALID_API_KEY = os.getenv("API_KEY", "default-hackathon-key-2026")


async def verify_api_key(api_key: str = Security(api_key_header)):
    """
    Check if the request has a valid API key.
    
    Think of this like a bouncer at a club - no valid key, no entry!
    
    Args:
        api_key: The API key from the 'x-api-key' header in the request
        
    Returns:
        The API key if it's valid
        
    Raises:
        HTTPException: If the key is missing or wrong (401 Unauthorized)
    """
    # Did they forget to include the key?
    if api_key is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API key. Please provide 'x-api-key' header."
        )
    
    # Is the key wrong?
    if api_key != VALID_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key"
        )
    
    # All good! Let them through
    return api_key
