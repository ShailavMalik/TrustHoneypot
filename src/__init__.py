"""
Honeypot API — Source Package
==============================

This package contains all core modules for the scam-detection honeypot system:
    - main.py               : FastAPI application entry point and request pipeline
    - agent.py              : 5-stage adaptive engagement controller
    - auth.py               : API key authentication middleware
    - callback.py           : Callback payload builder and async sender
    - conversation_quality.py : Quality threshold tracker for scoring compliance
    - detector.py           : Multi-layer risk scoring engine (20 signal layers)
    - engagement_ml.py      : Deep ML engine for neural response ranking
    - extractor.py          : Regex-based intelligence extraction (10 entity types)
    - memory.py             : Thread-safe in-memory session store
    - models.py             : Pydantic request/response schemas
"""
