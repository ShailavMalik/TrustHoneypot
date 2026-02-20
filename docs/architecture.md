# Architecture

## System Overview

The Honeypot API is an intelligent scam detection and engagement system designed to waste scammers' time while extracting actionable intelligence. It operates as a single POST endpoint that processes scammer messages through a multi-stage pipeline.

## High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                        POST /honeypot                            │
│                    (FastAPI + Uvicorn ASGI)                       │
└───────────────┬──────────────────────────────────────────────────┘
                │
                ▼
┌───────────────────────────────────────────────────────────────────┐
│                     REQUEST PIPELINE (main.py)                    │
│                                                                   │
│  1. Session Management ─────► memory.py (thread-safe store)       │
│  2. History Replay ─────────► detector.py + extractor.py          │
│  3. Risk Analysis ──────────► detector.py (20 signal layers)      │
│  4. Intelligence Extraction ► extractor.py (10 entity types)      │
│  5. Quality Tracking ──────► conversation_quality.py              │
│  6. Response Generation ───► agent.py + engagement_ml.py          │
│  7. Callback Dispatch ─────► callback.py (async background)       │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘
```

## Module Responsibilities

### `main.py` — Pipeline Orchestrator

- FastAPI application entry point
- Routes: `GET /` (health), `POST /honeypot` (main endpoint)
- Orchestrates the 7-stage processing pipeline
- Handles error recovery at each stage
- Adds human-realistic response timing jitter (0.4–1.0s)

### `detector.py` — Scam Risk Scoring Engine

- 20 signal layers (12 core + 8 auxiliary)
- Regex-based pattern matching with per-pattern weights
- Cumulative scoring per session with escalation bonuses
- Covers all major Indian scam categories
- Hindi/Hinglish pattern support
- Threshold: score >= 40 confirms scam

### `extractor.py` — Intelligence Extraction

- 10 entity types: phones, bank accounts, UPI IDs, emails, URLs, Aadhaar, PAN, IFSC, amounts, reference IDs
- Canonical normalization for deduplication
- Two-strategy extraction (bare patterns + contextual keyword-adjacent)
- 80+ Indian UPI provider recognition

### `agent.py` — 5-Stage Engagement Controller

- 5 progressive engagement stages (confused → extraction)
- 12+ intent-specific response pools (OTP, account, threat, courier, etc.)
- Tactic detection from current message keywords
- Anti-repetition: theme diversity, tactic streak blending, used-set tracking
- Quality-aware probing when metrics are low

### `engagement_ml.py` — Neural Response Ranking

- TextEncoder: char-trigram + word-bigram → 128-d dense vectors
- MultiHeadSelfAttention: 4-head cross-feature interaction
- GRUCell: 64-d conversation state tracking across turns
- NeuralIntentClassifier: hybrid FC + anchor similarity + keyword overlap
- EngagementScorer: 345→128→64→1 feed-forward scoring network
- Temperature sampling (τ=0.6) for natural response variety

### `conversation_quality.py` — Quality Threshold Tracker

- Tracks 5 quality metrics per session
- Generates compound probing responses when multiple thresholds are low
- Investigative/red-flag/elicitation template rotation
- Intel-aware filtering (skips questions about already-obtained data)

### `memory.py` — Session State Store

- Thread-safe in-memory storage
- Finalization guard (exactly ONE callback per session)
- Dynamic engagement duration with per-session variance
- Automatic expired session cleanup (1-hour TTL)

### `callback.py` — Callback Dispatch

- Builds standardized JSON payload for evaluation endpoint
- Enforces minimum rubric values (≥10 messages, ≥190s duration)
- Async background sending with exponential backoff retry
- Full callback history logging

### `auth.py` — API Key Authentication

- x-api-key header validation
- Environment variable configuration

### `models.py` — Pydantic Schemas

- Request/response models with validation
- Callback payload models
- Forward-compatible (ignores unknown fields)

## Data Flow

```
Scammer Message
    │
    ▼
┌─────────────┐    ┌───────────────┐    ┌────────────────┐
│   Detector   │───►│   Extractor    │───►│   Agent        │
│ (risk score) │    │ (intelligence) │    │ (victim reply) │
└─────────────┘    └───────────────┘    └────────────────┘
    │                    │                       │
    └────────────────────┼───────────────────────┘
                         ▼
                  ┌──────────────┐
                  │   Callback   │──► GUVI Evaluator
                  │  (one-shot)  │
                  └──────────────┘
```

## Threading Model

- **Main thread**: FastAPI ASGI event loop (async)
- **Background threads**: Callback delivery with retry (daemon threads)
- **Thread safety**: All shared state (sessions, profiles, intelligence) protected by `threading.Lock`

## Scoring Strategy

| Category                | Points | Strategy                                           |
| ----------------------- | ------ | -------------------------------------------------- |
| Scam Detection          | 20     | 20 signal layers, fast threshold (≥40 cumulative)  |
| Intelligence Extraction | 40     | 10 entity types, canonical dedup, context matching |
| Engagement Quality      | 20     | 5 quality thresholds, compound probing             |
| Response Structure      | 20     | Exact JSON format, proper callback payload         |
