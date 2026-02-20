# Honeypot API

## Description

An intelligent scam-detection honeypot API that acts as a convincing victim persona to waste scammers' time while extracting actionable intelligence. The system detects scam tactics in real-time, adaptively engages the scammer through a 5-stage conversation progression, and extracts identifiers like phone numbers, bank accounts, and UPI IDs — all reported through a structured callback payload.

**Strategy:** Rather than immediately blocking scammers, the honeypot keeps them engaged in a realistic conversation, progressively probing for intelligence while maintaining the illusion of a confused, elderly victim. A deep ML engine ranks response candidates for contextually appropriate replies.

## Tech Stack

- **Language:** Python 3.9+
- **Framework:** FastAPI (async ASGI) + Uvicorn
- **Validation:** Pydantic v2
- **ML Engine:** Custom neural architecture (numpy only, no GPU required)
  - TextEncoder (char-trigram + word-bigram hashing → 128-d vectors)
  - 4-Head Self-Attention for cross-feature interaction
  - GRU Cell for conversation state tracking (64-d hidden state)
  - Neural Intent Classifier (15 intent classes)
  - Engagement Scorer (3-layer feed-forward, 345→128→64→1)
- **Key Libraries:** requests, python-dotenv, numpy
- **Deployment:** Railway / any ASGI-compatible host

## Setup Instructions

### 1. Clone the repository

```bash
git clone <repo-url>
cd TrustHoneypot_API
```

### 2. Create and activate virtual environment

```bash
python -m venv .venv

# Windows PowerShell:
.\.venv\Scripts\Activate.ps1

# Linux/Mac:
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Set environment variables

```bash
cp .env.example .env
# Edit .env and set your API_KEY
```

### 5. Run the application

```bash
# Development (with auto-reload)
uvicorn src.main:app --reload --host 0.0.0.0 --port 8000

# Production
uvicorn src.main:app --host 0.0.0.0 --port 8000 --workers 4
```

**Windows shortcuts:**

```powershell
.\start_server.ps1
# or
start_server.bat
```

### Quick Verification

```bash
# Health check
curl http://localhost:8000/

# Should return: {"status": "online", "service": "Agentic Honey-Pot API", "version": "2.2.0"}
```

## API Endpoint

- **URL:** `https://your-deployed-url.com/honeypot`
- **Method:** POST
- **Authentication:** `x-api-key` header

### Request Format

```json
{
  "sessionId": "unique-session-id",
  "message": {
    "sender": "scammer",
    "text": "This is RBI. Your account will be blocked. Share OTP immediately."
  },
  "conversationHistory": [
    { "sender": "scammer", "text": "previous message..." }
  ]
}
```

### Response Format

```json
{
  "status": "success",
  "reply": "Hello? Who is this? I don't recognise this number."
}
```

### Health Check

- **URL:** `GET /`
- **Response:** `{"status": "online", "service": "Agentic Honey-Pot API", "version": "2.2.0"}`

## Approach

### How We Detect Scams

The detection engine scores messages through **20 signal layers** (12 core + 8 auxiliary) covering Indian scam categories:

| Signal Layer       | Examples                                     | Weight |
| ------------------ | -------------------------------------------- | ------ |
| Urgency            | "immediately", "last chance", "jaldi"        | 10-16  |
| Authority          | "RBI", "CBI", "Police", "Income Tax"         | 10-18  |
| OTP Request        | "share the OTP", "6-digit code"              | 18-25  |
| Payment Request    | "transfer now", "processing fee"             | 14-20  |
| Account Suspension | "account blocked", "KYC expired"             | 14-18  |
| Legal Threats      | "arrest warrant", "digital arrest"           | 14-20  |
| Phishing URLs      | bit.ly links, AnyDesk, suspicious TLDs       | 8-20   |
| + 13 more layers   | Courier, job fraud, investment, insurance... | 8-20   |

Cumulative scoring with **escalation bonuses** for compound signals ensures fast detection (threshold: 40 points).

### How We Extract Intelligence

**10 entity types** extracted via regex with canonical normalization:

- Phone numbers (Indian mobile/landline/toll-free) → `+91XXXXXXXXXX`
- Bank account numbers (9-18 digits, contextual matching)
- UPI IDs (80+ known Indian UPI providers)
- Email addresses, phishing URLs
- Aadhaar numbers, PAN cards, IFSC codes
- Fake case IDs, policy numbers, order numbers

### How We Maintain Engagement

**5-stage adaptive persona** that progresses based on risk score:

1. **Confused** — "Who is this? I don't recognise this number."
2. **Verifying** — "Can you give me your employee ID and callback number?"
3. **Concerned** — "You're worrying me. Let me call my son first."
4. **Cooperative** — "Okay, give me the complete account details slowly."
5. **Extracting** — "I have my banking app open. What is the UPI ID?"

**ML-powered response ranking:** A custom neural engine (TextEncoder → Self-Attention → GRU → Intent Classifier → Engagement Scorer) selects the most contextually appropriate response from 200+ templates.

**Quality assurance:** Conversation quality tracker ensures minimum thresholds (8 turns, 5 questions, 3 investigative probes, 5 red flag acknowledgments, 5 elicitation attempts) are met before the final callback is sent.

## Project Structure

```
TrustHoneypot_API/
├── README.md                     # This file — setup and usage instructions
├── requirements.txt              # Python dependencies
├── Procfile                      # Railway/Heroku deployment config
├── .env.example                  # Environment variables template
├── start_server.ps1              # Windows PowerShell start script
├── start_server.bat              # Windows CMD start script
├── src/                          # Source code
│   ├── __init__.py               # Package initialization
│   ├── main.py                   # FastAPI app + request pipeline orchestrator
│   ├── agent.py                  # 5-stage engagement controller (honeypot logic)
│   ├── detector.py               # 20-layer scam risk scoring engine
│   ├── extractor.py              # Regex intelligence extraction (10 entity types)
│   ├── engagement_ml.py          # Deep ML engine (neural response ranking)
│   ├── conversation_quality.py   # Quality threshold tracker
│   ├── callback.py               # Callback builder + async sender
│   ├── memory.py                 # Thread-safe session state store
│   ├── models.py                 # Pydantic request/response schemas
│   └── auth.py                   # API key authentication
└── docs/                         # Additional documentation
    └── architecture.md           # System architecture deep-dive
```

## Testing

```bash
# Run scenario tests
python test_scenarios.py

# Run detection accuracy tests
python test_detection.py

# Run false positive tests
python test_false_positive.py

# Run full evaluation scoring
python self_test_eval.py
```

## Deployment

### Railway

The `Procfile` is pre-configured:

```
web: uvicorn src.main:app --host 0.0.0.0 --port $PORT
```

Set these environment variables in Railway:

- `API_KEY` — your API key
- `CALLBACK_URL` — evaluation endpoint URL

## Dependencies

| Package           | Version | Purpose                       |
| ----------------- | ------- | ----------------------------- |
| fastapi           | 0.115.0 | ASGI web framework            |
| uvicorn           | 0.32.1  | ASGI server                   |
| pydantic          | 2.10.3  | Request/response validation   |
| pydantic-settings | 2.6.1   | Settings management           |
| python-dotenv     | 1.0.1   | Environment variable loading  |
| requests          | 2.32.3  | HTTP client for callbacks     |
| numpy             | ≥2.0.0  | ML engine (optional fallback) |
