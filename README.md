# Agentic Honey-Pot API

**Scam Detection, Engagement & Intelligence Extraction System**

Built for the **India AI Impact Buildathon (GUVI)** — Problem Statement 2

---

## What it does

A **FastAPI** backend that acts as an intelligent honeypot for phone/SMS scammers:

1. **Detects scams** — 9-layer risk scoring engine with cumulative scoring
2. **Engages the scammer** — 5-stage adaptive persona (confused elderly Indian victim)
3. **Extracts intelligence** — Phones, bank accounts, UPI IDs, URLs, emails
4. **Reports to evaluator** — Sends structured callback to GUVI endpoint on every eligible turn

Response format:

```json
{ "status": "success", "reply": "Hello? Who is this?" }
```

---

## Project Structure

```
app/
├── main.py          # FastAPI routes + pipeline
├── auth.py          # API key auth (x-api-key header)
├── models.py        # Pydantic schemas
├── detector.py      # Multi-layer risk scoring
├── extractor.py     # Regex intelligence extraction
├── agent.py         # 5-stage engagement controller
├── memory.py        # Thread-safe session store
└── callback.py      # Callback builder + sender
```

---

## Setup & Run

### Prerequisites

- Python 3.9+

### Install

```bash
git clone <repo-url> && cd TrustHoneypot_API
python -m venv venv

# Windows PowerShell:
.\venv\Scripts\Activate.ps1
# Linux/Mac:
source venv/bin/activate

pip install -r requirements.txt
cp .env.example .env
# Edit .env and set your API_KEY
```

### Run locally

```bash
# Development (with auto-reload)
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# Production
uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4
```

**Windows shortcut:**

```powershell
.\start_server.ps1
# or
start_server.bat
```

- API: http://localhost:8000
- Docs: http://localhost:8000/docs
- Health: http://localhost:8000/

---

## Testing

### Quick health check

```bash
curl http://localhost:8000/
```

### Single-turn test

```bash
curl -X POST http://localhost:8000/honeypot \
  -H "x-api-key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "sessionId": "test-001",
    "message": {
      "sender": "scammer",
      "text": "This is RBI. Your account will be blocked. Share OTP immediately."
    },
    "conversationHistory": []
  }'
```

### Multi-turn test (Python)

```bash
python test_scenarios.py
```

This runs a full 6-turn scam simulation and prints detection results, extracted intelligence, and engagement quality.

### Other test files

| File                         | Purpose                  |
| ---------------------------- | ------------------------ |
| `test_detection.py`          | Scam detection accuracy  |
| `test_false_positive.py`     | False positive rate      |
| `test_multiturn_callback.py` | Multi-turn callback flow |
| `quick_test.py`              | Quick smoke test         |
| `validate.py`                | Full validation suite    |

### Run evaluation scoring

```bash
python self_test_eval.py
```

Reports a detailed score breakdown (detection + extraction + engagement + structure = /100).

---

## API Reference

### `GET /`

Returns: `{ "status": "online", "service": "Agentic Honey-Pot API", "version": "2.0.0" }`

### `POST /honeypot`

**Headers:** `x-api-key: <key>`, `Content-Type: application/json`

**Body:**

```json
{
  "sessionId": "unique-id",
  "message": { "sender": "scammer", "text": "..." },
  "conversationHistory": [
    { "sender": "scammer", "text": "...", "timestamp": "..." }
  ]
}
```

**Response:** `{ "status": "success", "reply": "..." }`

---

## Deployment (Railway)

```
web: uvicorn app.main:app --host 0.0.0.0 --port $PORT
```

Set `API_KEY` and `CALLBACK_URL` in Railway environment variables.

---

## Scoring Breakdown

| Category                | Points | How                                                       |
| ----------------------- | ------ | --------------------------------------------------------- |
| Scam Detection          | 20     | Fires on first scammer turn; correct type                 |
| Intelligence Extraction | 40     | Multi-format phones, filtered banks, UPI + email          |
| Engagement Quality      | 20     | >= 5 messages, >= 60s duration, unique replies            |
| Response Structure      | 20     | `{status, reply}` only; `"status": "success"` in callback |

---

## Dependencies

fastapi 0.115.0 · uvicorn 0.32.1 · pydantic 2.10.3 · pydantic-settings 2.6.1 · python-dotenv 1.0.1 · requests 2.32.3

---

_Built for the India AI Impact Buildathon (GUVI) 2026._
