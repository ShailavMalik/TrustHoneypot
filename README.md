# Agentic Honey-Pot API

**Scam Detection, ML-Powered Engagement & Intelligence Extraction System**

Built for the **India AI Impact Buildathon (GUVI)** — Problem Statement 2

---

## What it does

A **FastAPI** backend that acts as an intelligent honeypot for phone/SMS scammers:

1. **Detects scams** — 20-layer risk scoring engine (12 core + 8 auxiliary) with cumulative scoring across Hindi/English/Hinglish
2. **Engages the scammer** — 5-stage adaptive persona powered by a deep ML engagement engine
3. **Extracts intelligence** — Phones, bank accounts, UPI IDs, URLs, emails, Aadhaar, PAN, IFSC codes
4. **Reports to evaluator** — Sends structured callback to GUVI endpoint on every eligible turn

Response format:

```json
{ "status": "success", "reply": "Hello? Who is this?" }
```

---

## Architecture

### Pipeline

```
POST /honeypot
  │
  ├── 1. Session Management   (memory.py)
  ├── 2. History Replay        (detector + extractor)
  ├── 3. Risk Analysis         (detector.py — 20 signal layers)
  ├── 4. Intelligence Extract  (extractor.py — 10 entity types)
  ├── 5. ML Response Selection (engagement_ml.py → agent.py)
  └── 6. Callback Dispatch     (callback.py)
```

### Deep ML Engagement Engine

A lightweight neural architecture (`engagement_ml.py`) that replaces random response selection with ML-ranked selection:

```
┌─────────────┐     ┌────────────────┐
│ TextEncoder  │────▶│ SelfAttention  │
│ (char+word)  │     │ (4-head)       │──┐
└─────────────┘     └────────────────┘  │
                                         │   ┌──────────────┐
┌─────────────────┐                      ├──▶│ IntentHead   │
│ ConversationGRU │──────────────────────┤   │ (15 classes) │
│ (64-dim state)  │                      │   └──────────────┘
└─────────────────┘                      │
                                         │   ┌──────────────┐
┌──────────────────┐                     └──▶│ Engagement   │
│ ResponseEncoder  │────────────────────────▶│ Scorer       │
│ (pre-computed)   │                         │ (rank pool)  │
└──────────────────┘                         └──────────────┘
```

| Component                  | Role                                                       | Dimensions         |
| -------------------------- | ---------------------------------------------------------- | ------------------ |
| **TextEncoder**            | Char-trigram + word-bigram feature hashing → dense vectors | 128-d              |
| **MultiHeadSelfAttention** | 4-head attention for cross-feature interaction             | 4 × 32             |
| **GRUCell**                | Recurrent conversation-state tracking across turns         | 64-d hidden        |
| **NeuralIntentClassifier** | Hybrid FC + anchor-similarity + keyword-overlap            | 15 classes         |
| **EngagementScorer**       | Feed-forward network ranking response candidates           | 345 → 128 → 64 → 1 |

**Performance:** ~0.7ms inference · ~300KB memory · numpy-only (no GPU required) · graceful fallback to random if numpy is unavailable

---

## Project Structure

```
app/
├── main.py            # FastAPI routes + pipeline
├── auth.py            # API key auth (x-api-key header)
├── models.py          # Pydantic schemas
├── detector.py        # 20-layer risk scoring engine
├── extractor.py       # Regex intelligence extraction (10 entity types)
├── agent.py           # 5-stage engagement controller (ML-enhanced)
├── engagement_ml.py   # Deep ML engagement engine (neural response ranking)
├── memory.py          # Thread-safe session store
└── callback.py        # Callback builder + sender
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

fastapi 0.115.0 · uvicorn 0.32.1 · pydantic 2.10.3 · pydantic-settings 2.6.1 · python-dotenv 1.0.1 · requests 2.32.3 · numpy ≥1.24

---

## How the ML Engine Works

1. **Text Encoding** — Each scammer message is encoded via FNV-1a feature hashing (char-trigrams + word-bigrams) into a 128-d dense vector. No vocabulary or tokenizer needed.

2. **Self-Attention** — A 4-head scaled dot-product attention layer enables cross-feature interaction across the embedding dimensions.

3. **Conversation GRU** — A gated recurrent unit maintains a 64-d hidden state per session, capturing conversation momentum, escalation pace, and topic shifts across turns.

4. **Intent Classification** — A hybrid classifier blends three signals:
   - FC network logits (35%)
   - Cosine similarity to pre-computed intent anchors (30%)
   - Direct keyword-overlap counting (35%)

   Classifies into 15 intents: urgency, authority, OTP request, payment request, suspension, prize lure, suspicious URL, emotional pressure, legal threat, courier, tech support, job fraud, investment, identity theft, neutral.

5. **Response Scoring** — All candidate responses are batch-scored through a 3-layer feed-forward network (345→128→64→1) using concatenated features: message embedding, response embedding, GRU state, intent probabilities, and 10 hand-crafted engagement features.

6. **Context Bonuses** — Stage-aware boosts reward confusion in early stages, probing in middle stages, and intelligence extraction in late stages.

7. **Temperature Sampling** — Softmax with τ=0.6 balances exploitation of top-scored responses with exploration for natural variety.

---

_Built for the India AI Impact Buildathon (GUVI) 2026._
