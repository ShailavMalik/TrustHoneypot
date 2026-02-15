# Agentic Honey-Pot API

**Advanced Scam Detection & Intelligence Extraction System**

Built for the **India AI Impact Buildathon (GUVI)** - Problem Statement 2

🌐 **Live Deployment:** https://trusthoneypot.up.railway.app  
📚 **API Documentation:** https://trusthoneypot.up.railway.app/docs

---

## Overview

This is a production-grade FastAPI backend that implements an **advanced intelligent honeypot system** for detecting and engaging with scammers. The system uses **multi-layer detection**, **intent classification**, **stage-aware response generation**, and comprehensive intelligence extraction to gather scammer information while maintaining a believable human persona.

### Phase-1 Enhancements

- **Intent Classification**: 12 intent types with weighted scoring (OTP=50, UPI=45, BANK_DETAILS=45, etc.)
- **Stage-Aware Responses**: 4 conversation stages (Greeting → Rapport → Suspicion → Extraction)
- **False Positive Prevention**: SCAM_THRESHOLD raised to 60 for high-confidence detection
- **Enhanced Extraction**: 60+ UPI handles, 15+ URL shorteners, 8+ phone patterns
- **Improved Callbacks**: Multi-condition triggering with engagement requirements

### Response Format (Simplified)

The API returns a clean, simple response:

```json
{
  "status": "success",
  "reply": "<human-like response>"
}
```

All internal processing (scam detection, intelligence extraction, metrics) is logged server-side but **never exposed** in the API response. This ensures:

- Scammers cannot detect they are interacting with a honeypot
- The agent maintains a believable human persona
- Detection status is never revealed

## 🏆 Key Differentiators

- **Simplified API Response**: Only `status` and `reply` - no detection exposed
- **Intent Classification**: 12 intent types with weighted risk scoring
- **Stage-Aware Engine**: 4 conversation stages with adaptive responses
- **Multi-Layer Detection Engine**: 6 layers of analysis (keywords, patterns, India-specific, behavioral, intent, confidence)
- **False Positive Prevention**: SCAM_THRESHOLD = 60 ensures high-confidence detection
- **Context-Aware Responses**: Agent adapts dynamically based on conversation history, intent, and stage
- **India-Specific Scam Patterns**: RBI impersonation, Aadhaar/PAN scams, digital arrest, TRAI notices
- **Confidence Scoring**: Not just yes/no, but percentage confidence with risk levels
- **Scam Type Classification**: Identifies 15+ specific scam types
- **Enhanced Intelligence**: Extracts Aadhaar (masked), PAN, emails, crypto wallets, IFSC codes
- **60+ UPI Handles**: Comprehensive payment app detection (PhonePe, GPay, Paytm, banks, etc.)
- **Privacy-Conscious**: Masks sensitive data (Aadhaar: XXXX-XXXX-1234, PAN: XXXXX1234X)
- **Human-Like Behavior**: Never reveals detection, maintains believable Hindi/English persona

## Features

### 🔒 Secure API

- API key authentication via `x-api-key` header
- Input validation using Pydantic models
- CORS-enabled for cross-origin requests

### 🎯 Advanced Multi-Layer Scam Detection

**Layer 1: Intent Classification (NEW)**

- 12 intent types: GREETING, SMALL_TALK, PAYMENT_REQUEST, OTP_REQUEST, BANK_DETAILS_REQUEST, UPI_REQUEST, IDENTITY_PROBE, ACCOUNT_SUSPENSION, LEGAL_THREAT, URGENCY, AFFIRMATION, UNKNOWN
- Weighted scoring: OTP_REQUEST=50, UPI_REQUEST=45, BANK_DETAILS_REQUEST=45, PAYMENT_REQUEST=40, ACCOUNT_SUSPENSION=35, LEGAL_THREAT=30, URGENCY=25
- Regex-based pattern matching for each intent

**Layer 2: Stage-Aware Rule Engine (NEW)**

- 4 conversation stages with progressive engagement:
  - `GREETING_STAGE`: Initial contact, polite confusion
  - `RAPPORT_STAGE`: Building trust, clarifying questions
  - `SUSPICION_STAGE`: Questioning authenticity, asking for documentation
  - `EXTRACTION_STAGE`: Gathering scammer details (UPI, accounts, links)
- Stage progression based on risk score + message count

**Layer 3: Weighted Keyword Scoring**

- 200+ keywords across 9 categories
- Urgency, verification, payment, threat, government, identity, telecom, courier, job/loan

**Layer 4: Pattern Combination Analysis**

- 20+ compound patterns (e.g., "RBI + KYC + suspend")
- Regex-based template matching
- Higher scores for multi-signal patterns

**Layer 5: India-Specific Scam Detection**

- Government impersonation (RBI, TRAI, Income Tax, CBI, ED)
- Aadhaar/PAN scams
- Digital arrest scams (trending 2024-2025)
- Telecom/SIM block scams
- Courier/parcel scams

**Layer 6: Behavioral Analysis**

- Escalation pattern detection
- Pressure sequence recognition
- Multi-category bonus scoring

**Layer 7: Confidence Calibration**

- Risk levels: Minimal → Low → Medium → High → Critical
- Confidence percentage (0-99%)
- Scam type classification
- **SCAM_THRESHOLD = 60** (prevents false positives on greetings)

### 🤖 Autonomous Agent Engagement

- **Stage-Aware Response Generation (NEW)**
  - 4 conversation stages: Greeting → Rapport → Suspicion → Extraction
  - Automatic stage progression based on risk score and message count
  - Intent-specific response pools (OTP, Bank Details, UPI, Identity Probe)
- **Context-Aware Response Generation**
  - Tracks conversation history across messages
  - Monitors escalation level (initial → engaged → suspicious → fearful)
  - Adapts responses based on detected intents and tactics
- **Expanded Response Pools (NEW)**
  - 12 stage-aware responses per stage
  - 8+ intent-specific responses (OTP, Bank, Identity, Payment, etc.)
  - 14 digital arrest responses, 12 courier responses, 12 tech confusion responses
  - Hindi/English mix for authenticity
- **Dynamic Response Adaptation**
  - Initial contact: Confused, "Who is this?"
  - Verification scams: Cautious, skeptical
  - Payment lures: Skeptical but curious
  - Digital arrest: Fearful, compliant (trending scam)
  - OTP requests: Technical confusion, delays
  - Threats: Fearful, cooperative (to extract more intel)
  - Extended engagement: Asks for details (UPI, account numbers)
- **Human-Like Behavior**
  - Uses stalling tactics ("Hold on, someone at the door")
  - Shows appropriate emotions based on scammer pressure
  - Never repeats the same response in a session
  - Avoids robotic or formulaic replies
  - Elderly persona with authentic Hindi phrases
- **Safety Guarantees**
  - Never reveals scam detection
  - Never mentions "fraud", "scam", or "suspicious"
  - Never accuses the sender
  - No external LLM calls required

### 🔍 Comprehensive Intelligence Extraction

- **UPI IDs**: 60+ payment app handles supported (PhonePe, GPay, Paytm, banks, BHIM, etc.)
- **Bank Accounts**: 9-18 digit account numbers
- **IFSC Codes**: Bank branch identification
- **Phone Numbers**: 8+ Indian phone patterns (with/without country code, spaces, hyphens)
- **Email Addresses**: Contact extraction
- **Aadhaar Numbers**: Masked for privacy (XXXX-XXXX-1234)
- **PAN Cards**: Masked for privacy (XXXXX1234X)
- **Crypto Wallets**: Bitcoin, Ethereum, USDT addresses
- **Phishing Links**: URLs, 15+ URL shorteners (bit.ly, tinyurl, cutt.ly, etc.)
- **Messaging IDs**: WhatsApp, Telegram identifiers

### 💾 Session Memory

- In-memory multi-turn conversation tracking
- Engagement metrics (duration, message count)
- Intelligence accumulation per session
- Callback state management

### 📡 Hackathon Integration

- Automatic callback to GUVI evaluation API
- Triggered when ALL conditions met:
  - ✅ Scam confirmed (risk_score ≥ 60)
  - ✅ Multi-turn engagement (≥3 messages)
  - ✅ Intelligence extracted OR ≥5 messages (engagement sufficient)
- Sent only once per session
- Full audit logging to `callback_history.json`

---

## Project Structure

```
honeypot-api/
├── app/
│   ├── main.py          # FastAPI app, routes, middleware
│   ├── auth.py          # API key authentication
│   ├── models.py        # Pydantic models
│   ├── detector.py      # Multi-layer scam detection engine
│   ├── agent.py         # Autonomous agent with enhanced notes
│   ├── extractor.py     # Comprehensive intelligence extraction
│   ├── memory.py        # Session storage
│   └── callback.py      # Final result callback with logging
├── requirements.txt     # Python dependencies
├── .env.example         # Environment variables template
└── README.md           # This file
```

---

## Installation

### Prerequisites

- Python 3.9 or higher
- pip package manager

### Setup

1. **Clone or extract the project**

2. **Create virtual environment** (recommended)

   ```powershell
   python -m venv venv
   .\venv\Scripts\Activate.ps1
   ```

3. **Install dependencies**

   ```powershell
   pip install -r requirements.txt
   ```

4. **Configure environment variables**

   ```powershell
   cp .env.example .env
   ```

   Edit `.env` and set your API key:

   ```
   API_KEY=your-secret-api-key-here
   CALLBACK_URL=https://hackathon.guvi.in/api/updateHoneyPotFinalResult
   ```

---

## Running the API

### Production Deployment (Railway)

✅ **Live API:** https://trust-honeypot.up.railway.app  
✅ **Interactive Docs:** https://trust-honeypot.up.railway.app/docs  
✅ **Health Check:** https://trust-honeypot.up.railway.app/

### Local Development Mode

```powershell
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Local Production Mode

```powershell
uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4
```

Local API: `http://localhost:8000`  
Local Docs: `http://localhost:8000/docs`

---

## API Usage

### Authentication

All requests require the `x-api-key` header:

```
x-api-key: your-secret-api-key-here
```

### Endpoint

**POST /honeypot**

Request format:

```json
{
  "sessionId": "unique-session-id",
  "message": {
    "sender": "scammer",
    "text": "Urgent! Your account will be suspended. Click here to verify.",
    "timestamp": "2026-01-24T10:30:00Z"
  },
  "conversationHistory": [],
  "metadata": {
    "channel": "SMS",
    "language": "English",
    "locale": "IN"
  }
}
```

Response format:

```json
{
  "status": "success",
  "reply": "Hello? Who is this?"
}
```

**Note:** The response contains only `status` and `reply`. All internal processing (scam detection, metrics, intelligence) is handled server-side and logged internally but never exposed to the client.

### Example cURL (Production)

```bash
curl -X POST https://trust-honeypot.up.railway.app/honeypot \
  -H "x-api-key: your-secret-api-key-here" \
  -H "Content-Type: application/json" \
  -d '{
    "sessionId": "test-session-001",
    "message": {
      "sender": "scammer",
      "text": "Urgent: Your bank account is suspended. Verify at http://fake-bank.com",
      "timestamp": "2026-01-24T10:30:00Z"
    },
    "conversationHistory": [],
    "metadata": {
      "channel": "SMS",
      "language": "English",
      "locale": "IN"
    }
  }'
```

### Example cURL (Local)

```bash
curl -X POST http://localhost:8000/honeypot \
  -H "x-api-key: your-secret-api-key-here" \
  -H "Content-Type: application/json" \
  -d '{
    "sessionId": "test-session-001",
    "message": {
      "sender": "scammer",
      "text": "Urgent: Your bank account is suspended. Verify at http://fake-bank.com",
      "timestamp": "2026-01-24T10:30:00Z"
    },
    "conversationHistory": [],
    "metadata": {
      "channel": "SMS",
      "language": "English",
      "locale": "IN"
    }
  }'
```

---

## How It Works

### 1. Message Processing Flow

```
Request → Scam Detection → Agent Response → Intelligence Extraction → Callback (if ready)
```

### 2. Scam Detection (Internal)

- Multi-layer keyword, pattern, and intent analysis
- Intent classification with weighted scoring
- Accumulative risk scoring per session
- Scam confirmed when threshold (60) crossed
- **Detection status never exposed in API response**

### 3. Agent Engagement (Human-Like Replies)

- Stage-aware response generation (4 stages)
- Intent-specific response pools
- Context-aware response generation
- Tracks conversation history and escalation level
- Adapts responses based on scammer tactics and detected intent:
  - Initial: Confused, "Who is this?"
  - Rapport: Building trust, clarifying
  - Suspicion: Asking for proof, documentation
  - Extraction: Gathering details (UPI, account numbers)
  - OTP requests: Technical confusion, delays
  - Digital arrest: Fearful, compliant
- **Never reveals scam detection**
- **Maintains believable Hindi/English human persona**

### 4. Intelligence Extraction (Internal)

- Runs on every message (silent)
- Extracts: UPI IDs, bank accounts, phones, links, emails
- Results logged internally, not exposed

### 5. Callback Trigger

When ALL conditions met:

- ✅ Scam confirmed (risk_score ≥ 60)
- ✅ Multi-turn conversation (≥3 messages)
- ✅ At least one intelligence item extracted OR ≥5 messages
- ✅ Callback not already sent for this session

System automatically sends final results to hackathon API.

### Detection Thresholds

Modify in [app/detector.py](app/detector.py):

- `SCAM_THRESHOLD = 60` - Risk score threshold for scam confirmation (raised to prevent false positives)

### Intent Weights

Customize intent weights in [app/detector.py](app/detector.py):

- `OTP_REQUEST = 50` - Highest risk (direct credential theft)
- `UPI_REQUEST = 45` - High risk (payment extraction)
- `BANK_DETAILS_REQUEST = 45` - High risk (financial fraud)
- `PAYMENT_REQUEST = 40` - Medium-high risk
- `ACCOUNT_SUSPENSION = 35` - Medium risk (fear tactic)
- `LEGAL_THREAT = 30` - Medium risk (intimidation)
- `URGENCY = 25` - Lower risk (pressure tactic)
- `GREETING/SMALL_TALK = 0` - No risk (prevents false positives)

### Agent Behavior

Customize response templates in [app/agent.py](app/agent.py):

**Stage-Based Response Pools:**

- `GREETING_STAGE_RESPONSES` - First contact (12 responses)
- `RAPPORT_STAGE_RESPONSES` - Building trust (12 responses)
- `SUSPICION_STAGE_RESPONSES` - Questioning authenticity (12 responses)
- `EXTRACTION_STAGE_RESPONSES` - Gathering details (12 responses)

**Intent-Specific Response Pools:**

- `OTP_RESPONSES` - OTP/verification code requests (10 responses)
- `ACCOUNT_NUMBER_RESPONSES` - Bank account requests (10 responses)
- `IDENTITY_PROBE_RESPONSES` - Identity verification (8 responses)
- `PAYMENT_REQUEST_RESPONSES` - Payment demands (8 responses)

**Scam-Type Response Pools:**

- `DIGITAL_ARREST_RESPONSES` - Digital arrest scams (14 responses)
- `COURIER_RESPONSES` - Courier/parcel scams (12 responses)
- `COMPLIANT_RESPONSES` - Trust-building (10 responses)
- `TECH_CONFUSION_RESPONSES` - Technical difficulties (12 responses)
- `FEARFUL_RESPONSES` - When threatened (12 responses)

**Legacy Response Pools:**

- `VERIFICATION_RESPONSES` - Account verification scenarios (cautious)
- `PAYMENT_RESPONSES` - Payment/refund scenarios (skeptical)
- `STALLING_RESPONSES` - Buying time (realistic excuses)
- `DETAIL_SEEKING` - Extracting intel (asking for UPI, accounts)
- `NEUTRAL_RESPONSES` - Non-scam messages (polite confusion)

---

## Testing

### Health Check

**Production:**

```bash
curl https://trust-honeypot.up.railway.app/
```

**Local:**

```bash
curl http://localhost:8000/
```

Expected response:

```json
{
  "status": "online",
  "service": "Agentic Honey-Pot API",
  "version": "1.0.0"
}
```

### Multi-Turn Conversation Test

Send multiple messages with the same `sessionId` to test:

- Session persistence
- Risk score accumulation
- Agent response generation
- Intelligence extraction
- Callback triggering

---

## Security Considerations

✅ **Implemented:**

- API key authentication
- Input validation with Pydantic
- No external credential requests
- No impersonation of real individuals
- Logging for audit trails

⚠️ **Production Recommendations:**

- Use strong, randomly generated API keys
- Implement rate limiting
- Add request logging to persistent storage
- Use HTTPS in production
- Implement IP whitelisting if needed
- Add monitoring and alerting

---

## Deployment

### Railway Deployment (Current)

The API is deployed on Railway and accessible at:

- **Production URL:** https://trust-honeypot.up.railway.app
- **API Documentation:** https://trust-honeypot.up.railway.app/docs
- **Health Endpoint:** https://trust-honeypot.up.railway.app/

#### Environment Variables on Railway:

- `API_KEY` - Strong random key for authentication
- `CALLBACK_URL` - GUVI evaluation endpoint (pre-configured)
- `PORT` - Automatically set by Railway

#### Deployment Process:

1. Push code to GitHub
2. Connect Railway to GitHub repository
3. Railway auto-deploys on push to `main` branch
4. Uses `Procfile` for configuration

---

## Compliance

This implementation follows the official problem statement (Phase-1 guidelines):

✅ No external LLM API calls  
✅ Rule-based agent logic only  
✅ Risk-based (not binary) detection  
✅ Multi-turn conversation support  
✅ Regex-based intelligence extraction  
✅ No credential requests  
✅ Mandatory callback implementation  
✅ Exact response format adherence (`{"status": "success", "reply": "..."}`)  
✅ Intent classification with weighted scoring  
✅ Stage-aware response generation  
✅ False positive prevention (SCAM_THRESHOLD = 60)  
✅ Enhanced extraction (60+ UPI handles, 15+ URL shorteners)

---

## Troubleshooting

### API Key Errors

- Ensure `x-api-key` header is included
- Check `.env` file has correct `API_KEY` value
- Verify no extra spaces in header value

### Callback Not Sending

- Check if all conditions met (3+ messages, intelligence extracted, scam confirmed)
- Verify `CALLBACK_URL` in `.env`
- Check logs for callback errors
- Ensure network connectivity

### No Agent Response

- Agent only responds after scam is confirmed
- Check if risk score threshold reached
- Verify session exists in memory

---

## License

This project is submitted for the India AI Impact Buildathon (GUVI) 2026.

---

## Contact

For questions or issues related to this submission, please refer to the hackathon guidelines.

**Built with ❤️ for safer digital communications**
