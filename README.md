# Agentic Honey-Pot API

**Advanced Scam Detection & Intelligence Extraction System**

Built for the **India AI Impact Buildathon (GUVI)** - Problem Statement 2

🌐 **Live Deployment:** https://trusthoneypot.up.railway.app  
📚 **API Documentation:** https://trusthoneypot.up.railway.app/docs

---

## Overview

This is a production-grade FastAPI backend that implements an **advanced intelligent honeypot system** for detecting and engaging with scammers. The system uses **multi-layer detection**, autonomous agent responses, and comprehensive intelligence extraction to gather scammer information while maintaining a believable human persona.

## 🏆 Key Differentiators

- **Multi-Layer Detection Engine**: 5 layers of analysis (keywords, patterns, India-specific, behavioral, confidence)
- **India-Specific Scam Patterns**: RBI impersonation, Aadhaar/PAN scams, digital arrest, TRAI notices
- **Confidence Scoring**: Not just yes/no, but percentage confidence with risk levels
- **Scam Type Classification**: Identifies 15+ specific scam types
- **Enhanced Intelligence**: Extracts Aadhaar (masked), PAN, emails, crypto wallets, IFSC codes
- **Privacy-Conscious**: Masks sensitive data (Aadhaar: XXXX-XXXX-1234, PAN: XXXXX1234X)

## Features

### 🔒 Secure API

- API key authentication via `x-api-key` header
- Input validation using Pydantic models
- CORS-enabled for cross-origin requests

### 🎯 Advanced Multi-Layer Scam Detection

**Layer 1: Weighted Keyword Scoring**

- 200+ keywords across 9 categories
- Urgency, verification, payment, threat, government, identity, telecom, courier, job/loan

**Layer 2: Pattern Combination Analysis**

- 20+ compound patterns (e.g., "RBI + KYC + suspend")
- Regex-based template matching
- Higher scores for multi-signal patterns

**Layer 3: India-Specific Scam Detection**

- Government impersonation (RBI, TRAI, Income Tax, CBI, ED)
- Aadhaar/PAN scams
- Digital arrest scams (trending 2024-2025)
- Telecom/SIM block scams
- Courier/parcel scams

**Layer 4: Behavioral Analysis**

- Escalation pattern detection
- Pressure sequence recognition
- Multi-category bonus scoring

**Layer 5: Confidence Calibration**

- Risk levels: Minimal → Low → Medium → High → Critical
- Confidence percentage (0-99%)
- Scam type classification

### 🤖 Autonomous Agent Engagement

- Rule-based response generation
- Maintains confused, cautious human persona
- Context-aware replies based on detected tactics
- Never reveals scam detection
- No external LLM calls required

### 🔍 Comprehensive Intelligence Extraction

- **UPI IDs**: 50+ payment app handles supported
- **Bank Accounts**: 9-18 digit account numbers
- **IFSC Codes**: Bank branch identification
- **Phone Numbers**: Multiple Indian formats
- **Email Addresses**: Contact extraction
- **Aadhaar Numbers**: Masked for privacy (XXXX-XXXX-1234)
- **PAN Cards**: Masked for privacy (XXXXX1234X)
- **Crypto Wallets**: Bitcoin, Ethereum, USDT addresses
- **Phishing Links**: URLs, shortened links, messaging app links
- **Messaging IDs**: WhatsApp, Telegram identifiers

### 💾 Session Memory

- In-memory multi-turn conversation tracking
- Engagement metrics (duration, message count)
- Intelligence accumulation per session
- Callback state management

### 📡 Hackathon Integration

- Automatic callback to GUVI evaluation API
- Triggered when all conditions met:
  - Scam confirmed
  - Multi-turn engagement (≥3 messages)
  - Intelligence extracted
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
  "scamDetected": true,
  "engagementMetrics": {
    "engagementDurationSeconds": 420,
    "totalMessagesExchanged": 18
  },
  "extractedIntelligence": {
    "bankAccounts": ["123456789012"],
    "upiIds": ["scammer@paytm"],
    "phishingLinks": ["http://fake-bank.com"],
    "phoneNumbers": ["9876543210"],
    "suspiciousKeywords": ["verify account", "urgent"]
  },
  "agentNotes": "Scam conversation detected after 18 message exchanges. Extracted: 1 UPI ID(s), 1 bank account(s), 1 phone number(s), 1 phishing link(s). Agent successfully maintained believable persona throughout engagement."
}
```

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

### 1. Scam Detection Flow

- Message received → Extract keywords
- Calculate weighted risk score
- Accumulate score per session
- Confirm scam when threshold (30) crossed

### 2. Agent Engagement

- Once scam confirmed → Generate contextual response
- Maintain confused, cautious persona
- Ask clarifying questions
- Stall with believable excuses
- Never expose detection

### 3. Intelligence Extraction

- Scan each message with regex patterns
- Extract UPI IDs, bank accounts, phones, URLs
- Accumulate per session
- Track suspicious keywords

### 4. Callback Trigger

When ALL conditions met:

- ✅ Scam confirmed
- ✅ Multi-turn conversation (≥3 messages)
- ✅ At least one intelligence item extracted

System automatically sends final results to hackathon API.

### Detection Thresholds

Modify in [app/detector.py](app/detector.py):

- `SCAM_THRESHOLD = 30` - Risk score threshold for scam confirmation

### Agent Behavior

Customize response templates in [app/agent.py](app/agent.py):

- `INITIAL_RESPONSES` - First contact replies
- `VERIFICATION_RESPONSES` - Account verification scenarios
- `PAYMENT_RESPONSES` - Payment/refund scenarios
- `CAUTIOUS_RESPONSES` - Suspicious behavior reactions

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

This implementation follows the official problem statement:

✅ No external LLM API calls  
✅ Rule-based agent logic only  
✅ Risk-based (not binary) detection  
✅ Multi-turn conversation support  
✅ Regex-based intelligence extraction  
✅ No credential requests  
✅ Mandatory callback implementation  
✅ Exact response format adherence

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
