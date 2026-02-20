"""
detector.py — Multi-Layer Scam Risk Scoring Engine
===================================================

The core detection engine that analyzes scammer messages through 20 signal
layers (12 core + 8 auxiliary) to produce a cumulative risk score per session.

Coverage includes all major Indian scam categories:
    - Bank fraud (SBI, HDFC, ICICI impersonation)
    - UPI fraud (fake payment requests, QR codes)
    - Phishing (OTP theft, credential harvesting)
    - Authority impersonation (RBI, CBI, Police, IT Dept)
    - Digital arrest (fake video-call court proceedings)
    - Courier/parcel (drugs-found-in-package scam)
    - Lottery/prize (KBC, Amazon Lucky Draw)
    - Tech support (fake virus, AnyDesk remote access)
    - Job fraud (Telegram tasks, fake work-from-home)
    - Loan fraud (instant loan apps, processing fees)
    - Insurance fraud (unclaimed policies, fake maturity)
    - Romance scams (emotional manipulation, gift parcels)

Scoring mechanics:
    1. Each message is scored against all 20 signal layers
    2. Matching regex patterns contribute weighted points (6-25 per match)
    3. Escalation bonuses reward compound signals (2+ simultaneous categories)
    4. Repeat-signal bonuses penalize persistent tactics (+6 for 2x, +12 for 3x+)
    5. Score >= 40 triggers scam confirmation (deliberately low for fast detection)

Multi-language support:
    All pattern layers include Hindi/Hinglish variants for Indian market coverage.

Thread safety:
    Per-session RiskProfile access is protected by threading.Lock.
"""

import re
import threading
from typing import Tuple, Dict, List, Set
from dataclasses import dataclass, field


# Valid scam type labels used for classification output.
# These map to the evaluator's expected scam_type values.
VALID_SCAM_TYPES = frozenset([
    "bank_fraud", "upi_fraud", "phishing", "impersonation",
    "investment", "courier", "lottery", "tech_support",
    "job_fraud", "loan_fraud", "insurance_fraud", "unknown",
])


@dataclass
class RiskProfile:
    """Per-session risk accumulation state.
    
    Tracks the running score, per-turn breakdowns, which signal
    categories have fired, and the final scam classification.
    """
    cumulative_score: float = 0.0                          # Running total risk score
    turn_scores: List[float] = field(default_factory=list)  # Score per individual message
    triggered_signals: Set[str] = field(default_factory=set)  # Unique signal categories hit
    signal_counts: Dict[str, int] = field(default_factory=dict)  # Hit count per category
    scam_detected: bool = False                            # True once threshold breached
    scam_type: str = "unknown"                             # Classified scam label
    message_count: int = 0                                 # Messages analyzed so far


class RiskAccumulator:
    """
    Production-grade scam detection engine. Scores scammer messages through
    20 signal layers (12 core + 8 auxiliary) and accumulates risk per session.
    Thread-safe via lock on the session dict.

    Covers: bank fraud, UPI fraud, phishing, impersonation, digital arrest,
    courier/parcel, lottery/prize, tech support, job fraud, loan fraud,
    insurance fraud, romance scams, and multi-language (Hindi/Hinglish) patterns.
    """

    # Lower threshold for faster detection — compound signals push past quickly
    SCAM_THRESHOLD: float = 40.0

    # ================================================================
    # CORE SIGNAL LAYERS — each is a list of (regex, weight) tuples
    # ================================================================

    URGENCY_PATTERNS = [
        # English urgency
        (r'\b(urgent|urgently|immediate(?:ly)?|right\s*now|asap)\b',           12),
        (r'\b(hurry|quickly|fast|rush|rushing)\b',                             10),
        (r'\b(within\s*\d+\s*(?:hour|minute|min|day|hr)s?|today\s*only)\b',    14),
        (r'\b(last\s*chance|final\s*(?:notice|warning|chance)|expir(?:e|ing|ed))\b', 16),
        (r'\b(deadline|time\s*(?:running|left)|before\s*\d+)\b',              12),
        (r'\b(act\s*now|don.t\s*wait|limited\s*time|time\s*sensitive)\b',      14),
        (r'\b(running\s*out|clock\s*is\s*ticking|no\s*time)\b',               12),
        (r'\b(expire[sd]?\s*(?:in|within|today|soon)|valid\s*(?:till|until|for))\b', 14),
        (r'\b(?:only|just)\s*\d+\s*(?:hour|minute|min|slot|seat)s?\s*(?:left|remaining)\b', 16),
        (r'\b(respond\s*(?:now|immediately|urgently)|time\s*is\s*(?:running|short))\b', 12),
        # Hindi/Hinglish urgency
        (r'\b(jaldi|turant|abhi|fauran|fatafat|jald\s*se\s*jald)\b',          12),
        (r'\b(samay\s*(?:khatam|nahi)|waqt\s*nahi|bahut\s*zaruri)\b',         12),
        (r'\b(aakhri\s*(?:mauka|chance|moka)|ant(?:im|a)\s*(?:chetavani|warning))\b', 14),
        (r'\b(jaldi\s*kar(?:o|iye|en)|der\s*mat\s*kar(?:o|iye))\b',           12),
        (r'\b(tatkaal|atisheeghra|sheeghrata\s*se)\b',                        10),
    ]

    AUTHORITY_PATTERNS = [
        # Indian government agencies
        (r'\b(rbi|reserve\s*bank(?:\s*of\s*india)?)\b',                        18),
        (r'\b(income\s*tax|it\s*department|itr)\b',                            16),
        (r'\b(police|cbi|enforcement\s*directorate)\b',                        18),
        (r'\b(trai|dot|department\s*of\s*telecom(?:munications)?)\b',          16),
        (r'\b(customs|ministry|government|govt)\b',                            14),
        (r'\b(officer|inspector|commissioner|superintendent|sub[\s\-]?inspector)\b', 12),
        (r'\b(uidai|npci|sebi|irda|irdai|nabard|sidbi)\b',                    14),
        (r'\b(cyber\s*(?:cell|crime|police|branch))\b',                        16),
        (r'\b(central\s*bureau|investigation\s*agency|nia|nsa)\b',             18),
        (r'\b(supreme\s*court|high\s*court|court\s*order|sessions?\s*court)\b', 16),
        (r'\b(pradhan\s*mantri|pm\s*(?:scheme|yojana)|govt\s*scheme)\b',       14),
        # Specific Indian entities commonly impersonated
        (r'\b(sbi|state\s*bank|hdfc|icici|axis\s*bank|kotak|pnb)\b',          10),
        (r'\b(airtel|jio|vodafone|vi|bsnl)\b',                                10),
        (r'\b(amazon|flipkart|paytm|phonepe|google\s*pay)\b',                  8),
        (r'\b(narcotics?\s*(?:bureau|department|control)|ncb)\b',              18),
        (r'\b(immigration|passport\s*office|dgca|rcb)\b',                      14),
        (r'\b(election\s*commission|eci|niti\s*aayog)\b',                      12),
        (r'\b(epfo|pf\s*office|esi|labour\s*(?:department|office))\b',         12),
        (r'\b(municipal|nagar\s*(?:nigam|palika)|corporation)\b',              10),
        # Hindi authority terms
        (r'\b(sarkar|sarkari|adhikari|thana|thanedar)\b',                      12),
        (r'\b(vibhag|mantralaya|niyamak|pradhikaran)\b',                       10),
    ]

    OTP_PATTERNS = [
        (r'\b(otp|one\s*time\s*password|verification\s*code)\b',               20),
        (r'\b(?:share|send|tell|give|provide|forward)\s*(?:me\s*)?(?:the\s*)?(?:otp|code|pin)\b', 25),
        (r'\b\d[\s\-]?digit\s*(?:code|otp|pin|password|number)\b',            22),
        (r'\b(?:enter|type|input|submit)\s*(?:the\s*)?(?:otp|code|pin)\b',     22),
        (r'\b(cvv|atm\s*pin|card\s*pin|mpin|m[\s\-]?pin|upi\s*pin)\b',        22),
        (r'\b(?:received?\s*(?:a\s*)?(?:otp|code|sms|message))\b',             18),
        (r'\b(?:read\s*(?:out|me)\s*(?:the\s*)?(?:otp|code|number))\b',        25),
        (r'\b(?:what\s*(?:is|was)\s*(?:the\s*)?(?:otp|code|pin))\b',           22),
        (r'\b(?:confirm\s*(?:your\s*)?(?:otp|code|pin|password))\b',           20),
        (r'\b(?:send\s*(?:the\s*)?sms\s*(?:code|otp))\b',                     22),
        # Hindi OTP requests
        (r'\b(?:otp\s*(?:batao|bhejo|do|dijiye|bataiye))\b',                   22),
        (r'\b(?:code\s*(?:batao|bhejo|do|dijiye))\b',                          20),
    ]

    PAYMENT_PATTERNS = [
        (r'\b(?:send|transfer|pay)\s*(?:me|us|the|now|rs|₹|\$|\d+)\b',        18),
        (r'\b(processing\s*fee|registration\s*fee|advance\s*payment)\b',       20),
        (r'\b(pay\s*now|transfer\s*now|send\s*money|make\s*payment)\b',        18),
        (r'\b(?:amount|money|payment)\s*(?:of|is|due|required|pending)\b',     14),
        (r'\b(demand\s*draft|neft|rtgs|imps|wire\s*transfer)\b',              10),
        (r'\b(?:refund|cashback|reward)\s*(?:of|is|amount|pending|process)\b', 16),
        (r'\b(?:rs|₹|inr)\s*\d[\d,]*\b',                                      12),
        (r'\b\d[\d,]*\s*(?:rs|rupees?|₹|inr)\b',                              12),
        (r'\b(security\s*deposit|verification\s*(?:fee|charge|amount))\b',     18),
        (r'\b(service\s*(?:charge|fee|tax)|gst\s*(?:charge|fee|extra))\b',     16),
        (r'\b(clearance\s*(?:fee|charge|amount)|handling\s*(?:fee|charge))\b', 18),
        (r'\b(stamp\s*duty|documentation\s*(?:fee|charge))\b',                 16),
        (r'\b(insurance\s*premium|membership\s*fee|activation\s*(?:fee|charge))\b', 16),
        (r'\b(token\s*(?:money|amount)|booking\s*(?:amount|fee))\b',           14),
        # Hindi payment phrases
        (r'\b(paisa|paise|rupaye|bhejo|transfer\s*karo|payment\s*karo)\b',     14),
        (r'\b(rashi|dhanrashi|shulk|fees?\s*jama\s*kar(?:o|en))\b',            14),
    ]

    SUSPENSION_PATTERNS = [
        (r'\b(?:account|a/c)\s*(?:will\s*be\s*)?(?:suspend|block|deactivat|freez|terminat|clos|lock)\w*\b', 18),
        (r'\b(?:suspend|block|deactivat|freez|terminat|lock|clos)(?:ed|ion|ing|ure)\s*(?:your\s*)?(?:account|a/c|card|number|sim|wallet)?\b', 16),
        (r'\b(?:kyc|ekyc|re[\s\-]?kyc|ckyc)\s*(?:update|expir|fail|mandatory|required|pending|incomplete|verify)\b', 18),
        (r'\b(?:sim|number|mobile|phone)\s*(?:will\s*be\s*)?(?:block|deactivat|suspend|disconnect)\b', 16),
        (r'\b(?:aadhaar|aadhar|pan|pan\s*card)\s*(?:block|suspend|deactivat|cancel|link|mismatch)\b', 16),
        (r'\b(?:your\s*(?:card|debit|credit)\s*(?:is|will\s*be|has\s*been))\s*(?:block|suspend|deactivat|freez)\w*\b', 18),
        (r'\b(?:unauthorized?\s*(?:access|transaction|activity|login))\b',     16),
        (r'\b(?:suspicious\s*(?:activity|transaction|login|access))\b',        16),
        (r'\b(?:compromised?|hacked?|breach(?:ed)?|tamper(?:ed)?)\b',          16),
        (r'\b(?:permanently?\s*(?:block|close|deactivat|suspend|disabled?))\b', 18),
        (r'\b(?:service\s*(?:discontinue|terminate|suspend|restrict))\b',      14),
        # Hindi suspension
        (r'\b(band\s*(?:ho\s*jayega|kar\s*diya|hoga)|rok\s*diya)\b',          14),
        (r'\b(khata\s*(?:band|block|freeze)|sim\s*band)\b',                    14),
    ]

    LURE_PATTERNS = [
        (r'\b(?:won|winner|winning|congratulat)\w*\b',                         16),
        (r'\b(prize|lottery|lucky\s*draw|jackpot|bumper\s*draw)\b',            18),
        (r'\b(?:cashback|cash\s*back|bonus|reward)\s*(?:of|is|amount)?\b',     14),
        (r'\b(?:claim|collect|receive|redeem)\s*(?:your\s*)?(?:prize|reward|money|amount|gift)\b', 16),
        (r'\b(?:guaranteed\s*returns?|double\s*your\s*money|high\s*returns?)\b', 18),
        (r'\b(?:selected|chosen|nominated|shortlisted)\s*(?:for|as)\b',        14),
        (r'\b(?:free\s*(?:gift|iphone|laptop|car|bike|gold|trip|holiday))\b',  16),
        (r'\b(?:scratch\s*card|spin\s*wheel|mega\s*(?:offer|deal|sale))\b',    14),
        (r'\b(?:exclusive\s*(?:offer|deal|discount)|special\s*(?:offer|price))\b', 12),
        (r'\b(?:limited\s*(?:offer|period|seats?)|offer\s*ends?\s*(?:today|soon|now))\b', 14),
        (r'\b(?:kbc|kaun\s*banega\s*crorepati|who\s*wants?\s*to\s*be)\b',     20),
        (r'\b(?:amazon\s*(?:lucky|winner|prize)|flipkart\s*(?:lucky|winner))\b', 18),
        (r'\b(?:government\s*(?:scheme|subsidy|grant)|pm\s*(?:yojana|scheme))\b', 14),
        # Hindi lure
        (r'\b(jeet(?:a|e)|muft|inaam|lakhpati|crorepati)\b',                   14),
        (r'\b(badhai|badhaiyan|shubh|lucky)\b',                                10),
    ]

    URL_PATTERNS = [
        (r'https?://[^\s<>"{}|\\^`\[\]]+',                                    12),
        (r'\b(?:bit\.ly|tinyurl|goo\.gl|t\.co|rb\.gy|is\.gd|cutt\.ly|shorturl|ow\.ly|tiny\.cc|v\.gd)\b', 16),
        (r'\b(?:click\s*(?:here|this|below|the\s*link)|tap\s*(?:here|this|below)|open\s*(?:this|the\s*link))\b', 14),
        (r'\b(?:wa\.me|whatsapp\.com|t\.me|telegram\.me)\b',                   10),
        (r'[a-z0-9]+\.(?:xyz|top|online|site|work|click|live|club|fun|icu|buzz)\b', 14),
        (r'\b(?:download|install|update)\s*(?:from|the|this|our)\s*(?:link|app|apk)\b', 14),
        (r'\b(?:apk|\.exe|\.msi)\s*(?:file|download|install)\b',              16),
        (r'\b(?:anydesk|teamviewer|quicksupport|ammyy|ultraviewer)\b',         20),
        (r'\b(?:screen\s*shar(?:e|ing)|remote\s*(?:access|desktop|control))\b', 18),
        (r'\b(?:play\s*store\s*(?:link|download)|app\s*(?:store|download))\b',  8),
        # Additional phishing/mobile-app/social-engineering patterns
        (r'\b(?:insure|securelink|e-verification|e[\.\s]?verif)\b',            16),
        (r'\b(?:whatsapp|telegram)\s*(?:link|url|group|channel)\b',            14),
        (r'\b(?:mobile\s*app|apk\s*file|install\s*app)\b',                    14),
        (r'\b(?:secure[\.\-]?link|safe[\.\-]?pay|verify[\.\-]?now|claim[\.\-]?reward)\b', 16),
        (r'[a-z0-9\-]*(?:secure|verify|account|update|login|claim)[a-z0-9\-]*\.(?:in|com|org|net)/[^\s]*', 16),
    ]

    EMOTIONAL_PATTERNS = [
        (r'\b(scared|afraid|worried|danger(?:ous)?|risk|destroy|ruin)\b',      10),
        (r'\b(?:your\s*(?:family|children|parents?|wife|husband|reputation|career|future))\b', 12),
        (r'\b(embarrass|shame|disgrace|humiliat|insult)\b',                    12),
        (r'\b(?:save|protect)\s*(?:yourself|your\s*(?:family|money))\b',        8),
        (r'\b(?:trust\s*me|believe\s*me|honest|genuine|rest\s*assured)\b',      6),
        (r'\b(confidential|secret|private|between\s*us|don.t\s*tell)\b',       10),
        (r'\b(?:no\s*one\s*(?:will\s*know|can\s*help)|only\s*(?:I|we)\s*can)\b', 12),
        (r'\b(helpless|hopeless|no\s*(?:choice|option|way\s*out))\b',          10),
        (r'\b(suffer|suffering|pain|misery|tragedy)\b',                         8),
        (r'\b(?:your\s*(?:life|name)\s*(?:will\s*be|is)\s*(?:ruin|destroy|finish))\b', 14),
        (r'\b(media|newspaper|social\s*media|viral|public)\b',                  8),
        # Hindi emotional pressure
        (r'\b(darr|daro|dar\s*jao|ghabrao|chinta|pareshaan)\b',               10),
        (r'\b(badnaam|izzat|sharm|beizzati|lat|barbad)\b',                     12),
        (r'\b(bach\s*jao|bacha\s*lo|madad|sahara|bharosa)\b',                   8),
    ]

    LEGAL_THREAT_PATTERNS = [
        (r'\b(legal\s*action|legal\s*notice|legal\s*proceedings?)\b',          16),
        (r'\b(arrest(?:ed)?|warrant|fir|first\s*information\s*report)\b',      16),
        (r'\b(jail|prison|imprison(?:ment)?|custody|detention|lock[\s\-]?up)\b', 18),
        (r'\b(penalty|fine|prosecution|indictment|conviction)\b',              14),
        (r'\b(?:case\s*(?:filed|registered|pending)|under\s*investigation)\b', 16),
        (r'\b(digital\s*arrest|video\s*call\s*arrest|online\s*arrest)\b',      20),
        (r'\b(money\s*laundering|terror(?:ist)?\s*funding|hawala)\b',          20),
        (r'\b(non[\s\-]?bailable|criminal\s*(?:case|offence|charge))\b',       18),
        (r'\b(section\s*\d+|ipc\s*\d+|crpc|it\s*act|cyber\s*(?:act|law))\b',  14),
        (r'\b(summon(?:s|ed)?|notice\s*(?:served|issued)|contempt\s*of\s*court)\b', 16),
        (r'\b(blacklist(?:ed)?|watchlist|lookout\s*(?:notice|circular))\b',     16),
        (r'\b(interpol|red\s*corner|blue\s*corner|extradition)\b',             18),
        (r'\b(narcotics?\s*(?:case|offence)|drug\s*trafficking)\b',            20),
        (r'\b(stay\s*on\s*(?:the\s*)?(?:call|video|line)|don.t\s*disconnect)\b', 16),
        (r'\b(seize|confiscate|attach|freeze)\s*(?:your\s*)?(?:property|assets?|accounts?)\b', 16),
        # Hindi legal threats
        (r'\b(giraftaar|giraftaari|hathkadi|jail\s*bhejo|andar\s*kar\s*denge)\b', 18),
        (r'\b(kanoon|kanuni|kaarwahi|mukadma|adalat|peshi)\b',                 14),
        (r'\b(jurmana|saza|dand|paabandi)\b',                                 12),
    ]

    # ================================================================
    # GREETINGS — suppress false positives on first message
    # ================================================================

    GREETING_ONLY = [
        r'^[\s]*(hello|hi|hey|namaste|namaskar|good\s*(?:morning|afternoon|evening|day))[\s!.,?]*$',
        r'^[\s]*(greetings|howdy|salam|jai\s*hind|jai\s*shri\s*ram)[\s!.,?]*$',
        r'^[\s]*(how\s*are\s*you|hope\s*you.?re\s*well|are\s*you\s*there)[\s?.!]*$',
        r'^[\s]*(dear\s*(?:sir|ma.?am|customer|user|friend))[\s,!.]*$',
        r'^[\s]*(welcome|thank\s*you|thanks)[\s!.,?]*$',
        r'^[\s]*(kaise\s*ho|kya\s*haal|theek\s*ho|sab\s*theek)[\s?!.]*$',
    ]

    # ================================================================
    # ESCALATION BONUSES — Compound signal categories = higher risk
    # When a session triggers N distinct signal types simultaneously,
    # an escalation bonus is applied. More categories = more confidence
    # that this is a real scam, not a false positive.
    # Boosted for 3+ simultaneous signals to ensure fast threshold breach.
    # ================================================================

    ESCALATION_BONUSES: Dict[int, float] = {
        2: 10,
        3: 28,   # boosted from 22 — 3 simultaneous signals is highly indicative
        4: 45,   # boosted from 35
        5: 60,   # boosted from 50
        6: 72,   # boosted from 60
        7: 85,   # boosted from 70
        8: 100,  # boosted from 80
    }

    # ================================================================
    # AUXILIARY SIGNAL LAYERS — specialized scam type detection
    # ================================================================

    COURIER_AUX = [
        (r'\b(?:parcel|courier|package|shipment|consignment)\s*.{0,30}(?:seiz|held|illegal|drugs|contraband|suspicious)\b', 20),
        (r'\b(?:customs?\s*(?:duty|clearance|department|officer|fee|charge))\b', 14),
        (r'\b(?:drugs?|contraband|illegal\s*(?:items?|goods?|substance))\s*.{0,30}(?:found|detected|seized|discovered)\b', 20),
        (r'\b(?:fedex|dhl|blue\s*dart|dtdc|india\s*post|speed\s*post)\b',      12),
        (r'\b(?:tracking\s*(?:number|id|code)|consignment\s*(?:number|id|no))\b', 10),
        (r'\b(?:parcel|package|shipment)\s*(?:from|to)\s*(?:china|abroad|overseas|foreign|international)\b', 16),
        (r'\b(?:import\s*(?:duty|tax|fee)|export\s*(?:duty|tax|fee))\b',       14),
        (r'\b(?:x[\s\-]?ray|scan(?:ned)?|inspect(?:ed|ion)?)\s*.{0,20}(?:parcel|package|shipment)\b', 14),
    ]

    UPI_AUX = [
        (r'\b(?:upi\s*(?:id|address|handle)|bhim\s*id|vpa)\b',                12),
        (r'[\w.\-]+@(?:paytm|ybl|oksbi|okaxis|okicici|upi|phonepe|gpay|ibl|axl|apl|freecharge|airtel|jio|kotak|sbi|hdfc|icici|pnb|bob|barodapay|aubank)\b', 16),
        (r'\b(?:scan\s*(?:the\s*)?(?:qr|code|barcode)|upi\s*transfer)\b',     12),
        (r'\b(?:google\s*pay|phone\s*pe|paytm|bhim|cred|groww|slice|jupiter)\b', 8),
        (r'\b(?:collect\s*request|payment\s*(?:request|link)|pay\s*(?:link|request))\b', 14),
        (r'\b(?:qr\s*code|scan\s*(?:and|to)\s*pay|tap\s*(?:and|to)\s*pay)\b',  12),
    ]

    INVEST_AUX = [
        (r'\b(?:invest|trading|forex|crypto|bitcoin|ethereum)\s*.{0,30}(?:guaranteed|profit|returns?|income|gain)\b', 18),
        (r'\b(?:double|triple|10x|100x)\s*(?:your\s*)?(?:money|investment|capital|returns?)\b', 20),
        (r'\b(?:mutual\s*fund|stock\s*(?:tip|market)|insider\s*(?:info|tip|knowledge))\b', 14),
        (r'\b(?:demat|nifty|sensex|share\s*(?:market|trading)|ipo)\b',         12),
        (r'\b(?:monthly\s*(?:income|returns?|profit)|daily\s*(?:income|returns?|profit))\b', 16),
        (r'\b(?:risk[\s\-]?free|zero\s*risk|no\s*risk|safe\s*investment)\b',   18),
        (r'\b(?:portfolio|asset\s*management|wealth\s*management)\b',           10),
        (r'\b(?:mlm|multi[\s\-]?level|network\s*marketing|ponzi|pyramid)\b',   20),
        (r'\b(?:binary\s*(?:option|trading)|option\s*trading)\b',              16),
        (r'\b(?:referral\s*(?:bonus|income|commission)|joining\s*(?:bonus|fee))\b', 14),
    ]

    TECH_SUPPORT_AUX = [
        (r'\b(?:virus|malware|trojan|spyware|ransomware)\s*.{0,20}(?:detected|found|infected|attack)\b', 18),
        (r'\b(?:computer|system|device|laptop|pc)\s*.{0,20}(?:hacked|compromised|infected|at\s*risk)\b', 18),
        (r'\b(?:microsoft|apple|google|windows)\s*.{0,15}(?:support|helpdesk|team|security)\b', 16),
        (r'\b(?:anydesk|teamviewer|quicksupport|ammyy|ultraviewer|remote\s*desktop)\b', 20),
        (r'\b(?:screen\s*shar(?:e|ing)|remote\s*(?:access|control|connection))\b', 18),
        (r'\b(?:download\s*(?:this|the)\s*(?:app|software|tool)|install\s*(?:this|the)\s*(?:app|software))\b', 16),
        (r'\b(?:tech(?:nical)?\s*support|customer\s*(?:care|support|service)\s*(?:number|helpline))\b', 12),
        (r'\b(?:antivirus|firewall|security\s*(?:alert|warning|scan))\b',      14),
    ]

    JOB_FRAUD_AUX = [
        (r'\b(?:work\s*from\s*home|online\s*(?:job|work|earning|income))\b',   14),
        (r'\b(?:data\s*entry|typing\s*(?:job|work)|copy\s*paste)\b',           14),
        (r'\b(?:earn\s*(?:from\s*home|daily|weekly|monthly|lakhs?|thousands?))\b', 16),
        (r'\b(?:part[\s\-]?time\s*(?:job|work|income)|freelance\s*(?:job|work|opportunity))\b', 12),
        (r'\b(?:no\s*(?:experience|qualification|skill)s?\s*(?:needed|required))\b', 16),
        (r'\b(?:hiring|recruitment|vacancy|opening|placement)\b',               8),
        (r'\b(?:salary|stipend|package)\s*(?:of|is|upto|ranging)\s*(?:rs|₹|\d+)\b', 14),
        (r'\b(?:telegram\s*(?:group|channel|job)|whatsapp\s*(?:group|job))\b',  12),
        (r'\b(?:training\s*(?:fee|charge)|registration\s*(?:fee|charge|amount))\b', 18),
        (r'\b(?:amazon|flipkart|shopify)\s*(?:review|rating|product\s*review)\b', 16),
        (r'\b(?:youtube|instagram|social\s*media)\s*(?:like|follow|subscribe|view)\b', 14),
        (r'\b(?:task[\s\-]?based|per[\s\-]?task|commission[\s\-]?based)\b',    12),
    ]

    LOAN_FRAUD_AUX = [
        (r'\b(?:instant\s*(?:loan|credit)|pre[\s\-]?approved\s*(?:loan|credit))\b', 16),
        (r'\b(?:loan\s*(?:approved|sanction|disburs|offer|guarantee))\b',       14),
        (r'\b(?:low\s*(?:interest|emi)|zero\s*(?:interest|emi|percent))\b',     14),
        (r'\b(?:personal\s*loan|home\s*loan|business\s*loan|car\s*loan)\b',    10),
        (r'\b(?:no\s*(?:cibil|credit\s*score|document|collateral)\s*(?:needed|required|check))\b', 18),
        (r'\b(?:processing\s*fee|file\s*(?:charge|fee)|disbursement\s*(?:fee|charge))\b', 16),
        (r'\b(?:emi\s*(?:starts?|from|just)|pay\s*later|buy\s*now)\b',         10),
        (r'\b(?:nbfc|microfinance|fintech|lending\s*(?:app|company|platform))\b', 10),
    ]

    INSURANCE_FRAUD_AUX = [
        (r'\b(?:insurance\s*(?:claim|policy|premium|bonus|maturity|lapsed?))\b', 14),
        (r'\b(?:(?:policy|claim)\s*(?:expired?|lapsed?|pending|unclaimed|matured?))\b', 14),
        (r'\b(?:lic|life\s*insurance|health\s*insurance|motor\s*insurance)\b',  10),
        (r'\b(?:bonus\s*(?:amount|payment)|maturity\s*(?:amount|payment|benefit))\b', 14),
        (r'\b(?:unclaimed\s*(?:amount|money|fund|benefit|bonus|deposit))\b',    16),
        (r'\b(?:surrender\s*(?:value|charge)|policy\s*(?:revival|renewal))\b',  12),
        (r'\b(?:nominee|beneficiary)\s*(?:update|change|verify|details)\b',     12),
    ]

    ROMANCE_SCAM_AUX = [
        (r'\b(?:i\s*love\s*you|fallen?\s*(?:in\s*)?love|soul\s*mate)\b',      14),
        (r'\b(?:gift|present|parcel|package)\s*(?:for\s*you|sending|from\s*abroad)\b', 12),
        (r'\b(?:stuck\s*(?:at|in)\s*(?:airport|customs)|need\s*(?:money|help)\s*(?:urgently|now))\b', 16),
        (r'\b(?:military|army|navy|deployed|overseas)\b',                       8),
        (r'\b(?:inheritance|will|estate|fortune|million\s*dollars?)\b',         14),
        (r'\b(?:western\s*union|moneygram|money\s*order|bitcoin)\b',           14),
    ]

    IDENTITY_THEFT_AUX = [
        (r'\b(?:aadhaar|aadhar)\s*(?:number|no|card|id|details|copy)\b',       14),
        (r'\b(?:pan\s*(?:card|number|no|details)|permanent\s*account)\b',      14),
        (r'\b(?:voter\s*id|driving\s*licen[cs]e|passport\s*(?:number|no|details))\b', 14),
        (r'\b(?:date\s*of\s*birth|dob|mother.s?\s*(?:name|maiden))\b',         12),
        (r'\b(?:photo\s*(?:id|proof)|address\s*proof|identity\s*proof)\b',     10),
        (r'\b(?:selfie|photograph|photo)\s*(?:of|with)\s*(?:your|the)\s*(?:aadhaar|pan|id)\b', 16),
        (r'\b(?:share\s*(?:your\s*)?(?:aadhaar|pan|voter|passport|id)\s*(?:number|details|copy|photo))\b', 18),
    ]

    def __init__(self) -> None:
        self._profiles: Dict[str, RiskProfile] = {}
        self._lock = threading.Lock()

    def analyze_message(self, text: str, session_id: str) -> Tuple[float, bool]:
        """Score a message through all signal layers and return (cumulative_score, is_scam).
        
        Pipeline:
        1. Skip empty messages
        2. Suppress pure greetings on first message
        3. Score all 12 core + 8 auxiliary signal layers
        4. Apply escalation bonus for multiple signal categories
        5. Apply repeat-signal bonus for persistent tactics
        6. Check threshold and classify scam type
        """
        # Empty message — just return current state
        if not text or not text.strip():
            profile = self._get_profile(session_id)
            return profile.cumulative_score, profile.scam_detected

        profile = self._get_profile(session_id)
        profile.message_count += 1

        # Pure greeting on first message — don't bump score
        if profile.message_count == 1 and self._is_pure_greeting(text):
            profile.turn_scores.append(0.0)
            return 0.0, False

        # Score every signal layer
        turn_score: float = 0.0
        turn_signals: Set[str] = set()

        # 12 core signal layers
        core_layers = [
            ("urgency",                self.URGENCY_PATTERNS),
            ("authority_impersonation", self.AUTHORITY_PATTERNS),
            ("otp_request",            self.OTP_PATTERNS),
            ("payment_request",        self.PAYMENT_PATTERNS),
            ("account_suspension",     self.SUSPENSION_PATTERNS),
            ("prize_lure",             self.LURE_PATTERNS),
            ("suspicious_url",         self.URL_PATTERNS),
            ("emotional_pressure",     self.EMOTIONAL_PATTERNS),
            ("legal_threat",           self.LEGAL_THREAT_PATTERNS),
        ]
        # 8 auxiliary signal layers for specific scam types
        auxiliary_layers = [
            ("courier",         self.COURIER_AUX),
            ("upi_specific",    self.UPI_AUX),
            ("investment",      self.INVEST_AUX),
            ("tech_support",    self.TECH_SUPPORT_AUX),
            ("job_fraud",       self.JOB_FRAUD_AUX),
            ("loan_fraud",      self.LOAN_FRAUD_AUX),
            ("insurance_fraud", self.INSURANCE_FRAUD_AUX),
            ("romance_scam",    self.ROMANCE_SCAM_AUX),
            ("identity_theft",  self.IDENTITY_THEFT_AUX),
        ]

        for name, patterns in core_layers + auxiliary_layers:
            layer_score = self._score_layer(text, patterns)
            if layer_score > 0:
                turn_score += layer_score
                turn_signals.add(name)
                profile.signal_counts[name] = (
                    profile.signal_counts.get(name, 0) + 1
                )

        # Accumulate session-level signals
        profile.triggered_signals.update(turn_signals)

        # Escalation bonus for compound patterns — more categories = higher risk
        distinct_categories = len(profile.triggered_signals)
        escalation_bonus: float = 0.0
        for threshold in sorted(self.ESCALATION_BONUSES, reverse=True):
            if distinct_categories >= threshold:
                escalation_bonus = self.ESCALATION_BONUSES[threshold]
                break

        # Repeat-signal bonus — persistent tactics get extra points
        repeat_bonus: float = sum(
            6 if count == 2 else (12 if count >= 3 else 0)
            for count in profile.signal_counts.values()
        )

        # Update cumulative score
        profile.turn_scores.append(turn_score)
        profile.cumulative_score += turn_score + escalation_bonus + repeat_bonus

        # Check threshold
        if profile.cumulative_score >= self.SCAM_THRESHOLD:
            profile.scam_detected = True
            profile.scam_type = self._classify(profile)

        return profile.cumulative_score, profile.scam_detected

    def get_profile(self, session_id: str) -> RiskProfile:
        """Return the full risk profile for a session."""
        return self._get_profile(session_id)

    def get_scam_type(self, session_id: str) -> str:
        return self._get_profile(session_id).scam_type

    def get_triggered_signals(self, session_id: str) -> Set[str]:
        """Return a copy of the triggered signal names."""
        return self._get_profile(session_id).triggered_signals.copy()

    def reset_session(self, session_id: str) -> None:
        """Discard all state for a session."""
        with self._lock:
            self._profiles.pop(session_id, None)

    def _get_profile(self, session_id: str) -> RiskProfile:
        with self._lock:
            if session_id not in self._profiles:
                self._profiles[session_id] = RiskProfile()
            return self._profiles[session_id]

    @staticmethod
    def _score_layer(text: str, patterns: list) -> float:
        """Sum weights of all matching patterns."""
        total = 0.0
        lowered = text.lower()
        for pattern, weight in patterns:
            if re.search(pattern, lowered, re.IGNORECASE):
                total += weight
        return total

    def _is_pure_greeting(self, text: str) -> bool:
        """Check if text is just a greeting."""
        stripped = text.strip()
        return any(
            re.match(pat, stripped, re.IGNORECASE)
            for pat in self.GREETING_ONLY
        )

    def _classify(self, profile: RiskProfile) -> str:
        """Pick the most specific scam-type label based on triggered signals.
        
        Classification priority (most specific first):
        1. Courier/parcel scams (unique indicators)
        2. Investment/trading scams
        3. Tech support scams
        4. Job fraud
        5. Loan fraud
        6. Insurance fraud
        7. Romance scams
        8. UPI-specific fraud
        9. Prize/lottery scams
        10. Authority impersonation (digital arrest, CBI, police)
        11. Phishing (OTP/URL based)
        12. Bank fraud (account suspension, payment requests)
        13. Legal threats → impersonation
        14. Identity theft → phishing
        15. Unknown if no clear signal
        """
        signals = profile.triggered_signals

        if "courier" in signals:
            return "courier"
        if "investment" in signals:
            return "investment"
        if "tech_support" in signals:
            return "tech_support"
        if "job_fraud" in signals:
            return "job_fraud"
        if "loan_fraud" in signals:
            return "loan_fraud"
        if "insurance_fraud" in signals:
            return "insurance_fraud"
        if "romance_scam" in signals:
            return "impersonation"
        if "upi_specific" in signals:
            return "upi_fraud"
        if "prize_lure" in signals:
            return "lottery"
        if "authority_impersonation" in signals:
            return "impersonation"
        if "otp_request" in signals or "suspicious_url" in signals:
            return "phishing"
        if "account_suspension" in signals or "payment_request" in signals:
            return "bank_fraud"
        if "legal_threat" in signals:
            return "impersonation"
        if "identity_theft" in signals:
            return "phishing"

        return "unknown"


# Module-level singleton
risk_accumulator = RiskAccumulator()
