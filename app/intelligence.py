"""
Intelligence Registry & Pattern Correlation Engine — TrustHoneypot v2.2

Manages a registry of extracted identifiers (UPI, Phone, Email, Bank, Link)
with risk scoring, confidence, occurrence tracking, and session linking.

Also implements a lightweight pattern correlation engine that generates
pattern fingerprints and detects recurring tactics across sessions.
"""
import hashlib
import re
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set

logger = logging.getLogger(__name__)

# ── Fraud type classification ──────────────────────────────────────────────

FRAUD_TYPE_MAP = {
    "bank_impersonation": "KYC PHISHING",
    "account_threat": "KYC PHISHING",
    "phishing": "KYC PHISHING",
    "credential_phishing": "KYC PHISHING",
    "identity_threat": "KYC PHISHING",
    "payment_scam": "PAYMENT FRAUD",
    "refund_scam": "PAYMENT FRAUD",
    "urgent_action": "PAYMENT FRAUD",
    "lottery_scam": "LOTTERY SCAM",
    "investment_scam": "PAYMENT FRAUD",
    "crypto_scam": "PAYMENT FRAUD",
    "government_impersonation": "IMPERSONATION",
    "govt_threat": "IMPERSONATION",
    "telecom_scam": "IMPERSONATION",
    "telecom_impersonation": "IMPERSONATION",
    "digital_arrest": "IMPERSONATION",
    "courier_scam": "IMPERSONATION",
    "intimidation_scam": "IMPERSONATION",
    "identity_theft": "KYC PHISHING",
    "job_scam": "JOB SCAM",
    "loan_scam": "PAYMENT FRAUD",
    "job_loan_scam": "JOB SCAM",
    "generic_scam": "GENERIC SCAM",
    "unknown": "MONITORING",
}

FRAUD_TYPE_COLORS = {
    "PAYMENT FRAUD": "red",
    "KYC PHISHING": "amber",
    "LOTTERY SCAM": "purple",
    "JOB SCAM": "orange",
    "IMPERSONATION": "blue",
    "GENERIC SCAM": "slate",
    "MONITORING": "slate",
}


def classify_fraud_type(scam_type: str) -> str:
    """Map internal scam_type to a human-readable fraud label."""
    return FRAUD_TYPE_MAP.get(scam_type, "GENERIC SCAM")


def get_fraud_color(fraud_type: str) -> str:
    """Return badge color for a fraud type."""
    return FRAUD_TYPE_COLORS.get(fraud_type, "slate")


# ── Identifier type detection ──────────────────────────────────────────────

def _detect_identifier_type(value: str) -> str:
    """Detect the type of an identifier from its value."""
    v = value.strip().lower()
    if "@" in v and not re.match(r'.+@.+\..+', v):
        return "UPI"
    if re.match(r'.+@.+\..{2,}', v):
        return "Email"
    if re.match(r'^https?://', v) or re.match(r'^(bit\.ly|tinyurl|goo\.gl|t\.co|wa\.me|t\.me)', v):
        return "Link"
    if re.match(r'^\d{9,18}$', v):
        return "Bank"
    if re.match(r'^\d{10}$', v) and v[0] in "6789":
        return "Phone"
    return "Other"


def mask_identifier(value: str, id_type: str | None = None) -> str:
    """Mask sensitive numeric identifiers for privacy."""
    if id_type is None:
        id_type = _detect_identifier_type(value)
    if id_type == "Phone" and len(value) >= 10:
        return value[:2] + "****" + value[-4:]
    if id_type == "Bank" and len(value) >= 9:
        return value[:2] + "*" * (len(value) - 4) + value[-2:]
    if id_type == "UPI":
        parts = value.split("@")
        if len(parts) == 2 and len(parts[0]) > 2:
            return parts[0][:2] + "***@" + parts[1]
    return value


# ── Pattern Fingerprint ───────────────────────────────────────────────────

def generate_pattern_hash(scam_type: str, tactics: List[str], identifiers: List[str]) -> str:
    """
    Generate a pattern fingerprint from session characteristics.
    Used for correlating similar scam patterns across sessions.
    """
    components = [
        scam_type or "unknown",
        "|".join(sorted(set(tactics))) if tactics else "",
        "|".join(sorted(set(_detect_identifier_type(i) for i in identifiers))) if identifiers else "",
    ]
    raw = "::".join(components).lower()
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def compute_similarity_score(hash_a: str, hash_b: str, type_a: str, type_b: str,
                              tactics_a: List[str], tactics_b: List[str]) -> float:
    """
    Compute similarity between two sessions based on scam type,
    tactics overlap, and pattern hash match.
    Returns 0.0 to 1.0.
    """
    score = 0.0
    # Exact pattern hash match
    if hash_a == hash_b:
        return 1.0
    # Same scam type
    if type_a and type_b and type_a == type_b:
        score += 0.4
    # Tactics overlap (Jaccard similarity)
    set_a = set(tactics_a) if tactics_a else set()
    set_b = set(tactics_b) if tactics_b else set()
    if set_a and set_b:
        jaccard = len(set_a & set_b) / len(set_a | set_b)
        score += 0.6 * jaccard
    return round(min(score, 1.0), 2)


# ── Detection Reasoning Generator ─────────────────────────────────────────

def generate_detection_reasoning(
    scam_type: str,
    risk_level: str,
    confidence: float,
    tactics: List[str],
    intelligence_counts: Dict[str, int],
    pattern_match_count: int = 0,
    similarity_score: float = 0.0,
    recurring: bool = False,
    risk_score: int = 0,
) -> Dict:
    """
    Generate structured detection reasoning for session analysis.
    
    v2.2: Only generates full reasoning when risk_score >= REASONING_THRESHOLD (40).
    Below threshold, returns a minimal "monitoring" verdict.
    """
    from detector import detector as _det
    
    fraud_label = classify_fraud_type(scam_type)
    
    # v2.2: Below reasoning threshold → return minimal info
    if risk_score < _det.REASONING_THRESHOLD:
        return {
            "verdict": "MONITORING — No scam indicators confirmed",
            "fraud_type": fraud_label,
            "fraud_color": get_fraud_color(fraud_label),
            "risk_level": risk_level,
            "confidence": confidence,
            "similarity_score": 0.0,
            "recurring": False,
            "pattern_match_count": 0,
            "reasons": [],
        }
    
    reasons = []

    # Analyze tactics for reasoning
    urgency_tactics = [t for t in tactics if "urgency" in t.lower() or "urgent" in t.lower() or "pressure" in t.lower()]
    payment_tactics = [t for t in tactics if "payment" in t.lower() or "transfer" in t.lower() or "upi" in t.lower()]
    threat_tactics = [t for t in tactics if "threat" in t.lower() or "arrest" in t.lower() or "legal" in t.lower()]
    identity_tactics = [t for t in tactics if "kyc" in t.lower() or "verify" in t.lower() or "aadhaar" in t.lower()]

    if urgency_tactics:
        reasons.append("Urgency pattern detected")
    if payment_tactics:
        reasons.append("Payment redirection attempt")
    if threat_tactics:
        reasons.append("Threat/intimidation tactics used")
    if identity_tactics:
        reasons.append("Identity verification scam pattern")

    # Intel-based reasoning
    total_intel = sum(intelligence_counts.values()) if intelligence_counts else 0
    if total_intel > 0:
        reasons.append(f"Identifier recurrence detected ({total_intel} items extracted)")

    if recurring:
        reasons.append("Recurring indicator flag active")

    if pattern_match_count > 0:
        reasons.append(f"Similar pattern used in {pattern_match_count} previous sessions")

    if confidence >= 0.8:
        reasons.append("Escalation speed above threshold")
    elif confidence >= 0.6:
        reasons.append("Moderate escalation detected")

    if not reasons:
        reasons.append("Multiple scam indicators triggered")

    # v2.2: Verdict reflects actual state
    if risk_score >= _det.SCAM_THRESHOLD:
        verdict = f"SCAM CONFIRMED — {fraud_label}"
    elif risk_score >= _det.REASONING_THRESHOLD:
        verdict = f"SUSPICIOUS — {fraud_label} indicators detected"
    else:
        verdict = "MONITORING — No scam indicators confirmed"

    return {
        "verdict": verdict,
        "fraud_type": fraud_label,
        "fraud_color": get_fraud_color(fraud_label),
        "risk_level": risk_level,
        "confidence": confidence,
        "similarity_score": similarity_score,
        "recurring": recurring,
        "pattern_match_count": pattern_match_count,
        "reasons": reasons,
    }


# ── Intelligence Registry Service (DB-backed) ─────────────────────────────

class IntelligenceRegistryService:
    """
    Manages the intelligence_registry collection in MongoDB.
    Tracks unique identifiers across sessions with metadata.
    """

    def __init__(self, db_service):
        self.db = db_service

    def _get_collection(self):
        if not self.db._ensure_connected():
            return None
        return self.db.db.intelligence_registry

    def upsert_identifier(
        self,
        value: str,
        id_type: str,
        risk_level: str,
        confidence: float,
        session_id: str,
    ):
        """Insert or update an identifier in the registry."""
        coll = self._get_collection()
        if coll is None:
            return
        try:
            masked = mask_identifier(value, id_type)
            now = datetime.now(timezone.utc)
            existing = coll.find_one({"value": value})
            if existing:
                sessions = existing.get("sessions", [])
                if session_id not in sessions:
                    sessions.append(session_id)
                coll.update_one(
                    {"value": value},
                    {"$set": {
                        "riskLevel": risk_level,
                        "confidence": max(confidence, existing.get("confidence", 0)),
                        "lastSeen": now,
                        "masked": masked,
                        "sessions": sessions,
                    },
                    "$inc": {"occurrences": 1}},
                )
            else:
                coll.insert_one({
                    "value": value,
                    "masked": masked,
                    "type": id_type,
                    "riskLevel": risk_level,
                    "confidence": confidence,
                    "occurrences": 1,
                    "firstSeen": now,
                    "lastSeen": now,
                    "sessions": [session_id],
                })
        except Exception as e:
            logger.error(f"Failed to upsert identifier: {e}")

    def register_session_intelligence(
        self,
        session_id: str,
        intelligence: dict,
        risk_level: str,
        confidence: float,
    ):
        """Register all extracted intelligence from a session."""
        type_map = {
            "upiIds": "UPI",
            "phoneNumbers": "Phone",
            "emails": "Email",
            "bankAccounts": "Bank",
            "phishingLinks": "Link",
        }
        for field, id_type in type_map.items():
            for value in intelligence.get(field, []):
                if value:
                    self.upsert_identifier(value, id_type, risk_level, confidence, session_id)

    def get_registry(self, id_type: str | None = None, risk_level: str | None = None,
                     limit: int = 100) -> List[dict]:
        """Fetch registry entries with optional filters."""
        coll = self._get_collection()
        if coll is None:
            return []
        try:
            query = {}
            if id_type:
                query["type"] = id_type
            if risk_level:
                query["riskLevel"] = risk_level
            from pymongo import DESCENDING
            cursor = coll.find(query, {"_id": 0}).sort("lastSeen", DESCENDING).limit(limit)
            results = []
            for doc in cursor:
                # Serialize dates
                for k in ("firstSeen", "lastSeen"):
                    if doc.get(k) and hasattr(doc[k], "isoformat"):
                        doc[k] = doc[k].isoformat()
                results.append(doc)
            return results
        except Exception as e:
            logger.error(f"Failed to fetch registry: {e}")
            return []

    def get_identifier_detail(self, value: str) -> Optional[dict]:
        """Get detailed info for a single identifier."""
        coll = self._get_collection()
        if coll is None:
            return None
        try:
            doc = coll.find_one({"value": value}, {"_id": 0})
            if doc:
                for k in ("firstSeen", "lastSeen"):
                    if doc.get(k) and hasattr(doc[k], "isoformat"):
                        doc[k] = doc[k].isoformat()
            return doc
        except Exception as e:
            logger.error(f"Failed to fetch identifier detail: {e}")
            return None

    def get_registry_stats(self) -> dict:
        """Get summary statistics for the registry."""
        coll = self._get_collection()
        if coll is None:
            return {"total": 0, "by_type": {}, "by_risk": {}}
        try:
            total = coll.count_documents({})
            type_pipeline = [{"$group": {"_id": "$type", "count": {"$sum": 1}}}]
            risk_pipeline = [{"$group": {"_id": "$riskLevel", "count": {"$sum": 1}}}]
            by_type = {r["_id"]: r["count"] for r in coll.aggregate(type_pipeline)}
            by_risk = {r["_id"]: r["count"] for r in coll.aggregate(risk_pipeline)}
            return {"total": total, "by_type": by_type, "by_risk": by_risk}
        except Exception as e:
            logger.error(f"Failed to get registry stats: {e}")
            return {"total": 0, "by_type": {}, "by_risk": {}}


# ── Pattern Correlation Service (DB-backed) ───────────────────────────────

class PatternCorrelationService:
    """
    Lightweight pattern correlation engine.
    Stores pattern hashes and enables cross-session correlation.
    """

    def __init__(self, db_service):
        self.db = db_service

    def _get_collection(self):
        if not self.db._ensure_connected():
            return None
        return self.db.db.pattern_registry

    def register_pattern(
        self,
        session_id: str,
        scam_type: str,
        tactics: List[str],
        identifiers: List[str],
        risk_level: str,
        confidence: float,
    ) -> dict:
        """
        Register a pattern for a session and find correlations.
        Returns correlation info: pattern_hash, match_count, similar_sessions.
        """
        pattern_hash = generate_pattern_hash(scam_type, tactics, identifiers)
        coll = self._get_collection()

        result = {
            "pattern_hash": pattern_hash,
            "match_count": 0,
            "similar_sessions": [],
            "recurring": False,
            "similarity_score": 0.0,
        }

        if coll is None:
            return result

        try:
            now = datetime.now(timezone.utc)
            # Find existing patterns with same hash
            existing = list(coll.find(
                {"patternHash": pattern_hash, "sessionId": {"$ne": session_id}},
                {"_id": 0, "sessionId": 1}
            ))
            match_count = len(existing)
            similar_sessions = [e["sessionId"] for e in existing[:10]]

            # Compute similarity with most recent matching session
            similarity = 0.0
            if match_count > 0:
                recent = coll.find_one(
                    {"patternHash": pattern_hash, "sessionId": {"$ne": session_id}},
                    {"_id": 0},
                    sort=[("timestamp", -1)]
                )
                if recent:
                    similarity = compute_similarity_score(
                        pattern_hash, recent.get("patternHash", ""),
                        scam_type, recent.get("scamType", ""),
                        tactics, recent.get("tactics", [])
                    )

            # Upsert this session's pattern
            fraud_label = classify_fraud_type(scam_type)
            coll.update_one(
                {"sessionId": session_id},
                {"$set": {
                    "sessionId": session_id,
                    "patternHash": pattern_hash,
                    "scamType": scam_type,
                    "fraudType": fraud_label,
                    "tactics": tactics,
                    "identifierTypes": list(set(_detect_identifier_type(i) for i in identifiers)) if identifiers else [],
                    "riskLevel": risk_level,
                    "confidence": confidence,
                    "timestamp": now,
                }},
                upsert=True,
            )

            result["match_count"] = match_count
            result["similar_sessions"] = similar_sessions
            result["recurring"] = match_count > 0
            result["similarity_score"] = similarity if match_count > 0 else 0.0

        except Exception as e:
            logger.error(f"Failed to register pattern: {e}")

        return result

    def get_pattern_stats(self) -> dict:
        """Get pattern frequency statistics."""
        coll = self._get_collection()
        empty = {"total_patterns": 0, "top_patterns": [], "recurring_count": 0, "avg_similarity": 0.0, "unique_scam_types": 0}
        if coll is None:
            return empty
        try:
            pipeline = [
                {"$group": {
                    "_id": "$patternHash",
                    "count": {"$sum": 1},
                    "scamType": {"$first": "$scamType"},
                    "fraudType": {"$first": "$fraudType"},
                    "tactics": {"$first": "$tactics"},
                }},
                {"$sort": {"count": -1}},
                {"$limit": 20},
            ]
            top = list(coll.aggregate(pipeline))
            recurring = sum(1 for p in top if p["count"] > 1)
            total = coll.count_documents({})
            scam_types = set(p.get("fraudType") or classify_fraud_type(p.get("scamType", "unknown")) for p in top)
            avg_sim = round(recurring / max(len(top), 1), 2) if top else 0.0
            return {
                "total_patterns": total,
                "top_patterns": [
                    {
                        "hash": p["_id"],
                        "count": p["count"],
                        "scam_type": p.get("fraudType") or classify_fraud_type(p.get("scamType", "unknown")),
                        "tactics": p.get("tactics", [])[:5],
                    }
                    for p in top
                ],
                "recurring_count": recurring,
                "avg_similarity": avg_sim,
                "unique_scam_types": len(scam_types),
            }
        except Exception as e:
            logger.error(f"Failed to get pattern stats: {e}")
            return empty
