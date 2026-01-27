"""Test that real scam messages are still detected correctly."""
from app.detector import detector
from app.extractor import extractor

print("Testing REAL SCAM messages (should be detected):")
print("=" * 60)

# Test real scam scenarios
scam_tests = [
    ("test-scam-rbi", [
        "This is RBI calling about your account.",
        "Your account will be blocked. Complete KYC immediately.",
        "Send Rs 500 processing fee to verify@paytm"
    ]),
    ("test-scam-digital-arrest", [
        "This is CBI officer speaking.",
        "A case is registered against your Aadhaar.",
        "You are under digital arrest. Stay on video call.",
        "Transfer Rs 50000 to avoid arrest warrant."
    ]),
    ("test-scam-lottery", [
        "Congratulations! You have won a lottery prize of Rs 10 lakhs!",
        "Send processing fee of Rs 2000 to claim your prize.",
        "Pay to account 12345678901234 IFSC HDFC0001234"
    ]),
]

for session_id, messages in scam_tests:
    detector.reset_session(session_id)
    print(f"\n{session_id}:")
    for msg in messages:
        score, is_scam = detector.calculate_risk_score(msg, session_id)
        extractor.extract(msg, session_id)
    
    details = detector.get_detection_details(session_id)
    status = "✅ DETECTED" if details.is_scam else "❌ MISSED"
    print(f"  {status} | Score: {details.total_score} | Risk: {details.risk_level} | Conf: {details.confidence:.0%} | Type: {details.scam_type}")

print("\n" + "=" * 60)
print("Testing INNOCENT messages (should NOT be detected):")
print("=" * 60)

innocent_tests = [
    ("test-innocent-1", [
        "Hi", "Just checking in.", "Hope you are well.",
        "Let me know if you need anything.", "Hello, how are you?"
    ]),
    ("test-innocent-2", [
        "Good morning!", "How was your weekend?",
        "Did you finish the project?", "Let's meet for coffee.",
        "See you tomorrow!"
    ]),
    ("test-innocent-3", [
        "Thank you for your help.", "I appreciate your support.",
        "The meeting went well.", "Looking forward to next time.",
        "Have a great day!"
    ]),
]

all_passed = True
for session_id, messages in innocent_tests:
    detector.reset_session(session_id)
    print(f"\n{session_id}:")
    for msg in messages:
        score, is_scam = detector.calculate_risk_score(msg, session_id)
        extractor.extract(msg, session_id)
    
    details = detector.get_detection_details(session_id)
    if details.is_scam:
        status = "❌ FALSE POSITIVE"
        all_passed = False
    else:
        status = "✅ CORRECT (not scam)"
    print(f"  {status} | Score: {details.total_score} | Risk: {details.risk_level}")

print("\n" + "=" * 60)
if all_passed:
    print("✅ ALL TESTS PASSED!")
else:
    print("❌ SOME TESTS FAILED - Review false positives")
