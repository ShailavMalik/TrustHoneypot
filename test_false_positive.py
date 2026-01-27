"""Test that innocent messages don't trigger false positives."""
from app.detector import detector
from app.extractor import extractor

# Test the EXACT case from the screenshot - innocent messages
session_id = 'test-non-scam-001'

messages = [
    'Hi',
    'Just checking in.',
    'Hope you are well.',
    'Let me know if you need anything.',
    'Hello, how are you?'
]

print('Testing innocent messages:')
print('=' * 50)

for msg in messages:
    score, is_scam = detector.calculate_risk_score(msg, session_id)
    intel = extractor.extract(msg, session_id)
    print(f'Message: "{msg}"')
    print(f'  Score: {score}, Is Scam: {is_scam}')

print()
print('=' * 50)
details = detector.get_detection_details(session_id)
print(f'FINAL RESULT:')
print(f'  Total Score: {details.total_score}')
print(f'  Is Scam: {details.is_scam}')
print(f'  Risk Level: {details.risk_level}')
print(f'  Confidence: {details.confidence:.0%}')
print(f'  Categories: {details.triggered_categories}')

intel = extractor.extract('', session_id)
print(f'  Keywords Found: {intel["suspiciousKeywords"]}')

print()
print('=' * 50)
print('PASS!' if not details.is_scam else 'FAIL - Still detecting as scam!')
