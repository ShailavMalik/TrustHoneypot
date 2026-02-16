"""Validate the final output format matches documentation."""
from app.callback import build_final_output
import json

# Test the new format
output = build_final_output(
    session_id='test-format-check',
    scam_detected=True,
    scam_type='bank_fraud',  # This should NOT appear in output
    intelligence={
        'phoneNumbers': ['+91-1234567890'],
        'bankAccounts': ['1234567890'],
        'upiIds': ['test@upi'],
        'phishingLinks': [],
        'emailAddresses': ['test@email.com']
    },
    total_messages=10,
    duration_seconds=120,
    agent_notes='Test agent notes'
)

print('FINAL OUTPUT FORMAT:')
print(json.dumps(output, indent=2))

# Validate structure
required = ['sessionId', 'scamDetected', 'totalMessagesExchanged', 'extractedIntelligence', 'engagementMetrics', 'agentNotes']
forbidden = ['status', 'scamType', 'suspiciousKeywords']

print()
print('VALIDATION:')
for f in required:
    status = "PRESENT" if f in output else "MISSING"
    print(f'  {f}: {status}')

for f in forbidden:
    if f == 'suspiciousKeywords':
        found = f in output.get('extractedIntelligence', {})
    else:
        found = f in output
    status = "FOUND (ERROR)" if found else "NOT PRESENT (OK)"
    print(f'  {f}: {status}')

# Validate extractedIntelligence has exactly 5 fields
intel_fields = ['phoneNumbers', 'bankAccounts', 'upiIds', 'phishingLinks', 'emailAddresses']
intel = output.get('extractedIntelligence', {})
print()
print('EXTRACTED INTELLIGENCE FIELDS:')
for f in intel_fields:
    status = "PRESENT" if f in intel else "MISSING"
    print(f'  {f}: {status}')

extra = set(intel.keys()) - set(intel_fields)
if extra:
    print(f'  EXTRA FIELDS (ERROR): {extra}')
else:
    print('  No extra fields (OK)')
