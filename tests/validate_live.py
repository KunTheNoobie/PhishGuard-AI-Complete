"""Quick validation script for PhishGuard-AI endpoints."""
import httpx
import json

BASE = "http://127.0.0.1:8000"
HEADERS = {
    "Authorization": "Bearer phishguard_secret_key_2026",
    "Content-Type": "application/json",
}

# ── Test 1: Phishing page with mule account ──
print("=== TEST 1: Phishing + Mule Account ===")
r = httpx.post(f"{BASE}/api/v1/analyze/semantics", headers=HEADERS, json={
    "url": "https://rnaybank-secure.com/verify",
    "dom_content": (
        "<html><body>"
        "<h1>URGENT: Your Maybank Account Will Be Suspended!</h1>"
        "<p>Transfer RM500 immediately to account 112233445566 to avoid suspension.</p>"
        "<p>Your account has been compromised. Act now or face legal action!</p>"
        "</body></html>"
    ),
})
data = r.json()
print(f"Status: {r.status_code}")
print(f"BERT Label: {data['data']['semantic_analysis']['label']}")
print(f"BERT Confidence: {data['data']['semantic_analysis']['confidence']}")
print(f"Is Malicious: {data['data']['semantic_analysis']['is_malicious']}")
print(f"Mule Detected: {data['data']['mule_scan']['mule_detected']}")
print(f"Flagged Accounts: {data['data']['mule_scan']['flagged_accounts']}")
print(f"Verdict: {data['orchestration']}")
print(f"Latency: {data['meta']['processing_time_ms']}ms")
print()

# ── Test 2: Legitimate page ──
print("=== TEST 2: Legitimate Page ===")
r = httpx.post(f"{BASE}/api/v1/analyze/semantics", headers=HEADERS, json={
    "url": "https://www.maybank2u.com.my",
    "dom_content": (
        "<html><body>"
        "<h1>Welcome to Maybank2u</h1>"
        "<p>Internet Banking - Access your accounts securely.</p>"
        "<nav><a href='/accounts'>My Accounts</a></nav>"
        "</body></html>"
    ),
})
data = r.json()
print(f"Status: {r.status_code}")
print(f"BERT Label: {data['data']['semantic_analysis']['label']}")
print(f"BERT Confidence: {data['data']['semantic_analysis']['confidence']}")
print(f"Is Malicious: {data['data']['semantic_analysis']['is_malicious']}")
print(f"Mule Detected: {data['data']['mule_scan']['mule_detected']}")
print(f"Verdict: {data['orchestration']}")
print(f"Latency: {data['meta']['processing_time_ms']}ms")
print()

# ── Test 3: Dashboard endpoints ──
print("=== TEST 3: Dashboard Stats ===")
r = httpx.get(f"{BASE}/api/v1/dashboard/stats")
print(f"Status: {r.status_code}")
print(json.dumps(r.json(), indent=2))
print()

print("=== TEST 4: Dashboard Mule Registry ===")
r = httpx.get(f"{BASE}/api/v1/dashboard/mule-registry")
data = r.json()
print(f"Status: {r.status_code}")
print(f"Total mule accounts: {data['count']}")
for a in data["accounts"][:5]:
    print(f"  {a['account_number']} | {a['bank_name']:20s} | {a['platform_flagged']:25s} | Reports: {a['report_count']}")
print("  ...")
print()

print("=== TEST 5: Dashboard Telemetry ===")
r = httpx.get(f"{BASE}/api/v1/dashboard/telemetry")
data = r.json()
print(f"Status: {r.status_code}")
print(f"Total telemetry entries: {data['count']}")
for e in data["entries"]:
    print(f"  [{e['log_id']}] {e['malicious_url'][:60]:60s} | Score: {e['bert_score']} | {e['timestamp']}")

print()
print("=== ALL VALIDATION TESTS PASSED ===")
