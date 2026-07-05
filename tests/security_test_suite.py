import json
import requests
import io
import time

BASE_URL = "http://127.0.0.1:8000"

# Harmless EICAR Signature
EICAR_STRING = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

TEST_CASES = {
    "url_scan": [
        {"url": "http://fake-login-sbi-yono.cc", "expected_risk": "HIGH"},
        {"url": "http://127.0.0.1:8000", "expected_risk": "MEDIUM"},
        {"url": "https://google.com", "expected_risk": "LOW"},
        {"url": "", "expected_status": 400}, 
        {"url": "A" * 1000, "expected_risk": "LOW"}, 
        {"url": "' OR '1'='1", "expected_risk": "LOW"}, 
        {"url": "<script>alert('xss')</script>", "expected_risk": "LOW"}, 
    ],
    "sms_scan": [
        {"text": "Your power will disconnect tonight at 9:30 PM due to unpaid electricity bill. Contact BSES officer at 9988776655. Click www.bses-billcheck.com", "expected_risk": "HIGH"},
        {"text": "Mumbai Crime Branch alert: CBI has seized custom packet containing MDMA in your Aadhaar name. You are under digital arrest. Click www.cbi-police.in", "expected_risk": "HIGH"},
        {"text": "Claim PhonePe cashback reward of Rs 5000, scan QR and enter UPI PIN", "expected_risk": "HIGH"},
        {"text": "Urgent! Google Maps review rating jobs, earn Rs 5000 daily. Scan QR code to claim. Join telegram channel at www.telegram.me/ratingjob", "expected_risk": "HIGH"},
        {"text": "Meeting at 5pm today", "expected_risk": "LOW"},
        {"text": "", "expected_status": 400}, 
        {"text": "A" * 5000, "expected_risk": "LOW"}, 
        {"text": "'; DROP TABLE users; --", "expected_risk": "LOW"}, 
    ],
    "email_scan": [
        {"content": "Your account is suspended due to unauthorized login. Access the attached invoice immediately.", "from_address": "support@netflix-billing.com", "subject": "Final warning about suspended account", "expected_risk": "HIGH"},
        {"content": "Normal business communications about the project roadmap.", "from_address": "manager@company.com", "subject": "Project Status", "expected_risk": "LOW"},
        {"content": "", "from_address": "", "subject": "", "expected_status": 400}, 
    ],
    "scamcall_transcribe": [
        {"transcript": "This is Mumbai Customs department, MDMA drugs found in your Aadhaar package, you are under digital arrest", "expected_risk": "CRITICAL"},
        {"transcript": "Please install AnyDesk and pay your electricity bill cutoff", "expected_risk": "HIGH"},
        {"transcript": "Congratulations, you won KBC 25 lakh lottery processing fee", "expected_risk": "HIGH"},
        {"transcript": "Hello, how are you doing today?", "expected_risk": "LOW"},
        {"transcript": "' OR '1'='1", "expected_risk": "LOW"},
    ],
    "assistant_chat": [
        {"message": "tell me about digital arrest", "contains": "digital arrest"},
        {"message": "what is electricity cutoff scam?", "contains": "electricity"},
        {"message": "<script>alert('XSS')</script>", "contains": ""}, 
        {"message": "'; SELECT * FROM logs; --", "contains": ""}, 
    ]
}

report = []
report.append("# Netrava Security Validation Suite Report")
report.append(f"Generated at: {time.strftime('%Y-%m-%d %H:%M:%S')}")
report.append("\n## Test Configuration")
report.append(f"- **Target Server**: {BASE_URL}")
report.append("- **Security Test Suite Version**: 1.0.0 (Pragmatic Mock Suite)")

def run_tests():
    # 1. Server Health Check
    try:
        r = requests.get(f"{BASE_URL}/api")
        if r.status_code == 200:
            report.append("- **Server Connection**: ONLINE (FastAPI is active)")
        else:
            report.append(f"- **Server Connection**: FAILED (Status: {r.status_code})")
            return
    except Exception as e:
        report.append(f"- **Server Connection**: CRITICAL ERROR (Could not connect: {str(e)})")
        return

    # 2. Test Malware Upload (EICAR)
    report.append("\n## 1. Malware Static Analysis Engine Tests")
    try:
        file_data = io.BytesIO(EICAR_STRING.encode('utf-8'))
        r = requests.post(f"{BASE_URL}/api/scan/malware", files={"file": ("eicar_test.txt", file_data)})
        if r.status_code == 200:
            data = r.json()
            status = data.get("status")
            threat = data.get("threat_info", {}).get("name", "Unknown")
            report.append(f"| Test Scenario | Payload | Status Code | Risk Status | Threat Name | Result |")
            report.append(f"|---|---|---|---|---|---|")
            report.append(f"| EICAR Malware Signature | EICAR Standard Antivirus Test | {r.status_code} | {status} | {threat} | {'PASS (Detected)' if status == 'MALICIOUS' else 'FAIL'} |")
        else:
            report.append(f"- EICAR Test failed with status code {r.status_code}: {r.text}")

        normal_data = io.BytesIO(b"Hello world. This is a clean text file.")
        r = requests.post(f"{BASE_URL}/api/scan/malware", files={"file": ("safe.txt", normal_data)})
        if r.status_code == 200:
            data = r.json()
            status = data.get("status")
            report.append(f"| Safe File Scan | Standard Text Payload | {r.status_code} | {status} | - | {'PASS (Clean)' if status == 'SAFE' else 'FAIL'} |")
    except Exception as e:
        report.append(f"- Exception in malware scan tests: {str(e)}")

    # 3. URL scan tests
    report.append("\n## 2. URL and Phishing Scanner Tests")
    report.append("| Test URL | Expected Level | Actual Level | Status Code | Result |")
    report.append("|---|---|---|---|---|")
    for case in TEST_CASES["url_scan"]:
        url = case["url"]
        payload = {"url": url}
        try:
            r = requests.post(f"{BASE_URL}/api/scan/url", json=payload)
            if "expected_status" in case:
                expected_st = case["expected_status"]
                is_pass = r.status_code == expected_st
                report.append(f"| `{url[:40]}` (Invalid) | Status {expected_st} | Status {r.status_code} | {r.status_code} | {'PASS (Mitigated)' if is_pass else 'FAIL'} |")
            else:
                data = r.json()
                actual_risk = data.get("risk_level")
                is_pass = actual_risk == case["expected_risk"]
                report.append(f"| `{url[:40]}` | {case['expected_risk']} | {actual_risk} | {r.status_code} | {'PASS' if is_pass else 'FAIL'} |")
        except Exception as e:
            report.append(f"| `{url[:40]}` | Exception | {str(e)} | - | FAIL |")

    # 4. SMS scan tests
    report.append("\n## 3. SMS and Phishing Analyzer Tests")
    report.append("| Test SMS Text | Expected Level | Actual Level | Status Code | Result |")
    report.append("|---|---|---|---|---|")
    for case in TEST_CASES["sms_scan"]:
        text = case["text"]
        payload = {"text": text}
        try:
            r = requests.post(f"{BASE_URL}/api/scan/sms", json=payload)
            if "expected_status" in case:
                expected_st = case["expected_status"]
                is_pass = r.status_code == expected_st
                report.append(f"| `{text[:40]}` (Invalid) | Status {expected_st} | Status {r.status_code} | {r.status_code} | {'PASS (Mitigated)' if is_pass else 'FAIL'} |")
            else:
                data = r.json()
                actual_risk = data.get("risk_level")
                is_pass = actual_risk == case["expected_risk"]
                report.append(f"| `{text[:40]}` | {case['expected_risk']} | {actual_risk} | {r.status_code} | {'PASS' if is_pass else 'FAIL'} |")
        except Exception as e:
            report.append(f"| `{text[:40]}` | Exception | {str(e)} | - | FAIL |")

    # 5. Email scan tests
    report.append("\n## 4. Email Header Phishing Scanner Tests")
    report.append("| Test Subject | Expected Level | Actual Level | Status Code | Result |")
    report.append("|---|---|---|---|---|")
    for case in TEST_CASES["email_scan"]:
        payload = {"content": case["content"], "from_address": case["from_address"], "subject": case["subject"]}
        try:
            r = requests.post(f"{BASE_URL}/api/scan/email", json=payload)
            if "expected_status" in case:
                expected_st = case["expected_status"]
                is_pass = r.status_code == expected_st
                report.append(f"| `{case['subject'][:40]}` (Invalid) | Status {expected_st} | Status {r.status_code} | {r.status_code} | {'PASS (Mitigated)' if is_pass else 'FAIL'} |")
            else:
                data = r.json()
                actual_risk = data.get("risk_level")
                is_pass = actual_risk == case["expected_risk"]
                report.append(f"| `{case['subject'][:40]}` | {case['expected_risk']} | {actual_risk} | {r.status_code} | {'PASS' if is_pass else 'FAIL'} |")
        except Exception as e:
            report.append(f"| `{case['subject'][:40]}` | Exception | {str(e)} | - | FAIL |")

    # 6. Call Transcription scam detection tests
    report.append("\n## 5. Live Scam Call Analysis Tests")
    report.append("| Transcript Snippet | Expected Risk | Actual Risk | Warning Triggered | Result |")
    report.append("|---|---|---|---|---|")
    for case in TEST_CASES["scamcall_transcribe"]:
        payload = {"transcript": case["transcript"]}
        try:
            r = requests.post(f"{BASE_URL}/api/scamcall/transcribe", json=payload)
            data = r.json()
            actual_risk = data.get("risk_level")
            warning = data.get("warning")
            is_pass = actual_risk == case["expected_risk"]
            report.append(f"| `{case['transcript'][:40]}` | {case['expected_risk']} | {actual_risk} | {warning[:40]} | {'PASS' if is_pass else 'FAIL'} |")
        except Exception as e:
            report.append(f"| `{case['transcript'][:40]}` | Exception | {str(e)} | - | FAIL |")

    # 7. AI Chatbot tests
    report.append("\n## 6. AI Chatbot Fuzzing and Content Verification")
    report.append("| Prompt Message | Response Preview | Result |")
    report.append("|---|---|---|")
    for case in TEST_CASES["assistant_chat"]:
        payload = {"message": case["message"]}
        try:
            r = requests.post(f"{BASE_URL}/api/assistant/chat", json=payload)
            data = r.json()
            reply = data.get("reply", "")
            contains = case["contains"]
            is_pass = (contains in reply.lower()) if contains else True
            report.append(f"| `{case['message'][:40]}` | `{reply.replace('\n', ' ')[:60]}...` | {'PASS' if is_pass else 'FAIL'} |")
        except Exception as e:
            report.append(f"| `{case['message'][:40]}` | Exception: {str(e)} | FAIL |")

    # 8. Local Port Audit test
    report.append("\n## 7. Local Port Audit Constraints")
    try:
        r = requests.post(f"{BASE_URL}/api/scan/port?target=127.0.0.1")
        if r.status_code == 200:
            report.append("- Local scan target (`127.0.0.1`): PASS (Allowed)")
        else:
            report.append(f"- Local scan target (`127.0.0.1`): FAIL (Status: {r.status_code})")

        r = requests.post(f"{BASE_URL}/api/scan/port?target=8.8.8.8")
        if r.status_code == 403:
            report.append("- Public scan target (`8.8.8.8`): PASS (Mitigated / Blocked with 403 Forbidden)")
        else:
            report.append(f"- Public scan target (`8.8.8.8`): FAIL (Status: {r.status_code}, allowed scan of public address!)")
    except Exception as e:
        report.append(f"- Exception in port audit tests: {str(e)}")

    # 9. Write out report file
    report_content = "\n".join(report)
    with open("tests/security_test_report.md", "w") as f:
        f.write(report_content)
    print("Testing completed. Report generated at 'tests/security_test_report.md'")

if __name__ == "__main__":
    run_tests()
