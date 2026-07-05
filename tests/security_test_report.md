# Netrava Security Validation Suite Report
Generated at: 2026-07-05 08:54:08

## Test Configuration
- **Target Server**: http://127.0.0.1:8000
- **Security Test Suite Version**: 1.0.0 (Pragmatic Mock Suite)
- **Server Connection**: ONLINE (FastAPI is active)

## 1. Malware Static Analysis Engine Tests
| Test Scenario | Payload | Status Code | Risk Status | Threat Name | Result |
|---|---|---|---|---|---|
| EICAR Malware Signature | EICAR Standard Antivirus Test | 200 | MALICIOUS | EICAR Test File | PASS (Detected) |
| Safe File Scan | Standard Text Payload | 200 | SAFE | - | PASS (Clean) |

## 2. URL and Phishing Scanner Tests
| Test URL | Expected Level | Actual Level | Status Code | Result |
|---|---|---|---|---|
| `http://fake-login-sbi-yono.cc` | HIGH | HIGH | 200 | PASS |
| `http://127.0.0.1:8000` | MEDIUM | MEDIUM | 200 | PASS |
| `https://google.com` | LOW | LOW | 200 | PASS |
| `` (Invalid) | Status 400 | Status 400 | 400 | PASS (Mitigated) |
| `AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA` | LOW | LOW | 200 | PASS |
| `' OR '1'='1` | LOW | LOW | 200 | PASS |
| `<script>alert('xss')</script>` | LOW | LOW | 200 | PASS |

## 3. SMS and Phishing Analyzer Tests
| Test SMS Text | Expected Level | Actual Level | Status Code | Result |
|---|---|---|---|---|
| `Your power will disconnect tonight at 9:` | HIGH | HIGH | 200 | PASS |
| `Mumbai Crime Branch alert: CBI has seize` | HIGH | HIGH | 200 | PASS |
| `Claim PhonePe cashback reward of Rs 5000` | HIGH | HIGH | 200 | PASS |
| `Urgent! Google Maps review rating jobs, ` | HIGH | HIGH | 200 | PASS |
| `Meeting at 5pm today` | LOW | LOW | 200 | PASS |
| `` (Invalid) | Status 400 | Status 400 | 400 | PASS (Mitigated) |
| `AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA` | LOW | LOW | 200 | PASS |
| `'; DROP TABLE users; --` | LOW | LOW | 200 | PASS |

## 4. Email Header Phishing Scanner Tests
| Test Subject | Expected Level | Actual Level | Status Code | Result |
|---|---|---|---|---|
| `Final warning about suspended account` | HIGH | HIGH | 200 | PASS |
| `Project Status` | LOW | LOW | 200 | PASS |
| `` (Invalid) | Status 400 | Status 400 | 400 | PASS (Mitigated) |

## 5. Live Scam Call Analysis Tests
| Transcript Snippet | Expected Risk | Actual Risk | Warning Triggered | Result |
|---|---|---|---|---|
| `This is Mumbai Customs department, MDMA ` | CRITICAL | CRITICAL | CRITICAL THREAT: Fake Police / Digital A | PASS |
| `Please install AnyDesk and pay your elec` | HIGH | HIGH | HIGH RISK: Caller requests installing re | PASS |
| `Congratulations, you won KBC 25 lakh lot` | HIGH | HIGH | HIGH RISK: Fake KBC / Lucky Draw Lottery | PASS |
| `Hello, how are you doing today?` | LOW | LOW | No suspicious triggers detected. | PASS |
| `' OR '1'='1` | LOW | LOW | No suspicious triggers detected. | PASS |

## 6. AI Chatbot Fuzzing and Content Verification
| Prompt Message | Response Preview | Result |
|---|---|---|
| `tell me about digital arrest` | `**Digital Arrest & Police Impersonation Scam**  This is a ma...` | PASS |
| `what is electricity cutoff scam?` | `**Electricity Bill Cut-off Scam**  Scammers send messages wa...` | PASS |
| `<script>alert('XSS')</script>` | `**Welcome to Netrava Indian Cybercrime Support**  I am speci...` | PASS |
| `'; SELECT * FROM logs; --` | `**Welcome to Netrava Indian Cybercrime Support**  I am speci...` | PASS |

## 7. Local Port Audit Constraints
- Local scan target (`127.0.0.1`): PASS (Allowed)
- Public scan target (`8.8.8.8`): PASS (Mitigated / Blocked with 403 Forbidden)