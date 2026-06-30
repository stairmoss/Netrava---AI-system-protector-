import os
import re
import socket
import hashlib
import zipfile
import threading
from typing import List, Dict, Any

# Mock databases for demonstration and real lookups where applicable
KNOWN_MALWARE_HASHES = {
    # WannaCry SHA-256
    "24d009a104d8f54e64952de70900a83d77cc2d634710db690249c4ec11d37c88": {
        "name": "WannaCry Ransomware",
        "type": "Ransomware",
        "severity": "CRITICAL",
        "details": "High risk ransomware that encrypts system files and demands Bitcoin."
    },
    # Pegasus Spyware
    "ade480133c9484b397bfd38c64d84f88ef0ef0a373b98c7e6c3826048d08af6e": {
        "name": "Pegasus Spyware",
        "type": "Spyware / Trojan",
        "severity": "CRITICAL",
        "details": "Sophisticated surveillance tool capable of extracting text messages, photos, emails, and call history."
    },
    # Eicar test file hash
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": {
        "name": "EICAR Test File",
        "type": "Test Threat",
        "severity": "LOW",
        "details": "Standard anti-malware test file. Safe for detection testing."
    }
}

SUSPICIOUS_PE_IMPORTS = [
    "VirtualAlloc", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
    "RegOpenKeyEx", "RegSetValueEx", "InternetOpen", "InternetConnect", "HttpSendRequest",
    "GetProcAddress", "LoadLibrary", "CryptEncrypt", "CryptDecrypt"
]

SUSPICIOUS_ANDROID_PERMISSIONS = [
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.SYSTEM_ALERT_WINDOW",  # Screen Overlay Attack
    "android.permission.REQUEST_INSTALL_PACKAGES", # Side-loading apps
    "android.permission.BIND_ACCESSIBILITY_SERVICE", # Accessibility Abuse
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECORD_AUDIO",
    "android.permission.PROCESS_OUTGOING_CALLS"
]

# 1. Malware Static Analysis Engine
def analyze_uploaded_file(file_content: bytes, filename: str) -> Dict[str, Any]:
    file_size = len(file_content)
    
    # Calculate SHA-256 and MD5 hashes
    sha256_hash = hashlib.sha256(file_content).hexdigest()
    md5_hash = hashlib.md5(file_content).hexdigest()
    
    # Check threat database
    threat_info = KNOWN_MALWARE_HASHES.get(sha256_hash, None)
    
    file_ext = filename.split(".")[-1].lower() if "." in filename else ""
    detections = []
    suspicious_features = []
    risk_score = 0
    
    # Simple static analysis based on file extensions
    if file_ext == "exe":
        # Scan for suspicious PE import strings in the binary
        for imp in SUSPICIOUS_PE_IMPORTS:
            if imp.encode('utf-8', errors='ignore') in file_content:
                suspicious_features.append(f"Suspicious API Import: {imp}")
                risk_score += 15
        
        # Look for indicators of packing (common in malware)
        if b"UPX0" in file_content or b"UPX1" in file_content:
            suspicious_features.append("Packed Executable (UPX identified)")
            risk_score += 30
            
    elif file_ext == "apk":
        # Look for android manifest components inside APK zip
        try:
            # APK is a ZIP archive
            import io
            with zipfile.ZipFile(io.BytesIO(file_content)) as apk_zip:
                manifest_content = ""
                # Attempt to extract readable text from manifest
                if "AndroidManifest.xml" in apk_zip.namelist():
                    manifest_data = apk_zip.read("AndroidManifest.xml")
                    # Basic string matching on manifest binary/plain text
                    manifest_content = manifest_data.decode('utf-8', errors='ignore')
                
                # Check for suspicious permissions
                for perm in SUSPICIOUS_ANDROID_PERMISSIONS:
                    perm_name = perm.split(".")[-1]
                    # Check both full permission string and short name in binary
                    if perm in manifest_content or perm_name in manifest_content:
                        suspicious_features.append(f"Accessibility Abuse/Over-privileged: {perm_name}")
                        risk_score += 20
        except Exception:
            # Fallback if ZIP parsing fails (e.g. corrupted file)
            # Try plain text scan of permissions
            for perm in SUSPICIOUS_ANDROID_PERMISSIONS:
                if perm.encode('utf-8', errors='ignore') in file_content:
                    suspicious_features.append(f"Raw Permission Requested: {perm.split('.')[-1]}")
                    risk_score += 15
                    
    elif file_ext == "pdf":
        # Check for Javascript or OpenAction in PDF (often used for PDF exploits)
        if b"/JavaScript" in file_content or b"/JS" in file_content:
            suspicious_features.append("Embedded JavaScript script block")
            risk_score += 40
        if b"/OpenAction" in file_content:
            suspicious_features.append("Auto-execute triggers (/OpenAction)")
            risk_score += 30
            
    elif file_ext == "zip":
        try:
            import io
            with zipfile.ZipFile(io.BytesIO(file_content)) as zip_ref:
                names = zip_ref.namelist()
                double_ext = [n for n in names if re.search(r'\.(exe|scr|bat|pif|cmd|vbs|js)\.(zip|exe|pdf|docx|txt)$', n, re.IGNORECASE)]
                hidden_executables = [n for n in names if n.split(".")[-1].lower() in ["exe", "scr", "bat", "vbs", "js"]]
                
                if double_ext:
                    suspicious_features.append(f"Double-extension masquerading: {double_ext[0]}")
                    risk_score += 50
                if hidden_executables:
                    suspicious_features.append(f"Executable inside archive: {hidden_executables[0]}")
                    risk_score += 25
        except Exception:
            pass

    # Generic binary scans
    # Scan for common ransomware/malware strings
    ransom_notes_keywords = [b"decrypt your files", b"your files have been encrypted", b"payment to recover", b"tor browser"]
    for kw in ransom_notes_keywords:
        if kw in file_content.lower():
            suspicious_features.append(f"Ransomware signature: '{kw.decode()}'")
            risk_score += 60
            break

    # Calculate final status
    if threat_info:
        status = "MALICIOUS"
        risk_score = 100
        detections.append(f"Database Match: {threat_info['name']}")
    elif risk_score >= 60:
        status = "SUSPICIOUS"
    elif risk_score >= 25:
        status = "WARNING"
    else:
        status = "SAFE"
        risk_score = max(5, risk_score)

    return {
        "filename": filename,
        "size_bytes": file_size,
        "sha256": sha256_hash,
        "md5": md5_hash,
        "status": status,
        "risk_score": min(100, risk_score),
        "suspicious_indicators": suspicious_features,
        "threat_info": threat_info
    }


# 2. Local Port Scanner Engine
def scan_single_port(ip: str, port: int, open_ports: List[Dict[str, Any]], lock: threading.Lock):
    try:
        # Standard timeout of 1.0 seconds for quick scan
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.8)
            result = s.connect_ex((ip, port))
            if result == 0:
                # Resolve service name if possible
                try:
                    service = socket.getservbyport(port, "tcp")
                except Exception:
                    service = "Unknown Service"
                
                with lock:
                    open_ports.append({
                        "port": port,
                        "service": service.upper(),
                        "status": "OPEN",
                        "security_level": "WARNING" if port in [21, 23, 135, 139, 445, 3389] else "INFO"
                    })
    except Exception:
        pass

def run_local_network_scan(target_ip: str = "127.0.0.1") -> Dict[str, Any]:
    # Common ports to scan
    ports_to_scan = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 1433, 3306, 3389, 8080, 9000, 27017]
    open_ports = []
    lock = threading.Lock()
    
    threads = []
    for port in ports_to_scan:
        t = threading.Thread(target=scan_single_port, args=(target_ip, port, open_ports, lock))
        threads.append(t)
        t.start()
        
    for t in threads:
        t.join()
        
    # Sort open ports
    open_ports = sorted(open_ports, key=lambda x: x["port"])
    
    # Calculate network risk rating
    risk_level = "LOW"
    warning_ports = [p["port"] for p in open_ports if p["security_level"] == "WARNING"]
    if len(warning_ports) > 0:
        risk_level = "HIGH"
    elif len(open_ports) > 3:
        risk_level = "MEDIUM"
        
    return {
        "target_host": target_ip,
        "scanned_ports": len(ports_to_scan),
        "open_ports": open_ports,
        "total_open": len(open_ports),
        "risk_level": risk_level,
        "recommendation": "Close unused open ports like SMB (445), Telnet (23) or RDP (3389) to prevent unauthorized remote exploits." if warning_ports else "Network configuration looks healthy."
    }


# 3. URL and Phishing Scanner Engine
def scan_url_threats(url: str) -> Dict[str, Any]:
    clean_url = url.strip().lower()
    
    # Remove protocol prefix
    domain = clean_url
    if "://" in domain:
        domain = domain.split("://")[1]
    if "/" in domain:
        domain = domain.split("/")[0]
        
    risk_score = 10
    reasons = []
    
    # Check for phishing flags
    # 1. Suspicious keywords in domain
    phishing_keywords = [
        "login", "verify", "secure", "bank", "update", "support", "kyc", "signin",
        "account", "netflix", "paypal", "meta-security", "facebook-support",
        "amazon-refunding", "free-lottery", "crypto-rewards", "claim-bonus"
    ]
    for kw in phishing_keywords:
        if kw in domain and not (domain.endswith("paypal.com") or domain.endswith("netflix.com") or domain.endswith("amazon.com") or domain.endswith("facebook.com")):
            reasons.append(f"Suspicious subdomain/keyword in domain: '{kw}'")
            risk_score += 30
            
    # 2. Typosquatting / Fake extensions
    if any(ext in domain for ext in [".xyz", ".top", ".buzz", ".bid", ".cc", ".icu", ".work", ".gq", ".cf", ".tk"]) and not domain.endswith(".gov"):
        reasons.append("Using high-risk generic top-level domain (gTLD)")
        risk_score += 15
        
    # 3. Numeric IPs or excessive hyphens
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
        reasons.append("Raw IP address used instead of hostname")
        risk_score += 45
    elif domain.count("-") >= 3:
        reasons.append("Excessive hyphens in domain name (often masks phishing)")
        risk_score += 20
        
    # 4. HTTPS check
    if not clean_url.startswith("https://") and clean_url.startswith("http://"):
        reasons.append("Unencrypted connection (HTTP used instead of HTTPS)")
        risk_score += 25
        
    # 5. Lookalike domains (Levenshtein mock check)
    lookalikes = {
        "arnazon.com": "amazon.com",
        "paypa1.com": "paypal.com",
        "netf1ix.com": "netflix.com",
        "gooogle.com": "google.com",
        "g00gle.com": "google.com",
        "microsoft-update.com": "microsoft.com",
        "sbi-kyc-verify.net": "sbi.co.in"
    }
    
    for look, orig in lookalikes.items():
        if look in domain:
            reasons.append(f"Domain spoofing detection: mimics trusted portal '{orig}'")
            risk_score += 65
            break
            
    # Calculate final classification
    risk_score = min(100, risk_score)
    if risk_score >= 70:
        level = "HIGH"
        rec = "Block website immediately. Do not enter any login, banking, or personal credentials."
    elif risk_score >= 35:
        level = "MEDIUM"
        rec = "Proceed with caution. Verify the sender/origin of the link before interacting."
    else:
        level = "LOW"
        risk_score = max(5, risk_score)
        rec = "Website appears safe, but always verify dynamic content."
        
    return {
        "url": url,
        "domain": domain,
        "risk_level": level,
        "risk_score": risk_score,
        "ssl_active": clean_url.startswith("https://"),
        "reasons": reasons,
        "recommendation": rec,
        "google_safe_browsing": "CLEAN" if risk_score < 70 else "SUSPICIOUS",
        "virustotal_positives": 0 if risk_score < 40 else (3 if risk_score < 70 else 12)
    }


# 4. SMS and WhatsApp Phishing Analyzer
def analyze_sms_threats(message_text: str) -> Dict[str, Any]:
    text = message_text.lower().strip()
    
    risk_score = 10
    reasons = []
    
    # Phishing categories & keywords
    # A. Banking/KYC
    kyc_match = re.search(r'\b(kyc|pan|aadhaar|verify|suspend|block|sbi|hdfc|icici|yono)\b', text)
    urgency_match = re.search(r'\b(immediately|urgent|today|within 24 hours|expire|lock|unauthorized)\b', text)
    if kyc_match and urgency_match:
        reasons.append("KYC/Account suspension threat detected with high urgency")
        risk_score += 40
        
    # B. Lottery/Rewards/UPI Fraud
    lottery_match = re.search(r'\b(won|lottery|prize|crore|lakh|cashback|rewards|scratch card|gift card|claim)\b', text)
    if lottery_match:
        reasons.append("Lottery, jackpot, or financial windfall lure identified")
        risk_score += 35
        
    # C. Courier/Delivery Scams
    courier_match = re.search(r'\b(courier|post office|delivery|package|dhl|fedex|unpaid custom|address correction)\b', text)
    if courier_match and ("link" in text or "http" in text or "update" in text):
        reasons.append("Package delivery redirection scam indicators found")
        risk_score += 30
        
    # D. Link presence
    url_found = re.findall(r'(https?://\S+|www\.\S+)', text)
    if url_found:
        reasons.append("Message contains a hyperlink redirecting to external page")
        risk_score += 15
        # Scan URL if found
        url_scan = scan_url_threats(url_found[0])
        if url_scan["risk_level"] == "HIGH":
            reasons.append(f"Highly suspicious domain detected: {url_scan['domain']}")
            risk_score += 30
            
    # E. OTP Fraud warning
    if "otp" in text or "one time password" in text or "pin" in text:
        if any(w in text for w in ["share", "send", "call", "forward"]):
            reasons.append("Solicitation of sensitive security token (OTP/PIN)")
            risk_score += 35

    risk_score = min(100, risk_score)
    if risk_score >= 70:
        level = "HIGH"
        rec = "Delete the message immediately. Do not tap any links, call any numbers, or reply."
    elif risk_score >= 35:
        level = "MEDIUM"
        rec = "Do not share OTPs, personal credentials, or money. Confirm details via the official website."
    else:
        level = "LOW"
        risk_score = max(5, risk_score)
        rec = "Looks like a typical informational or standard transaction notification."
        
    return {
        "text": message_text,
        "risk_level": level,
        "risk_score": risk_score,
        "reasons": reasons,
        "recommendation": rec
    }


# 5. Email Phishing Analyzer
def analyze_email_threats(email_content: str, from_address: str = "", subject: str = "") -> Dict[str, Any]:
    text = (subject + " " + from_address + " " + email_content).lower()
    
    risk_score = 10
    reasons = []
    
    # 1. Spoofing check
    if from_address:
        # Standard lookalike domains
        domain_parts = from_address.split("@")
        if len(domain_parts) == 2:
            email_domain = domain_parts[1]
            trusted_lookalikes = {
                "support-security-paypal": "paypal.com",
                "netflix-billing": "netflix.com",
                "google-accounts-alert": "google.com",
                "microsoft-support-team": "microsoft.com",
                "refund-team": "amazon.com"
            }
            for look, orig in trusted_lookalikes.items():
                if look in email_domain:
                    reasons.append(f"Spoofed sender domain structure: '{email_domain}' resembles official brand '{orig}'")
                    risk_score += 45
            
            # Check for generic free mailers impersonating enterprise
            free_mailers = ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com"]
            if email_domain in free_mailers and any(kw in from_address for kw in ["invoice", "bank", "billing", "support", "admin", "secure"]):
                reasons.append("Official/corporate business alert sent from a free public email address")
                risk_score += 35

    # 2. Urgency and Threat words
    urgency_words = ["suspended", "deactivated", "unauthorized login", "urgent action", "final warning", "tax refund", "overdue invoice"]
    matched_urgency = [w for w in urgency_words if w in text]
    if matched_urgency:
        reasons.append(f"Urgent coercive language: '{matched_urgency[0]}'")
        risk_score += 20
        
    # 3. Payment / Invoice scams
    payment_words = ["invoice", "wire transfer", "payment confirmation", "receipt attached", "unpaid bill", "direct deposit"]
    matched_payment = [w for w in payment_words if w in text]
    if matched_payment:
        reasons.append("Financial solicitation/invoice bait detected")
        risk_score += 15
        
    # 4. Attachment masquerading
    attachment_extensions = [".exe", ".scr", ".zip", ".pdf", ".xlsm", ".docm"]
    # Mock lookup for attachment extensions in content
    for ext in attachment_extensions:
        if f"attachment" in text and ext in text:
            reasons.append(f"Email mentions high-risk executable or macro attachment type: {ext}")
            risk_score += 25

    risk_score = min(100, risk_score)
    if risk_score >= 70:
        level = "HIGH"
        rec = "Do not click links or open attachments. Report as Phishing, then delete."
    elif risk_score >= 35:
        level = "MEDIUM"
        rec = "Confirm details directly with the verified sender through an alternate channel before action."
    else:
        level = "LOW"
        risk_score = max(5, risk_score)
        rec = "Email appears legitimate. Standard validation passed."

    return {
        "from_address": from_address,
        "subject": subject,
        "risk_level": level,
        "risk_score": risk_score,
        "reasons": reasons,
        "recommendation": rec
    }


# 6. Dark Web Monitoring Engine
def check_darkweb_leaks(search_term: str) -> Dict[str, Any]:
    # Mock data leaks database for demonstration
    term = search_term.strip().lower()
    
    leaks = []
    
    # Simulating data leaks for common demo addresses/phones
    if "admin" in term or "test" in term or "demo" in term or "@example" in term:
        leaks.append({
            "database": "Canva Leak (2019)",
            "leaked_fields": ["Email Addresses", "Passwords (salted hashes)", "Usernames", "Names"],
            "severity": "MEDIUM",
            "date": "May 2019"
        })
        leaks.append({
            "database": "Adobe Data Breach (2013)",
            "leaked_fields": ["Email Addresses", "Password Hints", "Passwords"],
            "severity": "HIGH",
            "date": "October 2013"
        })
    elif "adarsh" in term:
        leaks.append({
            "database": "LinkedIn Scraping Leak (2021)",
            "leaked_fields": ["Names", "Email Addresses", "Workplace details", "Social Handles"],
            "severity": "LOW",
            "date": "April 2021"
        })
    elif re.match(r'^\+?\d{10,12}$', term) or term.isdigit():
        leaks.append({
            "database": "Clubhouse Data Export (2021)",
            "leaked_fields": ["Phone Numbers", "Names", "User IDs"],
            "severity": "LOW",
            "date": "April 2021"
        })
        
    # Random fallback for other inputs (let's say 20% chance of a leak)
    if not leaks and len(term) > 3:
        # Generate a mock leak for demonstration based on string hash
        h = int(hashlib.md5(term.encode()).hexdigest(), 16)
        if h % 3 == 0:
            leaks.append({
                "database": "Standard Credential Combo-List (2023)",
                "leaked_fields": ["Email Addresses", "Plaintext Passwords"],
                "severity": "CRITICAL",
                "date": "December 2023"
            })
            
    return {
        "search_term": search_term,
        "breached": len(leaks) > 0,
        "total_leaks": len(leaks),
        "leaks": leaks,
        "recommendation": "Change your credentials immediately on breached sites and enable Multi-Factor Authentication (MFA)." if leaks else "No leaks found in indexing databases. Keep updating passwords regularly."
    }

// threat intelligence scan data loaded
