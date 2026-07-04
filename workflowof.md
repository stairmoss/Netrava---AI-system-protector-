# Netrava AI Cyber Guardian - System Workflows

This document outlines the step-by-step user workflows for configuring, validating, and interacting with the real-time security systems inside Netrava.

---

## 🚀 Getting Started

### 1. Launching the Security Backend
The backend must be running to enable process controls, file uploads, socket scanning, and USB auditing:
```bash
cd backend
source venv/bin/activate
pip install -r requirements.txt
python main.py
```
*The backend initiates an HTTP listener at `http://127.0.0.1:8000/`.*

### 2. Launching the Security Dashboard
Start the Vite development web server in a separate terminal:
```bash
npm install
npm run dev
```
*Open your web browser and navigate to `http://localhost:5174/` to view the interface.*

---

## 🛡️ Module Workflows

### 1. Communication Shield (Comm Guard)

#### Live VoIP Call Auditing
1. Navigate to the **Comm Guard** tab.
2. Select a voice room (e.g. `#general-lounge` or `📞 External VoIP Hotline`).
3. **Consent Dialog Overlay**: A native browser popup will appear requesting permission:
   > *"Should Netrava hear this call to check if the caller is scamming?"*
4. Click **OK (Yes)**.
5. **Real-time Speech Recognition**: Click the microphone icon to begin speaking. The Web Speech API will transcribe your voice live.
6. **Desktop Notifications**: If you grant permission, Netrava pushes a native desktop notification reading `🛡️ Netrava Call Guard ACTIVE` or `🔒 Private Call Session` (if you click **Cancel** on the consent prompt).
7. **Simulated Scenarios**: Click any mock scenario (e.g., *Bank Account Spoofing Call*) to test the AI’s warning engine without speaking.

#### SMS / WhatsApp / URL / Email Scans
* **SMS & WhatsApp Scanner**: Paste your message (or click a template like *Fake KYC Suspension*) and click **Scan Message**. The AI checks for fake payment domains and urgent text.
* **URL Phishing Scanner**: Paste any link (e.g., `http://sbi-kyc-verify.net`) and click **Scan Link** to retrieve domain age warnings and VirusTotal reputation indicators.
* **Email Phishing Auditor**: Paste raw email headers/text and verify fake sender masquerading rules.

---

### 2. Device Shield (Device Guard)

#### System Process Watcher & Sentinel
1. Open the **Device Guard** tab and scroll to **System Process Watcher**.
2. Netrava queries the active host processes sorted by CPU usage.
3. **Rogue Sentinel Prompt**: The background monitor audits processes every 5 seconds. If a process uses `>75%` CPU or contains keywords like `miner`, `trojan`, or `malicious`, a native blocking warning appears:
   > *"Should Netrava eliminate this process to secure the system?"*
4. Click **OK (Yes)** to kill the process on the host, or click **Cancel (No)** to bypass.
5. To kill any other process manually, click the red **Kill** button next to its entry in the process table.

#### Malware Static Signature Scanner
1. Go to the **Malware File Scanner** panel.
2. Drag and drop or upload any executable, APK, PDF, or ZIP file.
3. **Standard Validation (EICAR Test)**:
   * Upload the provided `eicar_test.txt` signature file from the root directory.
   * Netrava calculates the SHA-256 hash (`275a021b...`) and matches it against the signature database.
4. **Active Quarantine Prompt**:
   * A native warning popup will prompt:
     > *"Should Netrava eliminate/quarantine this file from local storage?"*
   * Click **OK (Yes)** to clear the file from the visual buffer and write quarantine logs to the system feed.

#### USB Auditor
1. Scroll to the **USB Hardware Audit** section.
2. Click **Scan USB Bus** to read live USB hardware tree nodes straight from `/sys/bus/usb/devices/` on your host.

---

### 3. Network Auditor (Net Guard)

1. Open the **Net Guard** tab.
2. Enter a local subnet IP or loopback address (e.g., `127.0.0.1` or `localhost`).
3. Click **Scan Active Ports**.
4. Netrava runs a multi-threaded socket probe (`socket.connect_ex`) against common administrative port bindings.
5. Review the **Administrative Port Matrix** to identify exposed listeners (e.g. SSH `22`, HTTP `80`, or SMB `445`).

---

### 4. AI Chatbot & Password strength Auditor

1. Open the **AI Chatbot** tab.
2. Type any security query (e.g. *"What should I do if infected by malware?"*) to receive guidelines.
3. **Offline Password Strength Auditor**:
   * Type a password in the input field.
   * Netrava evaluates character entropy offline and flags weakness alerts if your password lacks symbols or is vulnerable to dictionary attacks.
