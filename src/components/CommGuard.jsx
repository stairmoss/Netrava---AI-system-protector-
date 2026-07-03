import React, { useState, useEffect, useRef } from 'react';
import { 
  MessageSquare, 
  Phone, 
  Mail, 
  AlertOctagon, 
  CheckCircle, 
  Clock, 
  Play, 
  StopCircle, 
  UploadCloud,
  ChevronRight,
  ShieldAlert,
  Volume2,
  Mic,
  MicOff,
  LogOut,
  Users,
  Hash,
  VolumeX,
  Lock,
  Eye,
  EyeOff
} from 'lucide-react';

const SMS_TEMPLATES = [
  {
    title: "Fake KYC Suspension",
    text: "Dear SBI User, Your YONO NetBanking account will be blocked today. Please click http://sbi-kyc-verify.net to update your PAN Card immediately."
  },
  {
    title: "Fake Courier Unpaid Customs",
    text: "DHL Delivery Alert: Your package is held at the sorting office due to unpaid custom fee of Rs.48. Update address and pay now at: http://dhl-correction-portal.xyz"
  },
  {
    title: "Lottery Reward",
    text: "CONGRATULATIONS! Your mobile number has won Rs. 25,000,000 in KBC Lottery. To claim your prize cash reward, call our department manager on +919988776655."
  },
  {
    title: "Normal OTP notification",
    text: "Your one-time password (OTP) for transaction of Rs 1,200 at Amazon India is 849204. Do not share this with anyone. Valid for 10 minutes."
  }
];

const MOCK_SCENARIOS = [
  {
    label: "Bank Account Spoofing Call",
    transcript: [
      "Hello, I am the senior manager from the credit card security department.",
      "We detected an unauthorized transaction of forty-five thousand rupees on your card.",
      "To cancel this transaction, we need to verify your identity.",
      "I have sent a six digit security confirmation code to your mobile phone number.",
      "Please read that OTP to me so I can cancel the transaction."
    ]
  },
  {
    label: "Fake Courier Support Call",
    transcript: [
      "Hello, this is DHL express courier support.",
      "We have a parcel containing illegal passports under your Aadhaar number.",
      "This package is seized by the custom police department.",
      "You must connect to the cyber police team immediately via our video link.",
      "Please download AnyDesk remote software from the app store for security verification."
    ]
  },
  {
    label: "Safe Family Check-in Call",
    transcript: [
      "Hi, just calling to check if you reached home safely.",
      "Let me know if you need anything from the supermarket for dinner.",
      "I will be back home by seven pm. See you soon!"
    ]
  }
];

const EMAIL_TEMPLATES = [
  {
    from: "security-alert@paypa1.com",
    subject: "Urgent: Your PayPal account has been limited",
    content: "Dear Customer, we detected suspicious logins from Russia. Your account has been temporarily restricted. To restore access, click the link below and upload your credit card billing details: http://secure-paypal-login.xyz/resolve.html"
  },
  {
    from: "billing@office-accounting.com",
    subject: "Overdue Invoice #94820",
    content: "Please find attached the receipt for your recent order. The amount of $1,842.00 is due immediately. Kindly open the attached invoice spreadsheet to review billing details."
  }
];

export default function CommGuard({ addLog, addAlert }) {
  // SMS States
  const [smsInput, setSmsInput] = useState("");
  const [smsResult, setSmsResult] = useState(null);
  const [smsLoading, setSmsLoading] = useState(false);

  // Email States
  const [emailFrom, setEmailFrom] = useState("");
  const [emailSubject, setEmailSubject] = useState("");
  const [emailBody, setEmailBody] = useState("");
  const [emailResult, setEmailResult] = useState(null);
  const [emailLoading, setEmailLoading] = useState(false);

  // Huddle Call States
  const [selectedChannel, setSelectedChannel] = useState(null);
  const [callStatus, setCallStatus] = useState("IDLE"); // IDLE, ASKING_CONSENT, CONNECTED
  const [netravaMonitor, setNetravaMonitor] = useState(true);
  const [callTranscript, setCallTranscript] = useState([]);
  const [callAnalysis, setCallAnalysis] = useState(null);
  const [customSpeechText, setCustomSpeechText] = useState("");
  const [micActive, setMicActive] = useState(false);
  const [waveHeights, setWaveHeights] = useState([20, 40, 15, 30, 50, 25, 45, 10]);

  // Speech Recognition Ref
  const recognitionRef = useRef(null);
  const scenarioTimerRef = useRef(null);

  // Animate Voice Waveform when connected
  useEffect(() => {
    let interval;
    if (callStatus === "CONNECTED") {
      interval = setInterval(() => {
        setWaveHeights(Array.from({ length: 8 }, () => Math.floor(Math.random() * 55) + 10));
      }, 150);
    }
    return () => clearInterval(interval);
  }, [callStatus]);

  // Clean up timers on unmount & request notification permissions
  useEffect(() => {
    if (window.Notification && Notification.permission === 'default') {
      Notification.requestPermission();
    }
    return () => {
      if (scenarioTimerRef.current) clearTimeout(scenarioTimerRef.current);
      if (recognitionRef.current) {
        recognitionRef.current.stop();
      }
    };
  }, []);

  // SMS Scanning Routine
  const scanSMS = async (textToScan) => {
    const text = textToScan || smsInput;
    if (!text) return;
    setSmsLoading(true);
    addLog('SMS_SCAN', 'Scanning SMS content keywords & redirects...', 'info');

    try {
      const res = await fetch('/api/scan/sms', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text })
      });
      if (res.ok) {
        const data = await res.json();
        setSmsResult(data);
        if (data.risk_level === 'HIGH') {
          addAlert('Phishing SMS Blocked', 'HIGH', data.reasons[0] || 'Malicious link detected');
          addLog('SMS_SCAN', `SMS Scam detected. Risk: HIGH. Reason: ${data.reasons.join(', ')}`, 'error');
        } else {
          addLog('SMS_SCAN', `Scan finished. Risk level: ${data.risk_level}`, 'info');
        }
      }
    } catch (err) {
      addLog('SMS_SCAN', 'Backend communication failed. Running fallback offline parser.', 'warning');
      const hasLink = text.includes("http");
      setSmsResult({
        text,
        risk_level: hasLink ? "HIGH" : "LOW",
        risk_score: hasLink ? 85 : 10,
        reasons: hasLink ? ["Contains an external web link", "Potential domain mismatch"] : ["No threat triggers found"],
        recommendation: hasLink ? "Delete and block immediately." : "Looks clean."
      });
    } finally {
      setSmsLoading(false);
    }
  };

  // Email Phishing Scan
  const scanEmail = async () => {
    if (!emailBody) return;
    setEmailLoading(true);
    addLog('EMAIL_SCAN', `Inspecting mail from ${emailFrom || 'unknown'} for headers & macros...`, 'info');

    try {
      const res = await fetch('/api/scan/email', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          content: emailBody,
          from_address: emailFrom,
          subject: emailSubject
        })
      });
      if (res.ok) {
        const data = await res.json();
        setEmailResult(data);
        if (data.risk_level === 'HIGH') {
          addAlert('Email Phishing Stopped', 'HIGH', `Spoofing attempt detected: ${data.reasons[0]}`);
          addLog('EMAIL_SCAN', `Phishing Detected. Risk: ${data.risk_level}. Reasons: ${data.reasons.join(', ')}`, 'error');
        } else {
          addLog('EMAIL_SCAN', `Scan complete. Result: ${data.risk_level}`, 'info');
        }
      }
    } catch (err) {
      addLog('EMAIL_SCAN', 'Network error. Scanning locally.', 'warning');
      setEmailResult({
        from_address: emailFrom,
        subject: emailSubject,
        risk_level: "MEDIUM",
        risk_score: 55,
        reasons: ["Unable to verify SMTP records due to network failure."],
        recommendation: "Cross check sender before reading attachments."
      });
    } finally {
      setEmailLoading(false);
    }
  };

  const loadEmailTemplate = (tpl) => {
    setEmailFrom(tpl.from);
    setEmailSubject(tpl.subject);
    setEmailBody(tpl.content);
  };

  // Huddle / VoIP Call Management
  const selectChannelAndPrompt = (chanName) => {
    // Request notification permission if needed
    if (window.Notification && Notification.permission === 'default') {
      Notification.requestPermission();
    }

    // Native OS-level blocking confirmation pop-up
    const agree = window.confirm(
      `Netrava Shield Protocol\n\nChannel: #${chanName}\n\nShould Netrava hear this call to check if the caller is scamming?`
    );

    setSelectedChannel(chanName);
    setNetravaMonitor(agree);
    setCallStatus("CONNECTED");
    setCallTranscript([]);
    setCallAnalysis(null);

    // Native Desktop Notification pop-up
    if (window.Notification && Notification.permission === 'granted') {
      try {
        const title = agree ? "🛡️ Netrava Call Guard ACTIVE" : "🔒 Private Call Session";
        const body = agree 
          ? `Now scanning voice data on #${chanName} for OTP/bank spoofing indicators.`
          : `Call scanning is disabled. Your communication on #${chanName} is private.`;
        
        const notif = new Notification(title, {
          body,
          icon: "/favicon.svg"
        });
        notif.onclick = () => {
          window.focus();
        };
      } catch (err) {
        console.error("Desktop notification failed", err);
      }
    }

    addLog('HUDDLE_CALL', `Joined channel #${chanName}. Privacy guard: ${agree ? 'ENABLED (Auditing Speech)' : 'DISABLED (Bypassed)'}`, agree ? 'info' : 'warning');
  };

  const handleConsentAnswer = (agree) => {
    setNetravaMonitor(agree);
    setCallStatus("CONNECTED");
    addLog('HUDDLE_CALL', `Joined channel #${selectedChannel}. Privacy guard: ${agree ? 'ENABLED (Auditing Speech)' : 'DISABLED (Bypassed)'}`, agree ? 'info' : 'warning');
  };

  const leaveHuddle = () => {
    stopMicListening();
    if (scenarioTimerRef.current) clearTimeout(scenarioTimerRef.current);
    setSelectedChannel(null);
    setCallStatus("IDLE");
    setCallTranscript([]);
    setCallAnalysis(null);
    addLog('HUDDLE_CALL', 'Left huddle voice channel.', 'info');
  };

  // Analyze Accumulative Speech Text
  const analyzeCallTranscript = async (text) => {
    try {
      const res = await fetch('/api/scamcall/transcribe', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ transcript: text })
      });
      if (res.ok) {
        const data = await res.json();
        setCallAnalysis(data);
        if (data.risk_level === 'CRITICAL' || data.risk_level === 'HIGH') {
          addAlert('Scam Call Triggered', 'HIGH', `Huddle alert: ${data.warning}`);
          addLog('CALL_SCAN', `Live Speech Alert: ${data.warning}`, 'error');
        }
      }
    } catch (err) {
      // Local fallback rules if backend offline
      const lowercase = text.toLowerCase();
      const hasOTP = lowercase.includes("otp") || lowercase.includes("code") || lowercase.includes("pin");
      const hasUrgency = lowercase.includes("immediately") || lowercase.includes("block") || lowercase.includes("police") || lowercase.includes("anydesk");
      
      if (hasOTP || hasUrgency) {
        setCallAnalysis({
          risk_level: "HIGH",
          warning: "Suspicious security code request or high-coercion request detected in live huddle.",
          recommendation: "Hang up immediately. Do not share codes."
        });
      }
    }
  };

  // Simulate injecting a caller speech scenario line by line
  const injectScenario = (scenarioIdx) => {
    if (scenarioTimerRef.current) clearTimeout(scenarioTimerRef.current);
    setCallTranscript([]);
    setCallAnalysis(null);
    
    const lines = MOCK_SCENARIOS[scenarioIdx].transcript;
    let idx = 0;

    const pushLine = () => {
      if (idx < lines.length) {
        const lineText = lines[idx];
        setCallTranscript(prev => [...prev, { speaker: "Caller", text: lineText }]);
        
        // Accumulate text for scanner
        const accumulated = lines.slice(0, idx + 1).join(" ");
        if (netravaMonitor) {
          analyzeCallTranscript(accumulated);
        }
        
        idx++;
        scenarioTimerRef.current = setTimeout(pushLine, 2500);
      } else {
        addLog('HUDDLE_CALL', `Scenario injection finished.`, 'info');
      }
    };
    pushLine();
  };

  // Keyboard manual speech input
  const handleManualSpeechSubmit = (e) => {
    e.preventDefault();
    if (!customSpeechText.trim()) return;

    const newMsg = { speaker: "You (Manual Speech)", text: customSpeechText };
    const updatedTranscript = [...callTranscript, newMsg];
    setCallTranscript(updatedTranscript);

    if (netravaMonitor) {
      const fullText = updatedTranscript.map(t => t.text).join(" ");
      analyzeCallTranscript(fullText);
    }

    setCustomSpeechText("");
  };

  // Speech Recognition Mic Hook
  const startMicListening = () => {
    const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;
    if (!SpeechRecognition) {
      alert("Microphone Speech Recognition is not supported on this browser version. Please try Chrome or Edge.");
      return;
    }

    const rec = new SpeechRecognition();
    rec.continuous = true;
    rec.interimResults = false;
    rec.lang = 'en-US';

    rec.onstart = () => {
      setMicActive(true);
      addLog('HUDDLE_CALL', 'Microphone connection online. Transcribing voice input...', 'info');
    };

    rec.onresult = (event) => {
      const transcriptText = event.results[event.results.length - 1][0].transcript;
      if (transcriptText.trim()) {
        const newMsg = { speaker: "You (Live Speech)", text: transcriptText };
        setCallTranscript(prev => {
          const next = [...prev, newMsg];
          if (netravaMonitor) {
            const fullText = next.map(t => t.text).join(" ");
            analyzeCallTranscript(fullText);
          }
          return next;
        });
      }
    };

    rec.onerror = (err) => {
      console.error(err);
      setMicActive(false);
    };

    rec.onend = () => {
      setMicActive(false);
    };

    rec.start();
    recognitionRef.current = rec;
  };

  const stopMicListening = () => {
    if (recognitionRef.current) {
      recognitionRef.current.stop();
      recognitionRef.current = null;
    }
    setMicActive(false);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      
      {/* 1. SMS / WhatsApp Scan Detection */}
      <div className="grid-2col">
        <div className="glass-panel" style={{ padding: '1.5rem' }}>
          <h3 style={{ fontSize: '1.15rem', display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
            <MessageSquare size={18} color="var(--primary-neon)" /> SMS & WhatsApp Phishing Audit
          </h3>
          
          <div style={{ marginBottom: '1.5rem' }}>
            <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '0.4rem' }}>
              Load Sandbox Templates:
            </label>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
              {SMS_TEMPLATES.map((tpl, i) => (
                <button
                  key={i}
                  onClick={() => { setSmsInput(tpl.text); setSmsResult(null); }}
                  className="cyber-button secondary"
                  style={{ padding: '0.3rem 0.6rem', fontSize: '0.75rem' }}
                >
                  {tpl.title}
                </button>
              ))}
            </div>
          </div>

          <textarea
            className="cyber-input"
            placeholder="Paste raw SMS or WhatsApp message content here..."
            value={smsInput}
            onChange={(e) => setSmsInput(e.target.value)}
            rows={5}
            style={{ resize: 'none', marginBottom: '1rem', width: '100%' }}
          />

          <button 
            onClick={() => scanSMS()} 
            disabled={smsLoading || !smsInput} 
            className="cyber-button"
            style={{ width: '100%' }}
          >
            {smsLoading ? "Auditing Content..." : "Audit Message Security"}
          </button>
        </div>

        {/* SMS Result Panel */}
        <div className="glass-panel" style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
          {!smsResult ? (
            <div style={{ textAlign: 'center', color: 'var(--text-muted)' }}>
              <AlertOctagon size={44} style={{ marginBottom: '0.5rem', opacity: 0.5 }} />
              <p style={{ fontSize: '0.9rem' }}>Awaiting message payload analysis.</p>
            </div>
          ) : (
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
                <span style={{ fontWeight: 600 }}>Analysis Report:</span>
                <span className={`badge ${smsResult.risk_level === 'HIGH' ? 'danger' : 'success'}`}>
                  Risk: {smsResult.risk_level} ({smsResult.risk_score}%)
                </span>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                <div>
                  <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Indicators Detected:</div>
                  {smsResult.reasons.length === 0 ? (
                    <div style={{ fontSize: '0.9rem', color: 'var(--threat-low)', marginTop: '0.2rem' }}>&bull; Clean (No flags tripped)</div>
                  ) : (
                    smsResult.reasons.map((r, i) => (
                      <div key={i} style={{ fontSize: '0.85rem', color: 'var(--threat-high)', display: 'flex', alignItems: 'center', gap: '0.25rem', marginTop: '0.2rem' }}>
                        <ChevronRight size={12} /> {r}
                      </div>
                    ))
                  )}
                </div>

                <div style={{ background: 'rgba(0, 0, 0, 0.03)', padding: '0.8rem', borderRadius: '8px', borderLeft: '3px solid var(--primary-neon)' }}>
                  <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', fontWeight: 600 }}>Recommendation:</div>
                  <p style={{ fontSize: '0.85rem', color: 'var(--text-primary)', marginTop: '0.2rem' }}>{smsResult.recommendation}</p>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* 2. Discord & Huddle Voice Workspace */}
      <div className="glass-panel" style={{ padding: '1.5rem' }}>
        <h3 style={{ fontSize: '1.15rem', display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
          <Volume2 size={18} color="var(--primary-neon)" /> Huddle Voice Workspace & Live Call Guard
        </h3>

        {callStatus === "IDLE" && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem' }}>
              Connect your audio session or join an active voice huddle. Netrava integrates live speech threat assessment to block voice scams and OTP harvesting.
            </p>
            
            <div className="grid-2col" style={{ gap: '1rem' }}>
              <div 
                className="glass-panel" 
                style={{ padding: '1.25rem', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '1rem' }}
                onClick={() => selectChannelAndPrompt("general-lounge")}
              >
                <div style={{ background: 'rgba(124, 58, 237, 0.08)', padding: '0.75rem', borderRadius: '10px' }}>
                  <Hash size={24} color="var(--accent-violet)" />
                </div>
                <div>
                  <div style={{ fontWeight: 600, fontSize: '0.95rem' }}>#general-lounge</div>
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Secure Voice Room &middot; 0 users</span>
                </div>
              </div>

              <div 
                className="glass-panel" 
                style={{ padding: '1.25rem', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '1rem' }}
                onClick={() => selectChannelAndPrompt("VoIP-Hotline-4402")}
              >
                <div style={{ background: 'rgba(37, 99, 235, 0.08)', padding: '0.75rem', borderRadius: '10px' }}>
                  <Phone size={24} color="var(--primary-neon)" />
                </div>
                <div>
                  <div style={{ fontWeight: 600, fontSize: '0.95rem' }}>📞 External VoIP Hotline</div>
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Incoming External Line Trunk</span>
                </div>
              </div>
            </div>
          </div>
        )}

        {callStatus === "ASKING_CONSENT" && (
          <div className="glass-panel" style={{ padding: '2rem', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '1.5rem', background: 'rgba(37, 99, 235, 0.03)', border: '1px dashed var(--primary-neon)' }}>
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '0.5rem', textAlign: 'center' }}>
              <div style={{ background: 'var(--primary-neon-glow)', width: '56px', height: '56px', borderRadius: '50%', display: 'flex', alignItems: 'center', justifySelf: 'center', justifyContent: 'center' }}>
                <ShieldAlert size={28} color="var(--primary-neon)" />
              </div>
              <h4 style={{ fontSize: '1.2rem', marginTop: '0.5rem' }}>Huddle Protection Protocol</h4>
              <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', maxWidth: '500px' }}>
                Netrava can join and listen to this call to audit it for scam indicators, suspicious banking claims, and OTP harvesting requests.
              </p>
              <div style={{ fontWeight: 600, fontSize: '0.95rem', color: 'var(--primary-neon)', marginTop: '0.25rem' }}>
                "Should Netrava hear this call to check if the caller is scamming?"
              </div>
            </div>

            <div style={{ display: 'flex', gap: '1rem' }}>
              <button onClick={() => handleConsentAnswer(true)} className="cyber-button">
                Yes, Enable Call Guard
              </button>
              <button onClick={() => handleConsentAnswer(false)} className="cyber-button secondary">
                No, Keep Session Private
              </button>
            </div>
          </div>
        )}

        {callStatus === "CONNECTED" && (
          <div className="grid-2col" style={{ alignItems: 'stretch' }}>
            
            {/* Left side: Huddle status & visualizer */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              
              {/* Channel metadata */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                  <h4 style={{ fontSize: '1.1rem', fontWeight: 700 }}>Huddle Connected</h4>
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Channel: #{selectedChannel}</span>
                </div>
                <button onClick={leaveHuddle} className="cyber-button" style={{ background: 'var(--threat-high)', color: '#fff', padding: '0.4rem 0.8rem', fontSize: '0.8rem' }}>
                  <LogOut size={12} /> Leave Huddle
                </button>
              </div>

              {/* Speaker card list */}
              <div className="glass-panel" style={{ padding: '1rem', display: 'flex', gap: '1rem', justifyContent: 'space-around', alignItems: 'center' }}>
                <div style={{ textAlign: 'center' }}>
                  <div style={{ width: '48px', height: '48px', borderRadius: '50%', background: 'var(--accent-violet)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#fff', fontWeight: 600, border: '2px solid var(--accent-violet)', margin: '0 auto 0.25rem' }}>
                    U
                  </div>
                  <div style={{ fontSize: '0.75rem', fontWeight: 600 }}>You</div>
                </div>

                {selectedChannel.includes("VoIP") && (
                  <div style={{ textAlign: 'center' }}>
                    <div style={{ width: '48px', height: '48px', borderRadius: '50%', background: 'var(--text-muted)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#fff', fontWeight: 600, margin: '0 auto 0.25rem' }}>
                      C
                    </div>
                    <div style={{ fontSize: '0.75rem', fontWeight: 600 }}>Caller</div>
                  </div>
                )}

                <div style={{ textAlign: 'center', opacity: netravaMonitor ? 1 : 0.2 }}>
                  <div style={{ width: '48px', height: '48px', borderRadius: '50%', background: 'var(--primary-neon)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#000', border: netravaMonitor ? '2px solid var(--primary-neon)' : 'none', margin: '0 auto 0.25rem' }}>
                    N
                  </div>
                  <div style={{ fontSize: '0.75rem', fontWeight: 600 }}>Netrava</div>
                </div>
              </div>

              {/* Status banner and wave visualizer */}
              <div className="glass-panel" style={{ padding: '1rem', textAlign: 'center', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                {netravaMonitor ? (
                  <div style={{ fontSize: '0.85rem', color: 'var(--threat-low)', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.25rem', fontWeight: 600 }}>
                    <Mic size={14} /> Active Threat Shielding Enabled
                  </div>
                ) : (
                  <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.25rem', fontWeight: 600 }}>
                    <Lock size={14} /> Private Session (No scanning active)
                  </div>
                )}

                {/* Animated wave bars */}
                <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', gap: '0.3rem', height: '60px' }}>
                  {waveHeights.map((h, i) => (
                    <div 
                      key={i} 
                      style={{ 
                        width: '6px', 
                        height: `${h}px`, 
                        background: !netravaMonitor ? 'var(--text-muted)' : i % 2 === 0 ? 'var(--primary-neon)' : 'var(--accent-violet)',
                        borderRadius: '3px',
                        transition: 'height 0.15s ease'
                      }} 
                    />
                  ))}
                </div>
              </div>

              {/* Voice alerts card */}
              {netravaMonitor && callAnalysis && callAnalysis.risk_level !== 'LOW' && (
                <div className="glass-panel" style={{ padding: '1rem', borderLeft: '4px solid var(--threat-high)', background: 'rgba(225, 29, 72, 0.03)' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--threat-high)', fontWeight: 700, fontSize: '0.9rem', marginBottom: '0.25rem' }}>
                    <ShieldAlert size={14} /> ALERT: SCAM DETECTED
                  </div>
                  <p style={{ fontSize: '0.8rem', color: 'var(--text-primary)' }}>{callAnalysis.warning}</p>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
                    <strong>Action:</strong> {callAnalysis.recommendation}
                  </div>
                </div>
              )}
            </div>

            {/* Right side: Speech inputs & transcript */}
            <div className="glass-panel" style={{ padding: '1.25rem', display: 'flex', flexDirection: 'column', background: 'rgba(0,0,0,0.03)', minHeight: '320px' }}>
              
              <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '0.5rem', marginBottom: '0.75rem' }}>
                <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', fontWeight: 600 }}>Huddle Session Transcript</span>
                <span className="badge info" style={{ fontSize: '0.65rem' }}>Whisper AI</span>
              </div>

              {/* Transcript feed */}
              <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '0.5rem', overflowY: 'auto', maxHeight: '180px', marginBottom: '1rem', paddingRight: '4px' }}>
                {callTranscript.length === 0 ? (
                  <div style={{ flex: 1, display: 'flex', justifyContent: 'center', alignItems: 'center', color: 'var(--text-muted)', fontSize: '0.8rem' }}>
                    No speech recorded yet. Use the mic or inject simulated speech.
                  </div>
                ) : (
                  callTranscript.map((t, idx) => (
                    <div key={idx} className="transcript-bubble" style={{ padding: '0.5rem 0.75rem', borderRadius: '6px', fontSize: '0.8rem', background: 'rgba(0,0,0,0.04)' }}>
                      <span style={{ fontWeight: 600, display: 'block', fontSize: '0.7rem', color: t.speaker.includes('Caller') ? 'var(--accent-violet)' : 'var(--primary-neon)' }}>
                        {t.speaker}:
                      </span>
                      {t.text}
                    </div>
                  ))
                )}
              </div>

              {/* Inputs section */}
              {netravaMonitor ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                  
                  {/* Mic and scenario row */}
                  <div style={{ display: 'flex', gap: '0.5rem' }}>
                    {micActive ? (
                      <button onClick={stopMicListening} className="cyber-button" style={{ background: 'var(--threat-high)', color: '#fff', flex: 1, padding: '0.5rem', fontSize: '0.8rem' }}>
                        <MicOff size={14} /> Stop Microphone
                      </button>
                    ) : (
                      <button onClick={startMicListening} className="cyber-button" style={{ flex: 1, padding: '0.5rem', fontSize: '0.8rem' }}>
                        <Mic size={14} /> Speak Live (Mic)
                      </button>
                    )}

                    <select
                      className="cyber-input"
                      style={{ flex: 1, padding: '0.3rem 0.5rem', fontSize: '0.75rem' }}
                      defaultValue=""
                      onChange={(e) => {
                        if (e.target.value !== "") {
                          injectScenario(parseInt(e.target.value));
                          e.target.value = "";
                        }
                      }}
                    >
                      <option value="" disabled>📂 Inject Scenario</option>
                      {MOCK_SCENARIOS.map((s, idx) => (
                        <option key={idx} value={idx}>{s.label}</option>
                      ))}
                    </select>
                  </div>

                  {/* Manual speech keyboard input */}
                  <form onSubmit={handleManualSpeechSubmit} style={{ display: 'flex', gap: '0.5rem' }}>
                    <input
                      type="text"
                      className="cyber-input"
                      placeholder="Type simulated caller dialogue..."
                      value={customSpeechText}
                      onChange={(e) => setCustomSpeechText(e.target.value)}
                      style={{ fontSize: '0.8rem', padding: '0.5rem' }}
                    />
                    <button type="submit" className="cyber-button" style={{ padding: '0.5rem 1rem', fontSize: '0.8rem' }}>
                      Send
                    </button>
                  </form>

                </div>
              ) : (
                <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', textAlign: 'center', padding: '1rem', border: '1px solid var(--border-subtle)', borderRadius: '8px' }}>
                  Private mode is active. Microphone capture and scenario injection are bypassed for user confidentiality.
                </div>
              )}
            </div>

          </div>
        )}
      </div>

      {/* 3. Email Phishing Detector */}
      <div className="grid-2col">
        <div className="glass-panel" style={{ padding: '1.5rem' }}>
          <h3 style={{ fontSize: '1.15rem', display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
            <Mail size={18} color="var(--primary-neon)" /> Email Phishing Inspector
          </h3>

          <div style={{ marginBottom: '1.5rem' }}>
            <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '0.4rem' }}>
              Load Email Templates:
            </label>
            <div style={{ display: 'flex', gap: '0.5rem' }}>
              {EMAIL_TEMPLATES.map((tpl, i) => (
                <button
                  key={i}
                  onClick={() => { loadEmailTemplate(tpl); setEmailResult(null); }}
                  className="cyber-button secondary"
                  style={{ padding: '0.3rem 0.6rem', fontSize: '0.75rem' }}
                >
                  {i === 0 ? "PayPal Spoof" : "Overdue Invoice"}
                </button>
              ))}
            </div>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', marginBottom: '1rem' }}>
            <input
              type="text"
              className="cyber-input"
              placeholder="Sender Address (e.g., support@paypal-alert.com)"
              value={emailFrom}
              onChange={(e) => setEmailFrom(e.target.value)}
              style={{ fontSize: '0.85rem' }}
            />
            <input
              type="text"
              className="cyber-input"
              placeholder="Subject (e.g., Account Suspended)"
              value={emailSubject}
              onChange={(e) => setEmailSubject(e.target.value)}
              style={{ fontSize: '0.85rem' }}
            />
            <textarea
              className="cyber-input"
              placeholder="Paste email body copy here..."
              value={emailBody}
              onChange={(e) => setEmailBody(e.target.value)}
              rows={4}
              style={{ resize: 'none', fontSize: '0.85rem' }}
            />
          </div>

          <button 
            onClick={scanEmail} 
            disabled={emailLoading || !emailBody} 
            className="cyber-button"
            style={{ width: '100%' }}
          >
            {emailLoading ? "Inspecting Mail Content..." : "Scan Email Security"}
          </button>
        </div>

        {/* Email Result Panel */}
        <div className="glass-panel" style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
          {!emailResult ? (
            <div style={{ textAlign: 'center', color: 'var(--text-muted)' }}>
              <UploadCloud size={44} style={{ marginBottom: '0.5rem', opacity: 0.5 }} />
              <p style={{ fontSize: '0.9rem' }}>Awaiting email header data inspection.</p>
            </div>
          ) : (
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
                <span style={{ fontWeight: 600 }}>Email Security Audit:</span>
                <span className={`badge ${emailResult.risk_level === 'HIGH' ? 'danger' : 'success'}`}>
                  Risk: {emailResult.risk_level} ({emailResult.risk_score}%)
                </span>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                <div>
                  <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Suspicious Features Triggered:</div>
                  {emailResult.reasons.length === 0 ? (
                    <div style={{ fontSize: '0.9rem', color: 'var(--threat-low)', marginTop: '0.2rem' }}>&bull; Standard sender and payload formats verified. Safe.</div>
                  ) : (
                    emailResult.reasons.map((r, i) => (
                      <div key={i} style={{ fontSize: '0.85rem', color: 'var(--threat-high)', display: 'flex', alignItems: 'center', gap: '0.25rem', marginTop: '0.2rem' }}>
                        <ChevronRight size={12} /> {r}
                      </div>
                    ))
                  )}
                </div>

                <div style={{ background: 'rgba(0, 0, 0, 0.03)', padding: '0.8rem', borderRadius: '8px', borderLeft: '3px solid var(--primary-neon)' }}>
                  <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', fontWeight: 600 }}>Action Recommendation:</div>
                  <p style={{ fontSize: '0.85rem', color: 'var(--text-primary)', marginTop: '0.2rem' }}>{emailResult.recommendation}</p>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

    </div>
  );
}

// linked webkitSpeechRecognition API
