import React, { useState, useEffect, useRef } from 'react';
import { 
  Terminal, 
  Send, 
  ShieldCheck, 
  KeyRound, 
  AlertTriangle,
  ChevronRight,
  Sparkles
} from 'lucide-react';

const QUICK_CHIPS = [
  "How does a courier delivery scam work?",
  "Why is SMS banking KYC risky?",
  "What is the danger of open ports like SMB?",
  "What should I do if my computer has ransomware?"
];

export default function AIChatbot({ addLog }) {
  // Chat States
  const [messages, setMessages] = useState([
    { role: 'assistant', content: "Hello! I am the Netrava AI Assistant. I can help analyze scam messages, explain network ports, guide you through malware cleanup, or check credential breaches. What threat can I help you investigate today?" }
  ]);
  const [chatInput, setChatInput] = useState("");
  const [chatLoading, setChatLoading] = useState(false);
  const chatHistoryRef = useRef(null);

  // Password States
  const [password, setPassword] = useState("");
  const [pwStrength, setPwStrength] = useState({ score: 0, label: "WEAK", color: "var(--threat-high)" });
  const [pwChecks, setPwChecks] = useState({
    length: false,
    upper: false,
    number: false,
    special: false
  });

  // Scroll chat window to bottom on new message
  useEffect(() => {
    if (chatHistoryRef.current) {
      chatHistoryRef.current.scrollTop = chatHistoryRef.current.scrollHeight;
    }
  }, [messages]);

  // 1. Submit Chat
  const sendChatMessage = async (textToSend) => {
    const text = textToSend || chatInput;
    if (!text.trim()) return;

    setMessages(prev => [...prev, { role: 'user', content: text }]);
    setChatInput("");
    setChatLoading(true);
    addLog('CHAT_BOT', 'Processing security assistant query...', 'info');

    try {
      const historyPayload = messages.map(m => ({ role: m.role, content: m.content }));
      
      const res = await fetch('/api/assistant/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: text,
          history: historyPayload
        })
      });
      if (res.ok) {
        const data = await res.json();
        setMessages(prev => [...prev, { role: 'assistant', content: data.reply }]);
        addLog('CHAT_BOT', 'Assistant response generated.', 'info');
      }
    } catch (err) {
      addLog('CHAT_BOT', 'Chat backend offline. Generating local reply...', 'warning');
      
      // Fallback response
      setTimeout(() => {
        setMessages(prev => [...prev, { 
          role: 'assistant', 
          content: "**Offline System Mode**\n\nI couldn't reach the backend server to process this query. Please check if your FastAPI server is running on port 8000. In standalone mode, I recommend checking our Comm Guard and Device Guard pages to run local analysis!" 
        }]);
      }, 800);
    } finally {
      setChatLoading(false);
    }
  };

  // 2. Password Strength Auditor Logic
  const handlePasswordChange = (val) => {
    setPassword(val);
    
    // Checks
    const len = val.length >= 8;
    const upp = /[A-Z]/.test(val);
    const num = /[0-9]/.test(val);
    const spec = /[^A-Za-z0-9]/.test(val);

    setPwChecks({ length: len, upper: upp, number: num, special: spec });

    let score = 0;
    if (val.length > 0) score += 1;
    if (len) score += 1;
    if (upp) score += 1;
    if (num) score += 1;
    if (spec) score += 1;

    let label = "WEAK";
    let color = "var(--threat-high)";

    if (score >= 5) {
      label = "EXCELLENT";
      color = "var(--threat-low)";
    } else if (score >= 4) {
      label = "STRONG";
      color = "var(--primary-neon)";
    } else if (score >= 2) {
      label = "MEDIUM";
      color = "var(--threat-medium)";
    }

    setPwStrength({ score, label, color });
  };

  return (
    <div className="grid-2col" style={{ gap: '1.5rem' }}>
      
      {/* AI Chatbot Assist */}
      <div className="glass-panel chat-window" style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column' }}>
        <h3 style={{ fontSize: '1.15rem', display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1.0rem' }}>
          <Sparkles size={18} color="var(--primary-neon)" /> Netrava Security Chatbot
        </h3>

        {/* Quick query chips */}
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.4rem', marginBottom: '1rem' }}>
          {QUICK_CHIPS.map((chip, idx) => (
            <button
              key={idx}
              onClick={() => sendChatMessage(chip)}
              className="cyber-button secondary"
              style={{ padding: '0.25rem 0.5rem', fontSize: '0.75rem', borderRadius: '6px', textAlign: 'left' }}
              disabled={chatLoading}
            >
              {chip}
            </button>
          ))}
        </div>

        {/* Chat History bubble container */}
        <div className="chat-history" ref={chatHistoryRef}>
          {messages.map((m, idx) => (
            <div key={idx} className={`chat-msg ${m.role}`}>
              <div style={{ whiteSpace: 'pre-line', lineHeight: '1.4' }}>{m.content}</div>
            </div>
          ))}
          {chatLoading && (
            <div className="chat-msg assistant" style={{ fontStyle: 'italic', opacity: 0.8 }}>
              Analyzing context threat model...
            </div>
          )}
        </div>

        {/* Chat Input controls */}
        <div style={{ display: 'flex', gap: '0.75rem', marginTop: '1rem' }}>
          <input
            type="text"
            className="cyber-input"
            placeholder="Ask about a suspicious email, scam format, or cybersecurity protection..."
            value={chatInput}
            onChange={(e) => setChatInput(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && sendChatMessage()}
            disabled={chatLoading}
            style={{ flex: 1 }}
          />
          <button 
            onClick={() => sendChatMessage()} 
            disabled={chatLoading || !chatInput} 
            className="cyber-button"
            style={{ width: '48px', height: '44px', padding: 0 }}
          >
            <Send size={16} />
          </button>
        </div>
      </div>

      {/* Password Security Auditor */}
      <div className="glass-panel" style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column' }}>
        <h3 style={{ fontSize: '1.15rem', display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
          <KeyRound size={18} color="var(--primary-neon)" /> Password Strength & Exposure Auditor
        </h3>
        
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginBottom: '1.5rem' }}>
          Verify password complexity rules and evaluate local entropy strength offline to block brute-force dictionary attacks.
        </p>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', flex: 1 }}>
          <input
            type="password"
            className="cyber-input"
            placeholder="Type a password to audit security strength..."
            value={password}
            onChange={(e) => handlePasswordChange(e.target.value)}
          />

          {password && (
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.85rem', marginBottom: '0.4rem' }}>
                <span>Entropy Rating: <strong style={{ color: pwStrength.color }}>{pwStrength.label}</strong></span>
                <span>Complexity Score: {pwStrength.score}/5</span>
              </div>
              <div style={{ width: '100%', height: '6px', background: 'var(--border-subtle)', borderRadius: '3px', overflow: 'hidden', marginBottom: '1rem' }}>
                <div 
                  style={{ 
                    width: `${(pwStrength.score / 5) * 100}%`, 
                    height: '100%', 
                    background: pwStrength.color, 
                    transition: 'width 0.2s ease, background 0.2s ease' 
                  }} 
                />
              </div>
            </div>
          )}

          {/* Password checklist */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem', fontSize: '0.85rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: pwChecks.length ? 'var(--threat-low)' : 'var(--text-muted)' }}>
              <ShieldCheck size={14} /> Length must be at least 8 characters
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: pwChecks.upper ? 'var(--threat-low)' : 'var(--text-muted)' }}>
              <ShieldCheck size={14} /> Contains uppercase letters (A-Z)
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: pwChecks.number ? 'var(--threat-low)' : 'var(--text-muted)' }}>
              <ShieldCheck size={14} /> Contains numeric digits (0-9)
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: pwChecks.special ? 'var(--threat-low)' : 'var(--text-muted)' }}>
              <ShieldCheck size={14} /> Contains special character symbols (@, #, $)
            </div>
          </div>

          {password && pwStrength.label === 'WEAK' && (
            <div style={{ 
              background: 'rgba(244, 63, 94, 0.08)', 
              border: '1px solid rgba(244, 63, 94, 0.3)', 
              padding: '0.8rem', 
              borderRadius: '8px', 
              color: 'var(--threat-high)', 
              fontSize: '0.8rem',
              display: 'flex',
              gap: '0.5rem',
              marginTop: 'auto'
            }}>
              <AlertTriangle size={16} style={{ flexShrink: 0 }} />
              <div>
                <strong>Vulnerability Flagged:</strong> This password is vulnerable to dictionary mapping. We recommend incorporating a passphrase structure.
              </div>
            </div>
          )}
        </div>
      </div>

    </div>
  );
}
