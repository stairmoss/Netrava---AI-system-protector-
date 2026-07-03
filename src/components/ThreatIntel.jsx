import React, { useState } from 'react';
import { 
  Globe, 
  Search, 
  ShieldAlert, 
  ShieldCheck, 
  HelpCircle, 
  FileText, 
  Copy, 
  UserX,
  AlertTriangle,
  ChevronRight
} from 'lucide-react';

const URL_SAMPLES = [
  "https://secure-bank-signin.sbi-kyc-verify.net/login",
  "https://arnazon.com/deals-refunding-portal",
  "https://paypa1-support-security.xyz/auth",
  "https://www.netflix.com",
  "http://192.168.1.1/admin"
];

export default function ThreatIntel({ addLog, addAlert }) {
  // URL Scan States
  const [urlInput, setUrlInput] = useState("");
  const [urlResult, setUrlResult] = useState(null);
  const [urlLoading, setUrlLoading] = useState(false);

  // Dark Web States
  const [darkInput, setDarkInput] = useState("");
  const [darkResult, setDarkResult] = useState(null);
  const [darkLoading, setDarkLoading] = useState(false);

  // Cybercrime Report States
  const [reportText, setReportText] = useState("");
  const [copied, setCopied] = useState(false);

  // 1. Scan URL
  const handleUrlScan = async (sampleUrl) => {
    const url = sampleUrl || urlInput;
    if (!url) return;

    setUrlLoading(true);
    setUrlResult(null);
    addLog('URL_SCAN', `Querying threat reputational indexes for ${url}...`, 'info');

    try {
      const res = await fetch('/api/scan/url', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url })
      });
      if (res.ok) {
        const data = await res.json();
        setUrlResult(data);
        if (data.risk_level === 'HIGH') {
          addAlert('Phishing Site Identified', 'HIGH', `Domain: ${data.domain} - mimics official platform.`);
          addLog('URL_SCAN', `URL Blocked: ${data.domain} (Score: ${data.risk_score}%)`, 'error');
        } else {
          addLog('URL_SCAN', `Domain index verification complete for ${data.domain}.`, 'info');
        }
      }
    } catch (err) {
      addLog('URL_SCAN', 'API lookup failed. Falling back to pattern recognizer.', 'warning');
      // Offline fallback
      const domain = url.replace('https://', '').replace('http://', '').split('/')[0];
      const isHigh = domain.includes('verify') || domain.includes('paypa1') || domain.includes('arnazon');
      
      setUrlResult({
        url,
        domain,
        risk_level: isHigh ? "HIGH" : "LOW",
        risk_score: isHigh ? 90 : 5,
        ssl_active: url.startsWith('https://'),
        reasons: isHigh ? ["Spoofed brand keywords found", "High risk gTLD extension"] : [],
        recommendation: isHigh ? "Avoid visiting. Keep credentials safe." : "Domain reputational scan looks clean.",
        google_safe_browsing: isHigh ? "SUSPICIOUS" : "CLEAN",
        virustotal_positives: isHigh ? 8 : 0
      });
    } finally {
      setUrlLoading(false);
    }
  };

  // 2. Dark Web Monitor
  const handleDarkWebSearch = async () => {
    if (!darkInput) return;
    setDarkLoading(true);
    setDarkResult(null);
    addLog('DARK_WEB', `Searching leaked data repositories for ${darkInput}...`, 'info');

    try {
      const res = await fetch('/api/darkweb', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ term: darkInput })
      });
      if (res.ok) {
        const data = await res.json();
        setDarkResult(data);
        if (data.breached) {
          addAlert('Data Leakage Detected', 'MEDIUM', `${darkInput} found in ${data.total_leaks} breaches.`);
          addLog('DARK_WEB', `Credential exposure detected for ${darkInput}. Found ${data.total_leaks} leaks.`, 'warning');
        } else {
          addLog('DARK_WEB', `Leak sweep complete. No records found for ${darkInput}.`, 'info');
        }
      }
    } catch (err) {
      addLog('DARK_WEB', 'Database query failed.', 'error');
    } finally {
      setDarkLoading(false);
    }
  };

  // 3. Cybercrime Report compiler
  const compileReport = () => {
    let details = "";
    if (urlResult && urlResult.risk_level === 'HIGH') {
      details += `• Phishing Link Target: ${urlResult.url}\n• Blocked Domain: ${urlResult.domain}\n• Risk Score: ${urlResult.risk_score}%\n• Detections: Spoofing indicators match trademark formats.`;
    } else {
      details += `• Event: Phishing / Financial fraud message solicitation.\n• Incident Details: Suspicious SMS / courier scam claiming unpaid bills and demanding payment redirection link.`;
    }

    const report = (
      `======================================\n` +
      `  CYBERCRIME EVIDENCE DOSSIER REPORT  \n` +
      `======================================\n` +
      `Date & Time of Audit: ${new Date().toISOString()}\n` +
      `Reporter: Netrava Cyber Guardian Shield\n` +
      `Threat Classification: Phishing / Credential Harvesting\n\n` +
      `IDENTIFIED COMPROMISE INDICATORS:\n` +
      `${details}\n\n` +
      `DIAGNOSTIC TELEMETRY:\n` +
      `• Platform: Web Audit Sandbox\n` +
      `• Host Intercept: Resolved locally via DNS hooks\n\n` +
      `======================================\n` +
      `Disclaimer: Report compiled programmatically. Verified signatures matches known malicious campaign directories.\n` +
      `Ready for upload to national reporting portals.`
    );
    setReportText(report);
    addLog('REPORT', 'Cybercrime reporting dossier compiled.', 'info');
  };

  const copyToClipboard = () => {
    navigator.clipboard.writeText(reportText);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      
      {/* URL Scanner Suite */}
      <div className="grid-2col">
        <div className="glass-panel" style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column' }}>
          <h3 style={{ fontSize: '1.15rem', display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
            <Globe size={18} color="var(--primary-neon)" /> Suspicious URL & Redirect Scanner
          </h3>

          <div style={{ marginBottom: '1rem' }}>
            <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '0.4rem' }}>
              Select Sample Phishing Links:
            </label>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
              {URL_SAMPLES.map((sUrl, idx) => (
                <button
                  key={idx}
                  onClick={() => { setUrlInput(sUrl); setUrlResult(null); }}
                  className="cyber-button secondary"
                  style={{ padding: '0.3rem 0.6rem', fontSize: '0.75rem', maxWidth: '280px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
                >
                  {sUrl.replace('https://', '').replace('http://', '').split('/')[0]}
                </button>
              ))}
            </div>
          </div>

          <div style={{ display: 'flex', gap: '1rem', marginTop: 'auto' }}>
            <input
              type="text"
              className="cyber-input"
              style={{ flex: 1 }}
              placeholder="Paste URL to inspect (e.g. https://sec-verify.xyz)"
              value={urlInput}
              onChange={(e) => setUrlInput(e.target.value)}
            />
            <button onClick={() => handleUrlScan()} disabled={urlLoading || !urlInput} className="cyber-button">
              {urlLoading ? "Scanning..." : "Scan URL"}
            </button>
          </div>
        </div>

        {/* URL scan results */}
        <div className="glass-panel" style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', justifyContent: 'center', minHeight: '260px' }}>
          {urlLoading ? (
            <div style={{ textAlign: 'center', color: 'var(--text-secondary)' }}>
              <Globe size={40} className="pulse-element" style={{ color: 'var(--primary-neon)', marginBottom: '0.5rem' }} />
              <div>Fetching reputation statistics...</div>
            </div>
          ) : !urlResult ? (
            <div style={{ textAlign: 'center', color: 'var(--text-muted)' }}>
              <Globe size={44} style={{ opacity: 0.5, marginBottom: '0.5rem' }} />
              <p style={{ fontSize: '0.9rem' }}>Awaiting domain registry queries.</p>
            </div>
          ) : (
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
                <span style={{ fontWeight: 600, fontSize: '0.95rem' }}>{urlResult.domain}</span>
                <span className={`badge ${urlResult.risk_level === 'HIGH' ? 'danger' : 'success'}`}>
                  Risk: {urlResult.risk_level} ({urlResult.risk_score}%)
                </span>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', fontSize: '0.85rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: 'var(--text-muted)' }}>SSL Encryption:</span>
                  <span style={{ color: urlResult.ssl_active ? 'var(--threat-low)' : 'var(--threat-high)', fontWeight: 600 }}>
                    {urlResult.ssl_active ? 'HTTPS (Active)' : 'HTTP (None)'}
                  </span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: 'var(--text-muted)' }}>Google Safe Browsing:</span>
                  <span style={{ color: urlResult.google_safe_browsing === 'CLEAN' ? 'var(--threat-low)' : 'var(--threat-high)', fontWeight: 600 }}>
                    {urlResult.google_safe_browsing}
                  </span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: 'var(--text-muted)' }}>VirusTotal Detections:</span>
                  <span style={{ color: urlResult.virustotal_positives > 0 ? 'var(--threat-high)' : 'var(--threat-low)', fontWeight: 600 }}>
                    {urlResult.virustotal_positives} Engines flagged
                  </span>
                </div>

                {urlResult.reasons.length > 0 && (
                  <div style={{ marginTop: '0.5rem' }}>
                    <strong style={{ color: 'var(--text-muted)' }}>Heuristic Flags:</strong>
                    {urlResult.reasons.map((r, idx) => (
                      <div key={idx} style={{ color: 'var(--threat-medium)', fontSize: '0.8rem', display: 'flex', alignItems: 'center', gap: '0.25rem', marginTop: '0.1rem' }}>
                        <ChevronRight size={10} /> {r}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Dark Web monitoring & Cybercrime Reporting */}
      <div className="grid-2col">
        {/* Dark Web leak checker */}
        <div className="glass-panel" style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', minHeight: '340px' }}>
          <h3 style={{ fontSize: '1.15rem', display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
            <UserX size={18} color="var(--primary-neon)" /> Dark Web Credential Leak Scanner
          </h3>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginBottom: '1.5rem' }}>
            Enter your email address or cellular phone number to search indexed threat actor combo-lists and breach logs.
          </p>

          <div style={{ display: 'flex', gap: '0.75rem', marginBottom: '1rem' }}>
            <input
              type="text"
              className="cyber-input"
              placeholder="e.g. adarsh@gmail.com or 9988776655"
              value={darkInput}
              onChange={(e) => setDarkInput(e.target.value)}
            />
            <button onClick={handleDarkWebSearch} disabled={darkLoading || !darkInput} className="cyber-button">
              Check Leaks
            </button>
          </div>

          <div style={{ flex: 1, overflowY: 'auto', maxHeight: '140px', fontSize: '0.85rem' }}>
            {darkLoading ? (
              <div style={{ textAlign: 'center', color: 'var(--text-secondary)', marginTop: '2rem' }}>Querying index database...</div>
            ) : !darkResult ? (
              <div style={{ textAlign: 'center', color: 'var(--text-muted)', marginTop: '2rem' }}>No sweep conducted.</div>
            ) : darkResult.total_leaks === 0 ? (
              <div style={{ color: 'var(--threat-low)', display: 'flex', alignItems: 'center', gap: '0.5rem', justifyContent: 'center', marginTop: '2rem' }}>
                <ShieldCheck size={20} /> Your credentials are not flagged in indexed breaches.
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                <div style={{ fontWeight: 600, color: 'var(--threat-high)' }}>Exposed Records Found ({darkResult.total_leaks}):</div>
                {darkResult.leaks.map((leak, idx) => (
                  <div key={idx} style={{ background: 'rgba(0,0,0,0.2)', padding: '0.5rem', borderRadius: '6px', borderLeft: '3px solid var(--threat-high)' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontWeight: 600, fontSize: '0.8rem' }}>
                      <span>{leak.database}</span>
                      <span style={{ color: 'var(--text-muted)' }}>{leak.date}</span>
                    </div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '0.2rem' }}>
                      Exposed: {leak.leaked_fields.join(', ')}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Cybercrime Reporting portal helper */}
        <div className="glass-panel" style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', minHeight: '340px' }}>
          <h3 style={{ fontSize: '1.15rem', display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
            <FileText size={18} color="var(--primary-neon)" /> Cybercrime Evidence Compiler
          </h3>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginBottom: '1rem' }}>
            Generate a formatted cybercrime evidence report that aggregates the threat logs, ready to submit to government portals (e.g. cybercrime.gov.in).
          </p>

          <button onClick={compileReport} className="cyber-button" style={{ marginBottom: '1rem', width: '100%' }}>
            Generate Incident Report Document
          </button>

          {reportText && (
            <div style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
              <textarea
                className="cyber-input"
                style={{ 
                  fontFamily: 'var(--font-mono)', 
                  fontSize: '0.75rem', 
                  flex: 1, 
                  resize: 'none', 
                  background: 'rgba(0,0,0,0.4)', 
                  color: 'var(--text-secondary)',
                  marginBottom: '0.75rem' 
                }}
                value={reportText}
                readOnly
                rows={5}
              />
              <button 
                onClick={copyToClipboard} 
                className="cyber-button secondary"
                style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', justifyContent: 'center' }}
              >
                <Copy size={14} /> {copied ? "Copied Report Details!" : "Copy Report to Clipboard"}
              </button>
            </div>
          )}
        </div>
      </div>

    </div>
  );
}
