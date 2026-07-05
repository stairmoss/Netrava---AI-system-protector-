import React, { useState, useEffect, useRef } from 'react';
import { 
  Shield, 
  MessageSquare, 
  ShieldCheck, 
  Activity, 
  Terminal, 
  Globe, 
  AlertTriangle, 
  Server, 
  Cpu, 
  Wifi, 
  Clock, 
  RefreshCw, 
  CheckCircle,
  HelpCircle
} from 'lucide-react';

// Import components
import Dashboard from './components/Dashboard';
import CommGuard from './components/CommGuard';
import DeviceGuard from './components/DeviceGuard';
import NetGuard from './components/NetGuard';
import AIChatbot from './components/AIChatbot';
import ThreatIntel from './components/ThreatIntel';

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [securityScore, setSecurityScore] = useState(88);
  const [threatCount, setThreatCount] = useState(2);
  const [systemLogs, setSystemLogs] = useState([
    { id: 1, time: '19:30:12', service: 'SHIELD', msg: 'Real-time protection enabled.', type: 'info' },
    { id: 2, time: '19:31:05', service: 'URL_SCAN', msg: 'Monitored suspicious redirection attempt to fake-login.cc.', type: 'warning' },
    { id: 3, time: '19:32:44', service: 'NET_SCAN', msg: 'Scanning local loopback interfaces for open ports...', type: 'info' },
  ]);
  const [alerts, setAlerts] = useState([
    { id: 101, title: 'Fake Courier Message Blocked', severity: 'HIGH', desc: 'Blocked SMS claiming unpaid DHL customs fees.', time: '5m ago' },
    { id: 102, title: 'Unsecured SMB Port Open', severity: 'MEDIUM', desc: 'Port 445 listening on localhost. Potential lateral threat.', time: '12m ago' }
  ]);
  const [backendOnline, setBackendOnline] = useState(false);

  const promptedPids = useRef(new Set());

  // Poll backend status
  useEffect(() => {
    const checkBackend = async () => {
      try {
        const res = await fetch('/api/');
        if (res.ok) {
          const data = await res.json();
          if (data.status === 'ONLINE') {
            setBackendOnline(true);
            return;
          }
        }
        setBackendOnline(false);
      } catch (err) {
        setBackendOnline(false);
      }
    };
    checkBackend();
    const interval = setInterval(checkBackend, 5000);
    return () => clearInterval(interval);
  }, []);

  // Background Process Sentinel Hunter & Call Detector
  useEffect(() => {
    if (!backendOnline) return;

    const auditSystemProcesses = async () => {
      try {
        const res = await fetch('/api/system/processes');
        if (res.ok) {
          const data = await res.json();
          const procList = data.processes || [];
          for (const proc of procList) {
            // Check for call-related processes
            const nameLower = proc.name.toLowerCase();
            const isCall = nameLower.includes("discord") || 
                           nameLower.includes("zoom") || 
                           nameLower.includes("teams") || 
                           nameLower.includes("skype") || 
                           nameLower.includes("slack") || 
                           nameLower.includes("webex") || 
                           nameLower.includes("huddle");

            if (isCall && !promptedPids.current.has(proc.pid) && !sessionStorage.getItem("autoStartCallPrompted")) {
              promptedPids.current.add(proc.pid);
              sessionStorage.setItem("autoStartCallPrompted", "true");
              
              const agree = window.confirm(
                `[NETRAVA CALL SHIELD]\n\nActive call session detected:\nProcess: ${proc.name} (PID: ${proc.pid})\n\nShould Netrava listen to this call session to identify real-time scam and fraud patterns?`
              );
              
              if (agree) {
                sessionStorage.setItem("autoStartCall", "true");
                sessionStorage.setItem("autoStartChannel", proc.name);
                setActiveTab('comm');
                addLog('HUDDLE_CALL', `Automatically attached to active call process (${proc.name}). Privacy guard: ENABLED`, 'info');
              } else {
                sessionStorage.setItem("autoStartCall", "false");
                sessionStorage.setItem("autoStartChannel", proc.name);
                addLog('HUDDLE_CALL', `User bypassed automatic protection for call process: ${proc.name}`, 'warning');
              }
              break;
            }

            // Condition: Process has high CPU (> 75%) or matches suspicious names
            const isSuspicious = proc.cpu > 75.0 || 
                                nameLower.includes("miner") || 
                                nameLower.includes("trojan") || 
                                nameLower.includes("malicious");
            
            if (isSuspicious && !promptedPids.current.has(proc.pid)) {
              promptedPids.current.add(proc.pid);
              
              // Prompt user with OS blocking confirm dialog
              const killIt = window.confirm(
                `[NETRAVA SENTINEL ALERT]\n\nSuspicious process detected running on host:\n\nCommand: ${proc.name}\nPID: ${proc.pid}\nCPU Usage: ${proc.cpu}%\n\nShould Netrava eliminate this process to secure the system? (Yes/No)`
              );
              
              if (killIt) {
                addLog('SENTINEL', `Initiating emergency termination for PID ${proc.pid}...`, 'warning');
                const killRes = await fetch('/api/system/kill', {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({ pid: proc.pid })
                });
                if (killRes.ok) {
                  addLog('SENTINEL', `Suspicious process ${proc.name} (PID: ${proc.pid}) successfully eliminated.`, 'info');
                  addAlert('Suspicious Process Eliminated', 'CRITICAL', `Forcibly terminated rogue PID ${proc.pid} (${proc.name})`);
                } else {
                  addLog('SENTINEL', `Failed to terminate PID ${proc.pid}. Access Denied.`, 'error');
                }
              } else {
                addLog('SENTINEL', `User bypassed threat isolation for PID ${proc.pid} (${proc.name}).`, 'warning');
              }
              // Prevent overlapping alerts in the same loop execution
              break;
            }
          }
        }
      } catch (err) {
        console.error("Sentinel process audit error:", err);
      }
    };

    const interval = setInterval(auditSystemProcesses, 5000);
    return () => clearInterval(interval);
  }, [backendOnline]);

  // Simulated VoIP call simulation for testing
  useEffect(() => {
    const timer = setTimeout(() => {
      if (sessionStorage.getItem("autoStartCallPrompted")) return;
      sessionStorage.setItem("autoStartCallPrompted", "true");
      
      const agree = window.confirm(
        `[NETRAVA CALL SHIELD]\n\nSimulated incoming VoIP call session detected (Process: discord.exe).\n\nShould Netrava listen to this call session to identify real-time scam and fraud patterns?`
      );
      
      if (agree) {
        sessionStorage.setItem("autoStartCall", "true");
        sessionStorage.setItem("autoStartChannel", "discord.exe");
        setActiveTab('comm');
        addLog('HUDDLE_CALL', `Automatically attached to active call process (discord.exe). Privacy guard: ENABLED`, 'info');
      } else {
        sessionStorage.setItem("autoStartCall", "false");
        sessionStorage.setItem("autoStartChannel", "discord.exe");
        addLog('HUDDLE_CALL', `User bypassed automatic protection for call process: discord.exe`, 'warning');
      }
    }, 15000);

    return () => clearTimeout(timer);
  }, []);

  const addLog = (service, msg, type = 'info') => {
    const time = new Date().toTimeString().split(' ')[0];
    setSystemLogs(prev => [
      { id: Date.now(), time, service: service.toUpperCase(), msg, type },
      ...prev.slice(0, 29) // Keep last 30 logs
    ]);
  };

  const addAlert = (title, severity, desc) => {
    setAlerts(prev => [
      { id: Date.now(), title, severity, desc, time: 'Just now' },
      ...prev
    ]);
    if (severity === 'HIGH' || severity === 'CRITICAL') {
      setThreatCount(prev => prev + 1);
      setSecurityScore(prev => Math.max(30, prev - 12));
    } else {
      setSecurityScore(prev => Math.max(30, prev - 5));
    }
  };

  const clearAlerts = () => {
    setAlerts([]);
    setThreatCount(0);
    setSecurityScore(98);
    addLog('SHIELD', 'Threat counter reset. System security database purged.', 'info');
  };

  const renderActiveView = () => {
    switch (activeTab) {
      case 'dashboard':
        return (
          <Dashboard 
            securityScore={securityScore} 
            threatCount={threatCount} 
            systemLogs={systemLogs} 
            alerts={alerts}
            clearAlerts={clearAlerts}
            addLog={addLog}
            setSecurityScore={setSecurityScore}
            backendOnline={backendOnline}
          />
        );
      case 'comm':
        return (
          <CommGuard 
            addLog={addLog} 
            addAlert={addAlert} 
          />
        );
      case 'device':
        return (
          <DeviceGuard 
            addLog={addLog} 
            addAlert={addAlert} 
          />
        );
      case 'network':
        return (
          <NetGuard 
            addLog={addLog} 
            addAlert={addAlert} 
          />
        );
      case 'chatbot':
        return (
          <AIChatbot 
            addLog={addLog} 
          />
        );
      case 'threat':
        return (
          <ThreatIntel 
            addLog={addLog} 
            addAlert={addAlert} 
          />
        );
      default:
        return <Dashboard />;
    }
  };

  return (
    <div className="dashboard-container">
      {/* Sidebar Navigation */}
      <aside className="sidebar">
        <div className="logo-container">
          <Shield className="pulse-element" size={28} color="var(--primary-neon)" />
          <span className="logo-text">NETRAVA</span>
        </div>
        
        <ul className="nav-links">
          <li 
            className={`nav-item ${activeTab === 'dashboard' ? 'active' : ''}`}
            onClick={() => setActiveTab('dashboard')}
          >
            <Activity size={18} />
            Overview
          </li>
          <li 
            className={`nav-item ${activeTab === 'comm' ? 'active' : ''}`}
            onClick={() => setActiveTab('comm')}
          >
            <MessageSquare size={18} />
            Comm Guard
          </li>
          <li 
            className={`nav-item ${activeTab === 'device' ? 'active' : ''}`}
            onClick={() => setActiveTab('device')}
          >
            <ShieldCheck size={18} />
            Device Guard
          </li>
          <li 
            className={`nav-item ${activeTab === 'network' ? 'active' : ''}`}
            onClick={() => setActiveTab('network')}
          >
            <Wifi size={18} />
            Network Auditor
          </li>
          <li 
            className={`nav-item ${activeTab === 'threat' ? 'active' : ''}`}
            onClick={() => setActiveTab('threat')}
          >
            <Globe size={18} />
            Threat Intel
          </li>
          <li 
            className={`nav-item ${activeTab === 'chatbot' ? 'active' : ''}`}
            onClick={() => setActiveTab('chatbot')}
          >
            <Terminal size={18} />
            Security Chatbot
          </li>
        </ul>

        {/* Sidebar Footer */}
        <div className="glass-panel" style={{ padding: '0.8rem', marginTop: 'auto', border: '1px solid var(--border-subtle)' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: '0.8rem' }}>
            <span style={{ color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
              <Server size={12} /> API Engine:
            </span>
            <span className={`badge ${backendOnline ? 'success' : 'danger'}`} style={{ fontSize: '0.65rem' }}>
              {backendOnline ? 'ONLINE' : 'OFFLINE'}
            </span>
          </div>
          <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '0.4rem' }}>
            Protected by Netrava Guardian v1.0
          </div>
        </div>
      </aside>

      {/* Main Core View Area */}
      <main className="main-content">
        <header className="dashboard-header">
          <div>
            <h1 style={{ fontSize: '1.8rem', margin: 0, fontWeight: 700, letterSpacing: '-0.02em' }}>
              {activeTab === 'dashboard' && 'Security Operations Center'}
              {activeTab === 'comm' && 'Communications Security'}
              {activeTab === 'device' && 'Device & Malware Isolation'}
              {activeTab === 'network' && 'Network Vulnerability Audit'}
              {activeTab === 'threat' && 'Global Threat Intelligence'}
              {activeTab === 'chatbot' && 'Netrava AI Cybersecurity Assistant'}
            </h1>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem' }}>
              Active Defense Mode &middot; Real-time AI Analysis
            </p>
          </div>
          
          <div className="header-meta">
            <div style={{ textAlign: 'right', display: 'flex', flexDirection: 'column', gap: '0.1rem' }}>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                <Clock size={12} /> Local Time
              </span>
              <span style={{ fontSize: '0.9rem', fontWeight: 600 }}>
                {new Date().toLocaleDateString('en-US', { month: 'short', day: 'numeric' })} | {new Date().toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit' })}
              </span>
            </div>
          </div>
        </header>

        {/* Dynamic Inner Panel */}
        {renderActiveView()}
      </main>
    </div>
  );
}
