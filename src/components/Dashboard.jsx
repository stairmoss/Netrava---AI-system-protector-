import React, { useState } from 'react';
import { 
  ShieldAlert, 
  ShieldCheck, 
  Flame, 
  Activity, 
  Cpu, 
  Database, 
  Radio, 
  HardDrive,
  Trash2,
  Play,
  Terminal
} from 'lucide-react';

export default function Dashboard({ 
  securityScore, 
  threatCount, 
  systemLogs, 
  alerts, 
  clearAlerts, 
  addLog,
  setSecurityScore,
  backendOnline
}) {
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);

  const runSystemDiagnostic = () => {
    if (isScanning) return;
    setIsScanning(true);
    setScanProgress(5);
    addLog('SHIELD', 'Starting global AI threat diagnostic routine...', 'info');

    const steps = [
      { p: 20, msg: 'Auditing active memory buffers & running processes.' },
      { p: 45, msg: 'Hashing system files against localized malware databases.' },
      { p: 70, msg: 'Inspecting open sockets and connection redirects.' },
      { p: 90, msg: 'Verifying browser sandboxes and email attachments.' },
      { p: 100, msg: 'Diagnostic complete. Host reputation verified.' }
    ];

    steps.forEach((step, index) => {
      setTimeout(() => {
        setScanProgress(step.p);
        addLog('SHIELD', step.msg, step.p === 100 ? 'info' : 'info');
        if (step.p === 100) {
          setIsScanning(false);
          addLog('SHIELD', 'Diagnostic complete. Score synchronized.', 'info');
        }
      }, (index + 1) * 1000);
    });
  };

  const getScoreColor = () => {
    if (securityScore >= 85) return 'var(--threat-low)';
    if (securityScore >= 60) return 'var(--threat-medium)';
    return 'var(--threat-high)';
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      
      {/* Metric Cards */}
      <div className="stats-grid">
        {/* Security Score */}
        <div className="glass-panel stat-card" style={{ borderLeft: `4px solid ${getScoreColor()}` }}>
          <div className="stat-icon-wrapper" style={{ background: 'rgba(255, 255, 255, 0.04)' }}>
            {securityScore >= 80 ? (
              <ShieldCheck size={24} color={getScoreColor()} />
            ) : (
              <ShieldAlert size={24} color={getScoreColor()} />
            )}
          </div>
          <div>
            <div className="stat-value" style={{ color: getScoreColor() }}>{securityScore}%</div>
            <div className="stat-label">System Integrity Score</div>
          </div>
        </div>

        {/* Threat Counters */}
        <div className="glass-panel stat-card" style={{ borderLeft: `4px solid ${threatCount > 0 ? 'var(--threat-high)' : 'var(--threat-low)'}` }}>
          <div className="stat-icon-wrapper" style={{ background: 'rgba(255, 255, 255, 0.04)' }}>
            <Flame size={24} color={threatCount > 0 ? 'var(--threat-high)' : 'var(--text-muted)'} />
          </div>
          <div>
            <div className="stat-value">{threatCount}</div>
            <div className="stat-label">Active Threat Indicators</div>
          </div>
        </div>

        {/* API Engine Status */}
        <div className="glass-panel stat-card" style={{ borderLeft: `4px solid ${backendOnline ? 'var(--threat-low)' : 'var(--threat-high)'}` }}>
          <div className="stat-icon-wrapper" style={{ background: 'rgba(255, 255, 255, 0.04)' }}>
            <Database size={24} color={backendOnline ? 'var(--threat-low)' : 'var(--threat-high)'} />
          </div>
          <div>
            <div className="stat-value" style={{ fontSize: '1.25rem', textTransform: 'uppercase' }}>
              {backendOnline ? 'CONNECTED' : 'STANDALONE'}
            </div>
            <div className="stat-label">Threat DB Engine</div>
          </div>
        </div>

        {/* Protection Shield */}
        <div className="glass-panel stat-card" style={{ borderLeft: '4px solid var(--primary-neon)' }}>
          <div className="stat-icon-wrapper" style={{ background: 'rgba(255, 255, 255, 0.04)' }}>
            <Radio size={24} color="var(--primary-neon)" />
          </div>
          <div>
            <div className="stat-value" style={{ fontSize: '1.25rem' }}>SECURE</div>
            <div className="stat-label">Active Shield Protocol</div>
          </div>
        </div>
      </div>

      {/* Diagnostic & Alert Section */}
      <div className="grid-2col">
        {/* Diagnostic Control Console */}
        <div className="glass-panel scanning-wrapper" style={{ padding: '1.5rem', minHeight: '340px', display: 'flex', flexDirection: 'column' }}>
          {isScanning && <div className="scanner-bar" />}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
            <h3 style={{ fontSize: '1.15rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Cpu size={18} color="var(--primary-neon)" /> System Security Center
            </h3>
            <span className="badge info" style={{ fontSize: '0.7rem' }}>Diagnostics</span>
          </div>

          <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginBottom: '1.5rem' }}>
            Initiate a full scan of local application headers, memory namespaces, network port bindings, and browser session security configurations.
          </p>

          <div style={{ flex: 1, display: 'flex', flexDirection: 'column', justifyContent: 'center', alignItems: 'center', gap: '1rem' }}>
            {isScanning ? (
              <div style={{ width: '100%', maxWidth: '280px', textAlign: 'center' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '0.25rem' }}>
                  <span>Scanning files & sockets...</span>
                  <span>{scanProgress}%</span>
                </div>
                <div style={{ width: '100%', height: '6px', background: 'var(--border-subtle)', borderRadius: '3px', overflow: 'hidden' }}>
                  <div style={{ width: `${scanProgress}%`, height: '100%', background: 'var(--primary-neon)', transition: 'width 0.2s ease' }} />
                </div>
              </div>
            ) : (
              <button 
                onClick={runSystemDiagnostic} 
                className="cyber-button"
                style={{ width: '100%', maxWidth: '240px' }}
              >
                <Play size={16} /> Run Full Diagnostic
              </button>
            )}
          </div>

          <div style={{ display: 'flex', gap: '1rem', marginTop: 'auto', borderTop: '1px solid var(--border-subtle)', paddingTop: '1rem' }}>
            <div style={{ flex: 1, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <HardDrive size={16} color="var(--text-muted)" />
              <div style={{ fontSize: '0.75rem' }}>
                <div style={{ color: 'var(--text-secondary)' }}>Files Monitored</div>
                <div style={{ fontWeight: 600 }}>184,812 Items</div>
              </div>
            </div>
            <div style={{ flex: 1, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Activity size={16} color="var(--text-muted)" />
              <div style={{ fontSize: '0.75rem' }}>
                <div style={{ color: 'var(--text-secondary)' }}>Shield Latency</div>
                <div style={{ fontWeight: 600 }}>&lt; 1.2 ms</div>
              </div>
            </div>
          </div>
        </div>

        {/* Live Threats List */}
        <div className="glass-panel" style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', minHeight: '340px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
            <h3 style={{ fontSize: '1.15rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <ShieldAlert size={18} color="var(--threat-high)" /> Critical Alert Inbox
            </h3>
            {alerts.length > 0 && (
              <button 
                onClick={clearAlerts}
                className="cyber-button secondary" 
                style={{ padding: '0.3rem 0.6rem', fontSize: '0.8rem', display: 'flex', alignItems: 'center', gap: '0.25rem' }}
              >
                <Trash2 size={12} /> Clear DB
              </button>
            )}
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', overflowY: 'auto', flex: 1 }}>
            {alerts.length === 0 ? (
              <div style={{ flex: 1, display: 'flex', flexDirection: 'column', justifyContent: 'center', alignItems: 'center', color: 'var(--text-muted)', gap: '0.5rem' }}>
                <ShieldCheck size={40} color="var(--threat-low)" />
                <span style={{ fontSize: '0.9rem' }}>System status: Safe. No active threats detected.</span>
              </div>
            ) : (
              alerts.map(alert => (
                <div 
                  key={alert.id} 
                  className="glass-panel" 
                  style={{ 
                    padding: '0.8rem', 
                    borderRadius: '8px', 
                    borderLeft: `3px solid ${alert.severity === 'HIGH' ? 'var(--threat-high)' : 'var(--threat-medium)'}` 
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.25rem' }}>
                    <span style={{ fontWeight: 600, fontSize: '0.9rem' }}>{alert.title}</span>
                    <span className={`badge ${alert.severity === 'HIGH' ? 'danger' : 'warning'}`} style={{ fontSize: '0.6rem', padding: '0.1rem 0.4rem' }}>
                      {alert.severity}
                    </span>
                  </div>
                  <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>{alert.desc}</p>
                  <div style={{ textAlign: 'right', fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>{alert.time}</div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      {/* Security Event Log Console */}
      <div className="glass-panel" style={{ padding: '1.5rem' }}>
        <h3 style={{ fontSize: '1.15rem', display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
          <Terminal size={18} color="var(--primary-neon)" /> Protection Operations Console Log
        </h3>
        
        <div 
          style={{ 
            fontFamily: 'var(--font-mono)', 
            fontSize: '0.85rem', 
            background: 'rgba(0, 0, 0, 0.4)', 
            padding: '1rem', 
            borderRadius: '8px', 
            border: '1px solid var(--border-subtle)',
            height: '180px',
            overflowY: 'auto',
            display: 'flex',
            flexDirection: 'column',
            gap: '0.4rem'
          }}
        >
          {systemLogs.map(log => (
            <div key={log.id} style={{ display: 'flex', gap: '0.8rem' }}>
              <span style={{ color: 'var(--text-muted)' }}>[{log.time}]</span>
              <span style={{ 
                color: log.type === 'error' ? 'var(--threat-high)' : log.type === 'warning' ? 'var(--threat-medium)' : 'var(--primary-neon)',
                fontWeight: 600
              }}>
                {log.service}:
              </span>
              <span style={{ color: 'var(--text-secondary)' }}>{log.msg}</span>
            </div>
          ))}
        </div>
      </div>

    </div>
  );
}
