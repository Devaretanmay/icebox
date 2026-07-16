import { useState } from 'react'

function App() {
  const [approvals, setApprovals] = useState([
    { id: 1, module: 'vuln_scanner', target: '10.0.0.15', reason: 'Routine weekly scan', status: 'pending' },
    { id: 2, module: 'exploit_test', target: '192.168.1.100', reason: 'Penetration test on staging', status: 'pending' },
  ])

  const [audits, setAudits] = useState([
    { id: 101, module: 'nmap_port', target: '10.0.0.5', status: 'allowed', timestamp: '14:32:01' },
    { id: 102, module: 'sql_inject', target: 'production-db', status: 'blocked', timestamp: '14:30:45' },
    { id: 103, module: 'dir_brute', target: 'staging-web', status: 'allowed', timestamp: '14:28:12' },
  ])

  const handleApprove = (id: number) => {
    const item = approvals.find(a => a.id === id);
    if (!item) return;
    setApprovals(approvals.filter(a => a.id !== id));
    setAudits([{ id: Date.now(), module: item.module, target: item.target, status: 'allowed', timestamp: new Date().toLocaleTimeString() }, ...audits]);
  }

  const handleDeny = (id: number) => {
    const item = approvals.find(a => a.id === id);
    if (!item) return;
    setApprovals(approvals.filter(a => a.id !== id));
    setAudits([{ id: Date.now(), module: item.module, target: item.target, status: 'blocked', timestamp: new Date().toLocaleTimeString() }, ...audits]);
  }

  return (
    <div className="p-8 max-w-4xl">
      <header className="header flex justify-between items-center">
        <div className="flex items-center gap-4">
          <svg width="40" height="40" viewBox="0 0 100 100" fill="none" xmlns="http://www.w3.org/2000/svg">
            <circle cx="50" cy="54" r="40" fill="#0E1620" />
            <circle cx="50" cy="54" r="40" stroke="#C9DCE6" strokeWidth="6" />
            <circle cx="50" cy="54" r="28" stroke="#C9DCE6" strokeWidth="6" />
            <circle cx="50" cy="54" r="16" stroke="#C9DCE6" strokeWidth="6" />
            <circle cx="50" cy="54" r="13" fill="#2E8C93" />
            <path d="M50 54 L38 0 L62 0 Z" fill="#0E1620" />
            <path d="M50 54 L44 14 L56 14 Z" fill="#E8542A" />
            <rect x="47" y="4" width="6" height="8" fill="#E8542A" />
          </svg>
          <h1 className="m-0">ICEBOX</h1>
        </div>
        <div className="mono text-core-ice">Operator View</div>
      </header>

      <div className="flex gap-8">
        <div className="w-full">
          <h2 className="text-core-ice">Pending Approvals</h2>
          {approvals.length === 0 ? (
            <div className="card text-slate-steel text-center py-8">
              No pending approvals. Queue is clear.
            </div>
          ) : (
            approvals.map(approval => (
              <div key={approval.id} className="card">
                <div className="flex justify-between items-center" style={{ marginBottom: '1rem' }}>
                  <span className="badge blocked">Requires Approval</span>
                  <span className="mono text-slate-steel">ID: {approval.id}</span>
                </div>
                <div className="mono" style={{ marginBottom: '0.5rem' }}>
                  <span className="text-slate-steel">Module:</span> {approval.module}
                </div>
                <div className="mono" style={{ marginBottom: '0.5rem' }}>
                  <span className="text-slate-steel">Target:</span> {approval.target}
                </div>
                <div style={{ marginBottom: '1.5rem', color: 'var(--core-ice)' }}>
                  {approval.reason}
                </div>
                <div className="flex gap-4">
                  <button className="button primary" onClick={() => handleApprove(approval.id)}>Approve</button>
                  <button className="button danger" onClick={() => handleDeny(approval.id)}>Deny</button>
                </div>
              </div>
            ))
          )}
        </div>

        <div className="w-full">
          <h2 className="text-core-ice">Audit Log</h2>
          <div className="card">
            {audits.map(audit => (
              <div key={audit.id} className="flex justify-between items-center" style={{ borderBottom: '1px solid var(--slate-steel)', padding: '0.75rem 0' }}>
                <div>
                  <span className="mono text-slate-steel" style={{ marginRight: '1rem' }}>{audit.timestamp}</span>
                  <span className="mono">{audit.module}</span>
                  <span className="text-slate-steel" style={{ margin: '0 0.5rem' }}>→</span>
                  <span className="mono text-core-ice">{audit.target}</span>
                </div>
                {audit.status === 'allowed' ? (
                  <span className="badge allowed">Cleared</span>
                ) : (
                  <span className="badge blocked">Blocked</span>
                )}
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}

export default App
