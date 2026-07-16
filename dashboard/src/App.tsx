import { useState, useEffect } from 'react'

interface ApprovalRequest {
  id: number;
  module: string;
  target: string;
  reason: string;
  status: string;
}

interface AuditRecord {
  at: number;
  target: string;
  module: string;
  decision: string | object;
}

function App() {
  const [approvals, setApprovals] = useState<ApprovalRequest[]>([])
  const [audits, setAudits] = useState<AuditRecord[]>([])
  const API_BASE = 'http://127.0.0.1:8443/api/v1'

  const fetchData = async () => {
    try {
      const appRes = await fetch(`${API_BASE}/approvals`)
      if (appRes.ok) {
        const appData = await appRes.json()
        setApprovals(appData.filter((a: ApprovalRequest) => a.status === 'Pending'))
      }
      const audRes = await fetch(`${API_BASE}/audit?n=20`)
      if (audRes.ok) {
        const audData = await audRes.json()
        setAudits(audData)
      }
    } catch (e) {
      console.error('Failed to fetch ICEBOX data:', e)
    }
  }

  useEffect(() => {
    fetchData()
    const interval = setInterval(fetchData, 2000)
    return () => clearInterval(interval)
  }, [])

  const handleApprove = async (id: number) => {
    try {
      await fetch(`${API_BASE}/approvals/${id}/approve`, { method: 'POST' })
      fetchData()
    } catch (e) {
      console.error(e)
    }
  }

  const handleDeny = async (id: number) => {
    try {
      await fetch(`${API_BASE}/approvals/${id}/deny`, { method: 'POST' })
      fetchData()
    } catch (e) {
      console.error(e)
    }
  }

  const formatDecision = (decision: string | object) => {
    if (typeof decision === 'string') return decision;
    if (decision && typeof decision === 'object') {
      const keys = Object.keys(decision);
      return keys[0] || 'Unknown';
    }
    return 'Unknown';
  }

  return (
    <div className="p-8 max-w-4xl mx-auto">
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

      <div className="flex gap-8 flex-col lg:flex-row">
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
          <div className="card max-h-[600px] overflow-y-auto">
            {audits.map((audit, idx) => {
              const decisionStr = formatDecision(audit.decision).toLowerCase()
              const isAllowed = decisionStr === 'allow' || decisionStr === 'auto_approve'
              const date = new Date(audit.at * 1000)
              
              return (
                <div key={`${audit.at}-${idx}`} className="flex justify-between items-center" style={{ borderBottom: '1px solid var(--slate-steel)', padding: '0.75rem 0' }}>
                  <div>
                    <span className="mono text-slate-steel" style={{ marginRight: '1rem' }}>
                      {date.getHours().toString().padStart(2, '0')}:{date.getMinutes().toString().padStart(2, '0')}:{date.getSeconds().toString().padStart(2, '0')}
                    </span>
                    <span className="mono">{audit.module}</span>
                    <span className="text-slate-steel" style={{ margin: '0 0.5rem' }}>→</span>
                    <span className="mono text-core-ice">{audit.target}</span>
                  </div>
                  {isAllowed ? (
                    <span className="badge allowed">Cleared</span>
                  ) : decisionStr.includes('requireapproval') || decisionStr.includes('require_approval') ? (
                    <span className="badge pending text-hazard-orange">Pending</span>
                  ) : (
                    <span className="badge blocked">Blocked</span>
                  )}
                </div>
              )
            })}
            {audits.length === 0 && (
              <div className="text-slate-steel text-center py-4">No audit events yet.</div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

export default App
