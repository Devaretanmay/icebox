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

interface ModuleItem {
  name: string;
  kind: string;
  description: string;
}

interface JobItem {
  id: number;
  module: string;
  target: string;
  status: string;
  elapsed_secs: number;
}

function App() {
  const [approvals, setApprovals] = useState<ApprovalRequest[]>([])
  const [audits, setAudits] = useState<AuditRecord[]>([])
  const [modules, setModules] = useState<ModuleItem[]>([])
  const [jobs, setJobs] = useState<JobItem[]>([])
  const [mode, setMode] = useState<string>('freezer')
  const [isChangingMode, setIsChangingMode] = useState(false)
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
      const modRes = await fetch(`${API_BASE}/modules`)
      if (modRes.ok) {
        setModules(await modRes.json())
      }
      const jobsRes = await fetch(`${API_BASE}/jobs`)
      if (jobsRes.ok) {
        setJobs(await jobsRes.json())
      }
      if (!isChangingMode) {
        const modeRes = await fetch(`${API_BASE}/mode`)
        if (modeRes.ok) {
          const modeData = await modeRes.json()
          setMode(modeData.mode)
        }
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

  const handleModeChange = async (newMode: string) => {
    setIsChangingMode(true)
    setMode(newMode)
    try {
      await fetch(`${API_BASE}/mode`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode: newMode })
      })
      fetchData()
    } catch (e) {
      console.error(e)
    } finally {
      setIsChangingMode(false)
    }
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
        
        <div className="flex items-center gap-2">
          <div className="mono text-slate-steel" style={{ fontSize: '0.875rem', marginRight: '1rem' }}>Restriction Mode:</div>
          <div className="flex bg-seam-black" style={{ border: '1px solid var(--slate-steel)', borderRadius: '4px', overflow: 'hidden' }}>
            <button 
              className={`button m-0 ${mode === 'fridge' ? 'bg-signal-teal text-seam-black' : 'bg-seam-black text-slate-steel'}`}
              style={{ border: 'none', borderRadius: 0 }}
              onClick={() => handleModeChange('fridge')}
              disabled={isChangingMode}
            >
              FRIDGE
            </button>
            <button 
              className={`button m-0 ${mode === 'freezer' ? 'bg-signal-teal text-seam-black' : 'bg-seam-black text-slate-steel'}`}
              style={{ border: 'none', borderLeft: '1px solid var(--slate-steel)', borderRadius: 0 }}
              onClick={() => handleModeChange('freezer')}
              disabled={isChangingMode}
            >
              FREEZER
            </button>
            <button 
              className={`button m-0 ${mode === 'deep_freezer' ? 'bg-signal-teal text-seam-black' : 'bg-seam-black text-slate-steel'}`}
              style={{ border: 'none', borderLeft: '1px solid var(--slate-steel)', borderRadius: 0 }}
              onClick={() => handleModeChange('deep_freezer')}
              disabled={isChangingMode}
            >
              DEEP FREEZER
            </button>
          </div>
        </div>
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

          <h2 className="text-core-ice mt-8" style={{ marginTop: '2rem' }}>Loaded Weapons</h2>
          <div className="card">
            {modules.length === 0 ? (
              <div className="text-slate-steel text-center py-4">No modules loaded.</div>
            ) : (
              <div className="grid gap-2" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: '0.5rem' }}>
                {modules.map(mod => (
                  <div key={mod.name} className="p-2 flex flex-col gap-1" style={{ border: '1px solid var(--slate-steel)', borderRadius: '2px' }}>
                    <div className="flex justify-between items-center">
                      <span className="mono font-bold">{mod.name}</span>
                    </div>
                    <span className="badge" style={{ alignSelf: 'flex-start', backgroundColor: 'var(--slate-steel)', color: 'var(--frost-white)' }}>{mod.kind}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
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
          
          <h2 className="text-core-ice mt-8" style={{ marginTop: '2rem' }}>Active Tasks</h2>
          <div className="card max-h-[300px] overflow-y-auto">
            {jobs.length === 0 ? (
              <div className="text-slate-steel text-center py-4">No active tasks running.</div>
            ) : (
              jobs.map(job => (
                <div key={job.id} className="flex justify-between items-center" style={{ borderBottom: '1px solid var(--slate-steel)', padding: '0.75rem 0' }}>
                  <div>
                    <span className="mono text-slate-steel" style={{ marginRight: '1rem' }}>ID: {job.id}</span>
                    <span className="mono font-bold text-signal-teal">{job.module}</span>
                    <span className="text-slate-steel" style={{ margin: '0 0.5rem' }}>on</span>
                    <span className="mono text-core-ice">{job.target}</span>
                  </div>
                  <div className="flex items-center gap-4">
                    <span className="mono text-slate-steel">{job.elapsed_secs}s</span>
                    <span className={`badge ${job.status === 'Running' ? 'allowed' : 'text-slate-steel'}`}>{job.status}</span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

export default App
