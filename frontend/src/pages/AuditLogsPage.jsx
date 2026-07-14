import React, { useEffect, useState } from 'react'
import { getLogs } from '../services/api'
import { Database, Filter, Eye, ShieldAlert } from 'lucide-react'

export default function AuditLogsPage() {
  const [logs, setLogs] = useState([])
  const [loading, setLoading] = useState(true)
  const [decisionFilter, setDecisionFilter] = useState("All")
  const [ipQuery, setIpQuery] = useState("")
  const [selectedLog, setSelectedLog] = useState(null)

  const fetchLogs = async () => {
    setLoading(true)
    try {
      const res = await getLogs({ decision: decisionFilter, ip: ipQuery })
      setLogs(res.data.logs || [])
    } catch (err) {
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchLogs()
  }, [decisionFilter])

  const getBadge = (decision) => {
    switch (decision) {
      case 'Block': return 'bg-rose-500/20 text-rose-400 border-rose-500/30'
      case 'Challenge': return 'bg-amber-500/20 text-amber-400 border-amber-500/30'
      case 'Monitor': return 'bg-blue-500/20 text-blue-400 border-blue-500/30'
      default: return 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30'
    }
  }

  return (
    <div className="space-y-6">
      <div className="glass-panel p-6">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-6">
          <div>
            <h2 className="text-lg font-bold text-white">Full AMRSF Inspection Audit Logs</h2>
            <p className="text-xs text-slate-400 mt-1">Real-time inspection history with per-request SHAP feature explanations.</p>
          </div>

          <div className="flex items-center space-x-3">
            <input
              type="text"
              placeholder="Search IP address..."
              value={ipQuery}
              onChange={(e) => setIpQuery(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && fetchLogs()}
              className="bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-white"
            />
            <select
              value={decisionFilter}
              onChange={(e) => setDecisionFilter(e.target.value)}
              className="bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-white"
            >
              <option value="All">All Decisions</option>
              <option value="Allow">Allow</option>
              <option value="Monitor">Monitor</option>
              <option value="Challenge">Challenge</option>
              <option value="Block">Block</option>
            </select>
            <button
              onClick={fetchLogs}
              className="px-3 py-1.5 rounded-lg bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 text-xs font-semibold"
            >
              Filter
            </button>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-800 text-xs font-semibold text-slate-400 uppercase tracking-wider">
                <th className="py-3 px-4">Timestamp</th>
                <th className="py-3 px-4">Source IP</th>
                <th className="py-3 px-4">Method & URI</th>
                <th className="py-3 px-4">Attack Category</th>
                <th className="py-3 px-4">Risk Score</th>
                <th className="py-3 px-4">Decision</th>
                <th className="py-3 px-4">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-sm">
              {logs.map((item) => (
                <tr key={item.id} className="hover:bg-slate-800/40 transition-colors">
                  <td className="py-3 px-4 text-xs font-mono text-slate-400">{item.timestamp}</td>
                  <td className="py-3 px-4 font-mono text-slate-200">{item.ip_address}</td>
                  <td className="py-3 px-4 max-w-xs truncate font-mono text-xs text-cyan-400">
                    <span className="font-bold text-white mr-1.5">{item.method}</span>
                    {item.url}
                  </td>
                  <td className="py-3 px-4 text-xs font-medium text-slate-300">{item.attack_category}</td>
                  <td className="py-3 px-4 font-mono font-bold text-white">{item.final_risk_score}</td>
                  <td className="py-3 px-4">
                    <span className={`px-2.5 py-1 rounded-full text-xs font-bold border ${getBadge(item.decision)}`}>
                      {item.decision}
                    </span>
                  </td>
                  <td className="py-3 px-4">
                    <button
                      onClick={() => setSelectedLog(item)}
                      className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-xs text-slate-300 flex items-center space-x-1"
                    >
                      <Eye className="w-3.5 h-3.5" />
                      <span>SHAP View</span>
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Detail Modal */}
      {selectedLog && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="glass-panel p-6 max-w-2xl w-full max-h-[85vh] overflow-y-auto space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-base font-bold text-white">Log Inspection Details #{selectedLog.id}</h3>
              <button
                onClick={() => setSelectedLog(null)}
                className="text-xs px-3 py-1 rounded bg-slate-800 text-slate-300"
              >
                Close
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div>
                <span className="text-slate-400">Target URL: </span>
                <span className="font-mono text-cyan-400">{selectedLog.method} {selectedLog.url}</span>
              </div>
              <div>
                <span className="text-slate-400">Payload: </span>
                <span className="font-mono text-slate-200">{selectedLog.payload || '(Empty)'}</span>
              </div>
              <div>
                <span className="text-slate-400">AMRSF Reason: </span>
                <span className="text-white font-medium">{selectedLog.reason}</span>
              </div>

              <div className="pt-2 border-t border-slate-800">
                <span className="font-bold text-slate-300 block mb-2">6-Layer Sub-Score Breakdown:</span>
                <div className="grid grid-cols-3 gap-2">
                  {Object.entries(selectedLog.scores_breakdown || {}).map(([k, v]) => (
                    <div key={k} className="p-2 rounded bg-slate-900 border border-slate-800">
                      <div className="text-slate-400 text-[11px] capitalize">{k.replace('_', ' ')}</div>
                      <div className="font-mono font-bold text-cyan-400 mt-0.5">{v}</div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
