import React, { useEffect, useState } from 'react'
import { getAttackTimeline } from '../services/api'
import { FileText, ShieldAlert, Clock, AlertOctagon } from 'lucide-react'

export default function AttackTimelinePage() {
  const [events, setEvents] = useState([])
  const [loading, setLoading] = useState(true)

  const fetchTimeline = async () => {
    try {
      const res = await getAttackTimeline()
      setEvents(res.data.events || [])
    } catch (err) {
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchTimeline()
  }, [])

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[50vh]">
        <div className="w-8 h-8 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin"></div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="glass-panel p-6">
        <div className="flex items-center justify-between mb-6">
          <div>
            <h2 className="text-lg font-bold text-white">Multi-Stage Attack Campaign Reconstruction</h2>
            <p className="text-xs text-slate-400 mt-1">
              Correlates multi-phase reconnaissance, payload obfuscation attempts, and automated WAF quarantine events.
            </p>
          </div>
          <button
            onClick={fetchTimeline}
            className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-200 border border-slate-700"
          >
            Refresh Timeline
          </button>
        </div>

        <div className="relative border-l border-slate-800 ml-4 space-y-6">
          {events.length === 0 ? (
            <div className="pl-6 text-sm text-slate-400">No attack timeline events recorded yet. Run a simulated attack in the Live WAF Inspector to view reconstructed campaigns.</div>
          ) : (
            events.map((ev) => (
              <div key={ev.id} className="relative pl-6">
                <span className={`absolute -left-2 top-1.5 w-4 h-4 rounded-full border-2 ${
                  ev.decision === 'Block' ? 'bg-rose-500 border-rose-900' : 'bg-amber-500 border-amber-900'
                }`}></span>

                <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 space-y-2">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-slate-800 text-cyan-400">
                        {ev.campaign_id}
                      </span>
                      <span className="text-sm font-semibold text-white">{ev.stage}</span>
                    </div>
                    <span className="text-xs text-slate-400 font-mono">{ev.timestamp}</span>
                  </div>

                  <p className="text-xs text-slate-300">{ev.description}</p>

                  <div className="flex items-center justify-between pt-2 border-t border-slate-800/80 text-xs">
                    <span className="text-slate-400">Source IP: <strong className="text-slate-200 font-mono">{ev.ip_address}</strong></span>
                    <span className={`px-2 py-0.5 rounded font-bold ${
                      ev.decision === 'Block' ? 'text-rose-400 bg-rose-500/10' : 'text-amber-400 bg-amber-500/10'
                    }`}>
                      Risk Score: {ev.risk_score} ({ev.decision})
                    </span>
                  </div>
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  )
}
