import React, { useState } from 'react'
import { inspectRequest, simulateAttack } from '../services/api'
import { ShieldAlert, Play, Cpu, AlertOctagon, CheckCircle2, ShieldCheck } from 'lucide-react'

export default function LiveInspectorLab() {
  const [ip, setIp] = useState("198.51.100.24")
  const [method, setMethod] = useState("GET")
  const [url, setUrl] = useState("/api/v1/users?id=1' UNION SELECT 1,username,password FROM admin--")
  const [payload, setPayload] = useState("")
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)

  const handleInspect = async (e) => {
    e.preventDefault()
    setLoading(true)
    try {
      const res = await inspectRequest({
        ip_address: ip,
        method: method,
        url: url,
        headers: { "User-Agent": "SOC Interactive Lab Inspector" },
        payload: payload
      })
      setResult(res.data.inspection_result)
    } catch (err) {
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  const handlePreset = async (presetName) => {
    setLoading(true)
    try {
      const res = await simulateAttack(presetName)
      const inp = res.data.request_input
      setIp(inp.ip_address)
      setMethod(inp.method)
      setUrl(inp.url)
      setPayload(inp.payload)
      setResult(res.data.inspection_result)
    } catch (err) {
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  const getDecisionColor = (decision) => {
    switch (decision) {
      case 'Block': return 'bg-rose-500/20 text-rose-400 border-rose-500/40 glow-red'
      case 'Challenge': return 'bg-amber-500/20 text-amber-400 border-amber-500/40'
      case 'Monitor': return 'bg-blue-500/20 text-blue-400 border-blue-500/40'
      default: return 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40 glow-cyan'
    }
  }

  return (
    <div className="space-y-6">
      {/* Preset simulation buttons */}
      <div className="glass-panel p-5">
        <h3 className="text-sm font-semibold text-slate-300 mb-3 flex items-center space-x-2">
          <Cpu className="w-4 h-4 text-cyan-400" />
          <span>Quick Preset Attack Vectors (Click to Inspect Instantly)</span>
        </h3>
        <div className="flex flex-wrap gap-2">
          {["SQL Injection", "XSS", "Command Injection", "SSTI", "Obfuscated SQLi", "Legitimate Traffic"].map((p) => (
            <button
              key={p}
              onClick={() => handlePreset(p)}
              className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-cyan-500/20 text-xs font-semibold text-slate-200 hover:text-cyan-400 border border-slate-700 transition-all"
            >
              {p}
            </button>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Request Sandbox Input Form */}
        <div className="lg:col-span-5 glass-panel p-6 space-y-4">
          <h3 className="text-base font-semibold text-white">Live WAF Request Sandbox</h3>
          <form onSubmit={handleInspect} className="space-y-4">
            <div className="grid grid-cols-3 gap-2">
              <div>
                <label className="text-xs text-slate-400">HTTP Method</label>
                <select
                  value={method}
                  onChange={(e) => setMethod(e.target.value)}
                  className="w-full mt-1 bg-slate-900 border border-slate-700 rounded-lg p-2 text-sm text-white"
                >
                  <option>GET</option>
                  <option>POST</option>
                  <option>PUT</option>
                  <option>DELETE</option>
                </select>
              </div>
              <div className="col-span-2">
                <label className="text-xs text-slate-400">Source IP Address</label>
                <input
                  type="text"
                  value={ip}
                  onChange={(e) => setIp(e.target.value)}
                  className="w-full mt-1 bg-slate-900 border border-slate-700 rounded-lg p-2 text-sm text-white font-mono"
                />
              </div>
            </div>

            <div>
              <label className="text-xs text-slate-400">Target URI Path & Query String</label>
              <input
                type="text"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                className="w-full mt-1 bg-slate-900 border border-slate-700 rounded-lg p-2 text-sm text-white font-mono"
                placeholder="/api/v1/products?id=1"
              />
            </div>

            <div>
              <label className="text-xs text-slate-400">Request Body Payload (Optional)</label>
              <textarea
                rows={3}
                value={payload}
                onChange={(e) => setPayload(e.target.value)}
                className="w-full mt-1 bg-slate-900 border border-slate-700 rounded-lg p-2 text-sm text-white font-mono"
                placeholder="param1=val1&param2=val2"
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full py-2.5 rounded-lg bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white font-semibold flex items-center justify-center space-x-2 shadow-lg shadow-cyan-500/20"
            >
              <Play className="w-4 h-4 fill-current" />
              <span>{loading ? "Inspecting 6 Layers..." : "Run AMRSF 6-Layer Inspection"}</span>
            </button>
          </form>
        </div>

        {/* Inspection Results & SHAP XAI Visuals */}
        <div className="lg:col-span-7 glass-panel p-6 space-y-6">
          <h3 className="text-base font-semibold text-white">AMRSF Multi-Layer Risk & Explainable AI Output</h3>
          
          {result ? (
            <div className="space-y-6">
              {/* Top Banner Decision & Final Score */}
              <div className="flex items-center justify-between p-4 rounded-xl bg-slate-900 border border-slate-800">
                <div>
                  <span className="text-xs text-slate-400 uppercase tracking-wider">Automated Decision</span>
                  <div className="mt-1 flex items-center space-x-3">
                    <span className={`px-3 py-1 rounded-lg border font-bold text-sm ${getDecisionColor(result.decision)}`}>
                      {result.decision.toUpperCase()}
                    </span>
                    <span className="text-sm text-slate-300 font-medium">{result.attack_category}</span>
                  </div>
                </div>

                <div className="text-right">
                  <span className="text-xs text-slate-400 uppercase tracking-wider">Final Risk Score</span>
                  <div className="text-3xl font-extrabold text-white font-mono">
                    {result.final_risk_score}
                    <span className="text-sm text-slate-400 font-normal"> / 100</span>
                  </div>
                </div>
              </div>

              {/* 6-Layer Sub-score Breakdown Grid */}
              <div>
                <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">6-Layer Inspection Sub-Scores</h4>
                <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
                  {Object.entries(result.scores_breakdown || {}).map(([key, val]) => (
                    <div key={key} className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                      <span className="text-xs text-slate-400 capitalize">{key.replace('_', ' ')}</span>
                      <div className="text-lg font-bold text-cyan-400 font-mono mt-1">{val.toFixed(1)}</div>
                    </div>
                  ))}
                </div>
              </div>

              {/* SHAP Explainable AI Waterfall Display */}
              <div className="p-4 rounded-xl bg-slate-900/90 border border-cyan-500/30">
                <div className="flex items-center justify-between mb-3">
                  <h4 className="text-sm font-semibold text-cyan-400 flex items-center space-x-2">
                    <ShieldAlert className="w-4 h-4" />
                    <span>Explainable AI (SHAP TreeExplainer Attribution)</span>
                  </h4>
                  <span className="text-xs text-slate-400">Shapley Feature Impact</span>
                </div>

                <p className="text-xs text-slate-300 mb-4 bg-slate-950 p-3 rounded-lg border border-slate-800">
                  <strong className="text-white">Explanation:</strong> {result.reason}
                </p>

                {(result.shap_explanations && result.shap_explanations.length > 0) ? (
                  <div className="space-y-2">
                    {result.shap_explanations.map((item, idx) => (
                      <div key={idx} className="flex items-center justify-between p-2.5 rounded-lg bg-slate-950 border border-slate-800">
                        <span className="text-sm font-medium text-slate-200">{item.feature}</span>
                        <div className="flex items-center space-x-3">
                          <span className="text-xs font-mono text-slate-400">observed={item.value_observed}</span>
                          <span className={`px-2 py-0.5 rounded text-xs font-mono font-bold ${
                            item.direction === '+' ? 'bg-rose-500/15 text-rose-400' : 'bg-emerald-500/15 text-emerald-400'
                          }`}>
                            {item.direction}{item.impact} SHAP
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-xs text-slate-400 italic">No anomalous SHAP feature deviations detected.</div>
                )}
              </div>
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center h-64 border border-dashed border-slate-800 rounded-xl">
              <Cpu className="w-10 h-10 text-slate-600 mb-2" />
              <p className="text-sm text-slate-400">Submit a request payload or choose a preset vector above to inspect.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
