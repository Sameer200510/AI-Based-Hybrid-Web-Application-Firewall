import React, { useEffect, useState } from 'react'
import { getRules, createRule, toggleRule, deleteRule } from '../services/api'
import { Sliders, Plus, Trash2, Power } from 'lucide-react'

export default function RuleManagerPage() {
  const [rules, setRules] = useState([])
  const [name, setName] = useState("")
  const [pattern, setPattern] = useState("")
  const [category, setCategory] = useState("Custom Signature")
  const [severity, setSeverity] = useState(85.0)
  const [loading, setLoading] = useState(false)

  const fetchRules = async () => {
    try {
      const res = await getRules()
      setRules(res.data.rules || [])
    } catch (err) {
      console.error(err)
    }
  }

  useEffect(() => {
    fetchRules()
  }, [])

  const handleCreate = async (e) => {
    e.preventDefault()
    if (!name || !pattern) return
    setLoading(true)
    try {
      await createRule({ name, pattern, attack_category: category, severity_score: severity })
      setName("")
      setPattern("")
      fetchRules()
    } catch (err) {
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  const handleToggle = async (id) => {
    await toggleRule(id)
    fetchRules()
  }

  const handleDelete = async (id) => {
    await deleteRule(id)
    fetchRules()
  }

  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
      {/* Create Rule Form */}
      <div className="lg:col-span-4 glass-panel p-6 space-y-4">
        <h3 className="text-base font-bold text-white flex items-center space-x-2">
          <Sliders className="w-4 h-4 text-cyan-400" />
          <span>Add Dynamic WAF Rule</span>
        </h3>
        <form onSubmit={handleCreate} className="space-y-3">
          <div>
            <label className="text-xs text-slate-400">Rule Name</label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Block Suspicious Path Pattern"
              className="w-full mt-1 bg-slate-900 border border-slate-700 rounded-lg p-2 text-sm text-white"
              required
            />
          </div>

          <div>
            <label className="text-xs text-slate-400">Regular Expression Pattern</label>
            <input
              type="text"
              value={pattern}
              onChange={(e) => setPattern(e.target.value)}
              placeholder="(?i)\b(union\s+select|sleep\()"
              className="w-full mt-1 bg-slate-900 border border-slate-700 rounded-lg p-2 text-sm font-mono text-cyan-400"
              required
            />
          </div>

          <div>
            <label className="text-xs text-slate-400">Threat Category</label>
            <select
              value={category}
              onChange={(e) => setCategory(e.target.value)}
              className="w-full mt-1 bg-slate-900 border border-slate-700 rounded-lg p-2 text-sm text-white"
            >
              <option>SQL Injection</option>
              <option>XSS</option>
              <option>Command Injection</option>
              <option>Path Traversal</option>
              <option>Custom Signature</option>
            </select>
          </div>

          <div>
            <label className="text-xs text-slate-400">Severity Score (0 - 100)</label>
            <input
              type="number"
              value={severity}
              onChange={(e) => setSeverity(float(e.target.value))}
              className="w-full mt-1 bg-slate-900 border border-slate-700 rounded-lg p-2 text-sm text-white font-mono"
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-black font-bold text-sm"
          >
            Deploy Rule to Engine
          </button>
        </form>
      </div>

      {/* Rules Table */}
      <div className="lg:col-span-8 glass-panel p-6">
        <h3 className="text-base font-bold text-white mb-4">Active & Auto-Suggested Signature Rules</h3>
        <div className="space-y-3">
          {rules.map((item) => (
            <div key={item.id} className="flex items-center justify-between p-4 rounded-xl bg-slate-900 border border-slate-800">
              <div className="space-y-1">
                <div className="flex items-center space-x-2">
                  <span className="text-sm font-bold text-white">{item.name}</span>
                  <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-cyan-400">{item.attack_category}</span>
                </div>
                <div className="font-mono text-xs text-slate-400">{item.pattern}</div>
              </div>

              <div className="flex items-center space-x-3">
                <span className="text-xs font-mono font-bold text-amber-400">Severity={item.severity_score}</span>
                <button
                  onClick={() => handleToggle(item.id)}
                  className={`p-2 rounded-lg border ${
                    item.is_active
                      ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30'
                      : 'bg-slate-800 text-slate-500 border-slate-700'
                  }`}
                >
                  <Power className="w-4 h-4" />
                </button>
                <button
                  onClick={() => handleDelete(item.id)}
                  className="p-2 rounded-lg bg-rose-500/15 text-rose-400 hover:bg-rose-500/25 border border-rose-500/30"
                >
                  <Trash2 className="w-4 h-4" />
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
