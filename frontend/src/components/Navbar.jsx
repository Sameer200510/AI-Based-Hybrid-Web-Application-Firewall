import React from 'react'
import { ShieldAlert, Activity, Cpu, Database, Sliders, FileText } from 'lucide-react'

export default function Navbar({ activeTab, setActiveTab }) {
  const tabs = [
    { id: 'dashboard', label: 'SOC Dashboard', icon: Activity },
    { id: 'inspector', label: 'Live WAF Inspector & XAI', icon: ShieldAlert },
    { id: 'timeline', label: 'Attack Timeline', icon: FileText },
    { id: 'logs', label: 'Audit Logs', icon: Database },
    { id: 'rules', label: 'Rule Manager', icon: Sliders },
    { id: 'research', label: 'IEEE Research Lab', icon: Cpu },
  ]

  return (
    <nav className="sticky top-0 z-50 bg-slate-950/90 backdrop-blur-md border-b border-slate-800/80">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          <div className="flex items-center space-x-3">
            <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center shadow-lg shadow-cyan-500/20">
              <ShieldAlert className="w-6 h-6 text-white" />
            </div>
            <div>
              <span className="text-lg font-bold tracking-tight text-white">AMRSF</span>
              <span className="ml-2 text-xs font-semibold px-2 py-0.5 rounded-full bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                Explainable AI Hybrid WAF
              </span>
            </div>
          </div>

          <div className="hidden md:flex items-center space-x-1">
            {tabs.map((tab) => {
              const Icon = tab.icon
              const active = activeTab === tab.id
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`flex items-center space-x-2 px-3 py-2 rounded-lg text-sm font-medium transition-all ${
                    active
                      ? 'bg-cyan-500/15 text-cyan-400 border border-cyan-500/30 glow-cyan'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
                  }`}
                >
                  <Icon className="w-4 h-4" />
                  <span>{tab.label}</span>
                </button>
              )
            })}
          </div>

          <div className="flex items-center space-x-3">
            <div className="flex items-center space-x-2 px-3 py-1.5 rounded-full bg-emerald-500/10 border border-emerald-500/20">
              <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
              <span className="text-xs font-semibold text-emerald-400">WAF Active (6 Layers)</span>
            </div>
          </div>
        </div>
      </div>
    </nav>
  )
}
