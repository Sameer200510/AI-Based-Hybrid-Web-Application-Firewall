import React, { useState } from 'react'
import Navbar from './components/Navbar'
import SOCDashboard from './pages/SOCDashboard'
import LiveInspectorLab from './pages/LiveInspectorLab'
import AttackTimelinePage from './pages/AttackTimelinePage'
import AuditLogsPage from './pages/AuditLogsPage'
import RuleManagerPage from './pages/RuleManagerPage'
import IEEEResearchLabPage from './pages/IEEEResearchLabPage'

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard')

  return (
    <div className="min-h-screen bg-soc-dark flex flex-col">
      <Navbar activeTab={activeTab} setActiveTab={setActiveTab} />
      
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {activeTab === 'dashboard' && <SOCDashboard />}
        {activeTab === 'inspector' && <LiveInspectorLab />}
        {activeTab === 'timeline' && <AttackTimelinePage />}
        {activeTab === 'logs' && <AuditLogsPage />}
        {activeTab === 'rules' && <RuleManagerPage />}
        {activeTab === 'research' && <IEEEResearchLabPage />}
      </main>

      <footer className="border-t border-slate-900 bg-slate-950 py-4 text-center text-xs text-slate-500">
        An Explainable AI-Based Hybrid Web Application Firewall with Adaptive Risk Scoring (AMRSF) &bull; Production Research Grade
      </footer>
    </div>
  )
}
