import React, { useState } from 'react'
import { runIEEEBenchmark } from '../services/api'
import { Cpu, CheckCircle2, Zap, BarChart2 } from 'lucide-react'

export default function IEEEResearchLabPage() {
  const [samples, setSamples] = useState(400)
  const [loading, setLoading] = useState(false)
  const [report, setReport] = useState(null)

  const handleBenchmark = async () => {
    setLoading(true)
    try {
      const res = await runIEEEBenchmark(samples)
      setReport(res.data.benchmark)
    } catch (err) {
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-6">
      <div className="glass-panel p-6 flex flex-col md:flex-row items-center justify-between gap-4">
        <div>
          <h2 className="text-lg font-bold text-white">IEEE Research Benchmark Laboratory</h2>
          <p className="text-xs text-slate-400 mt-1">
            Evaluates AMRSF against synthetic CSIC 2010 balanced web attack datasets and benchmarks against ModSecurity & Signature-Only WAF baselines.
          </p>
        </div>

        <div className="flex items-center space-x-3">
          <select
            value={samples}
            onChange={(e) => setSamples(Number(e.target.value))}
            className="bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white"
          >
            <option value={200}>200 Samples</option>
            <option value={400}>400 Samples</option>
            <option value={800}>800 Samples</option>
          </select>
          <button
            onClick={handleBenchmark}
            disabled={loading}
            className="px-4 py-2 rounded-lg bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white font-bold text-sm shadow-lg shadow-cyan-500/20"
          >
            {loading ? "Running IEEE Evaluation..." : "Run Scientific Evaluation"}
          </button>
        </div>
      </div>

      {report ? (
        <div className="space-y-6">
          {/* Comparative Table */}
          <div className="glass-panel p-6">
            <h3 className="text-base font-bold text-white mb-4">Comparative WAF Architecture Performance Benchmark</h3>
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="border-b border-slate-800 text-xs font-semibold text-slate-400 uppercase tracking-wider">
                    <th className="py-3 px-4">WAF Profile / Model</th>
                    <th className="py-3 px-4">Accuracy</th>
                    <th className="py-3 px-4">Precision</th>
                    <th className="py-3 px-4">Recall (TPR)</th>
                    <th className="py-3 px-4">F1 Score</th>
                    <th className="py-3 px-4">False Positive Rate</th>
                    <th className="py-3 px-4">Latency per Request</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800 text-sm">
                  {/* AMRSF Row */}
                  <tr className="bg-cyan-500/10 font-bold text-white">
                    <td className="py-4 px-4 text-cyan-400">AMRSF Hybrid 6-Layer Engine (Ours)</td>
                    <td className="py-4 px-4">{report.amrsf_hybrid.accuracy}%</td>
                    <td className="py-4 px-4">{report.amrsf_hybrid.precision}%</td>
                    <td className="py-4 px-4">{report.amrsf_hybrid.recall}%</td>
                    <td className="py-4 px-4 text-emerald-400">{report.amrsf_hybrid.f1_score}%</td>
                    <td className="py-4 px-4 text-emerald-400">{report.amrsf_hybrid.false_positive_rate}%</td>
                    <td className="py-4 px-4">{report.amrsf_hybrid.latency_ms} ms</td>
                  </tr>

                  {/* ModSecurity Row */}
                  <tr className="text-slate-300">
                    <td className="py-3 px-4">ModSecurity CRS Simulated Baseline</td>
                    <td className="py-3 px-4">{report.modsecurity_crs_baseline.accuracy}%</td>
                    <td className="py-3 px-4">{report.modsecurity_crs_baseline.precision}%</td>
                    <td className="py-3 px-4">{report.modsecurity_crs_baseline.recall}%</td>
                    <td className="py-3 px-4">{report.modsecurity_crs_baseline.f1_score}%</td>
                    <td className="py-3 px-4 text-amber-400">{report.modsecurity_crs_baseline.false_positive_rate}%</td>
                    <td className="py-3 px-4">{report.modsecurity_crs_baseline.latency_ms} ms</td>
                  </tr>

                  {/* Signature only Row */}
                  <tr className="text-slate-400">
                    <td className="py-3 px-4">Signature-Only WAF Baseline</td>
                    <td className="py-3 px-4">{report.signature_only_baseline.accuracy}%</td>
                    <td className="py-3 px-4">{report.signature_only_baseline.precision}%</td>
                    <td className="py-3 px-4">{report.signature_only_baseline.recall}%</td>
                    <td className="py-3 px-4">{report.signature_only_baseline.f1_score}%</td>
                    <td className="py-3 px-4">{report.signature_only_baseline.false_positive_rate}%</td>
                    <td className="py-3 px-4">{report.signature_only_baseline.latency_ms} ms</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>

          {/* Confusion Matrix Display */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="glass-panel p-6">
              <h4 className="text-sm font-bold text-white mb-4">AMRSF Hybrid Confusion Matrix</h4>
              <div className="grid grid-cols-2 gap-3 font-mono text-center">
                <div className="p-4 rounded-xl bg-slate-900 border border-emerald-500/40">
                  <div className="text-xs text-slate-400">True Positives (TP)</div>
                  <div className="text-2xl font-bold text-emerald-400 mt-1">{report.amrsf_hybrid.confusion_matrix.TP}</div>
                </div>
                <div className="p-4 rounded-xl bg-slate-900 border border-rose-500/40">
                  <div className="text-xs text-slate-400">False Positives (FP)</div>
                  <div className="text-2xl font-bold text-rose-400 mt-1">{report.amrsf_hybrid.confusion_matrix.FP}</div>
                </div>
                <div className="p-4 rounded-xl bg-slate-900 border border-amber-500/40">
                  <div className="text-xs text-slate-400">False Negatives (FN)</div>
                  <div className="text-2xl font-bold text-amber-400 mt-1">{report.amrsf_hybrid.confusion_matrix.FN}</div>
                </div>
                <div className="p-4 rounded-xl bg-slate-900 border border-cyan-500/40">
                  <div className="text-xs text-slate-400">True Negatives (TN)</div>
                  <div className="text-2xl font-bold text-cyan-400 mt-1">{report.amrsf_hybrid.confusion_matrix.TN}</div>
                </div>
              </div>
            </div>

            <div className="glass-panel p-6">
              <h4 className="text-sm font-bold text-white mb-2">Research Contribution Note</h4>
              <p className="text-xs text-slate-300 leading-relaxed">
                As demonstrated in the evaluation results, AMRSF achieves a higher F1-score than traditional signature-only WAFs while maintaining sub-5ms inspection latency. By fusing recursive decoding and Shannon entropy with Explainable ML (SHAP), AMRSF detects zero-day encodings and obfuscated payloads without sacrificing interpretability for SOC operations.
              </p>
            </div>
          </div>
        </div>
      ) : (
        <div className="glass-panel p-12 text-center text-slate-400">
          Click <strong className="text-white">Run Scientific Evaluation</strong> to evaluate {samples} HTTP traffic samples and benchmark against ModSecurity CRS.
        </div>
      )}
    </div>
  )
}
