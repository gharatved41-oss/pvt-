import React, { useState, useEffect } from 'react';
import {
  RotateCcw, CheckCircle2, AlertTriangle, RefreshCw,
  Terminal, ShieldCheck, ArrowRight, Layers, Cpu
} from 'lucide-react';
import { api } from '../services/api';
import { VulnerabilityFinding, DigitalTwin, RetestResult, BeforeAfterComparison } from '../types';
import { StatusBadge } from '../components/Badges';

export const RetestingPage: React.FC = () => {
  const [findings, setFindings] = useState<VulnerabilityFinding[]>([]);
  const [twins, setTwins] = useState<DigitalTwin[]>([]);
  const [retestResults, setRetestResults] = useState<RetestResult[]>([]);
  const [loading, setLoading] = useState(true);

  // Execution state
  const [selectedFindingId, setSelectedFindingId] = useState('');
  const [selectedTwinId, setSelectedTwinId] = useState('');
  const [executing, setExecuting] = useState(false);
  const [activeComparison, setActiveComparison] = useState<BeforeAfterComparison | null>(null);

  const fetchData = async () => {
    setLoading(true);
    try {
      const [findingsData, twinsData, resultsData] = await Promise.all([
        api.getVulnerabilities(),
        api.getTwins(),
        api.getRetestResults()
      ]);
      setFindings(findingsData);
      setTwins(twinsData);
      setRetestResults(resultsData);

      if (findingsData.length > 0 && !selectedFindingId) {
        setSelectedFindingId(findingsData[0].id);
      }
      if (twinsData.length > 0 && !selectedTwinId) {
        setSelectedTwinId(twinsData[0].id);
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleExecuteRetest = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedFindingId || !selectedTwinId) return;

    setExecuting(true);
    try {
      await api.executeRetest(selectedFindingId, selectedTwinId);
      // Fetch detailed before/after comparison
      const comp = await api.getBeforeAfterComparison(selectedFindingId);
      setActiveComparison(comp);
      // Refresh list
      fetchData();
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Retest verification failed');
    } finally {
      setExecuting(false);
    }
  };

  const loadComparison = async (findingId: string) => {
    try {
      const comp = await api.getBeforeAfterComparison(findingId);
      setActiveComparison(comp);
    } catch (e) {
      console.error(e);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-slate-100 flex items-center">
            Retesting & Verification Engine
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Strict before-and-after re-detection and non-destructive re-validation to prove remediation efficacy
          </p>
        </div>

        <button
          onClick={fetchData}
          className="p-2 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 hover:text-cyan-400 text-xs flex items-center space-x-1.5 transition-colors self-start sm:self-auto"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          <span>Refresh</span>
        </button>
      </div>

      {/* Verification Rule Notice */}
      <div className="p-4 rounded-xl bg-gradient-to-r from-blue-950/60 to-slate-900 border border-blue-800/40 flex items-start space-x-3">
        <ShieldCheck className="w-5 h-5 text-cyan-400 flex-shrink-0 mt-0.5" />
        <div className="text-xs text-slate-300">
          <span className="font-bold text-cyan-300">Dual-Verification Criteria:</span> A disappearing scanner alert alone is never treated as proof of resolution.
          The engine recollecting package evidence inside the twin must prove: (1) scanner detection rules no longer match, AND (2) controlled non-destructive validation probes fail to reproduce the vulnerability.
        </div>
      </div>

      {/* Retest Execution Trigger Form */}
      <div className="cyber-card p-5 bg-[#0c1222] border border-slate-800 rounded-xl shadow-xl">
        <h3 className="text-xs font-mono font-bold text-slate-200 uppercase tracking-wider mb-4 flex items-center">
          <RotateCcw className="w-4 h-4 text-cyan-400 mr-2" />
          Trigger Retest Verification in Sandbox Replica
        </h3>

        <form onSubmit={handleExecuteRetest} className="grid grid-cols-1 sm:grid-cols-12 gap-3 text-xs items-end">
          <div className="sm:col-span-5">
            <label className="block font-medium text-slate-300 mb-1">Target Finding</label>
            <select
              value={selectedFindingId}
              onChange={(e) => {
                setSelectedFindingId(e.target.value);
                loadComparison(e.target.value);
              }}
              className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-100 focus:outline-none focus:border-cyan-500 font-sans"
            >
              {findings.map((f) => (
                <option key={f.id} value={f.id}>
                  {f.cve_id} - {f.affected_component} ({f.detection_status.toUpperCase()})
                </option>
              ))}
            </select>
          </div>

          <div className="sm:col-span-4">
            <label className="block font-medium text-slate-300 mb-1">Target Digital Twin Sandbox</label>
            <select
              value={selectedTwinId}
              onChange={(e) => setSelectedTwinId(e.target.value)}
              className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-100 focus:outline-none focus:border-cyan-500 font-sans"
            >
              {twins.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.name} ({t.ip_address})
                </option>
              ))}
            </select>
          </div>

          <div className="sm:col-span-3">
            <button
              type="submit"
              disabled={executing || !selectedFindingId || !selectedTwinId}
              className="w-full py-2.5 px-4 rounded-lg font-bold text-xs bg-cyan-500 hover:bg-cyan-400 text-slate-950 flex items-center justify-center space-x-1.5 transition-all shadow-md shadow-cyan-500/20 disabled:opacity-50"
            >
              {executing ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  <span>Verifying in Twin...</span>
                </>
              ) : (
                <>
                  <RotateCcw className="w-3.5 h-3.5" />
                  <span>Run Retest Verification</span>
                </>
              )}
            </button>
          </div>
        </form>
      </div>

      {/* Before-and-After Comparison Card */}
      {activeComparison && (
        <div className="cyber-card p-6 bg-[#0c1222] border border-cyan-800/50 rounded-xl shadow-2xl space-y-4">
          <div className="flex justify-between items-center pb-3 border-b border-slate-800">
            <h3 className="text-sm font-bold font-mono text-cyan-400 flex items-center uppercase tracking-wider">
              <Layers className="w-4 h-4 mr-2" />
              Before-and-After Remediation Verification Comparison
            </h3>
            <span className={`px-2.5 py-1 rounded text-xs font-mono font-bold uppercase ${
              activeComparison.final_status === 'resolved'
                ? 'bg-emerald-950 text-emerald-400 border border-emerald-700'
                : 'bg-amber-950 text-amber-400 border border-amber-700'
            }`}>
              Outcome: {activeComparison.final_status}
            </span>
          </div>

          {/* Comparison Side-by-Side Columns */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
            {/* Left: Baseline State */}
            <div className="p-4 rounded-lg bg-slate-950/80 border border-red-900/40 space-y-2">
              <span className="text-rose-400 font-bold block text-xs">BEFORE REMEDIATION (BASELINE)</span>
              <div className="flex justify-between py-1 border-b border-slate-800">
                <span className="text-slate-500">Component Version:</span>
                <span className="text-slate-200">{activeComparison.original_version}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-800">
                <span className="text-slate-500">Validation Status:</span>
                <span className="text-rose-400 font-bold">{activeComparison.original_status.toUpperCase()}</span>
              </div>
              <div className="flex justify-between py-1">
                <span className="text-slate-500">Initial Realized Risk:</span>
                <span className="text-rose-400 font-bold">{activeComparison.original_risk.toFixed(1)} / 100</span>
              </div>
            </div>

            {/* Right: Post-Remediation State */}
            <div className="p-4 rounded-lg bg-slate-950/80 border border-emerald-900/40 space-y-2">
              <span className="text-emerald-400 font-bold block text-xs">AFTER REMEDIATION (RETESTED)</span>
              <div className="flex justify-between py-1 border-b border-slate-800">
                <span className="text-slate-500">Upgraded Version:</span>
                <span className="text-emerald-300 font-bold">{activeComparison.new_version}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-800">
                <span className="text-slate-500">Retest Verdict:</span>
                <span className="text-emerald-400 font-bold">{activeComparison.final_status.toUpperCase()}</span>
              </div>
              <div className="flex justify-between py-1">
                <span className="text-slate-500">Remaining Risk:</span>
                <span className="text-emerald-400 font-bold">{activeComparison.remaining_risk.toFixed(1)} / 100</span>
              </div>
            </div>
          </div>

          {/* Applied Change & Evidence Logs */}
          <div className="p-3 bg-slate-900 border border-slate-800 rounded-lg text-xs font-mono space-y-2">
            <div className="text-slate-400">
              <span className="text-cyan-400 font-bold">Applied Vendor Change:</span> {activeComparison.remediation_applied}
            </div>
            <div className="text-slate-400">
              <span className="text-emerald-400 font-bold">Retest Evidence Telemetry:</span>
              <pre className="text-slate-300 bg-black/60 p-2 rounded mt-1 overflow-x-auto whitespace-pre-wrap text-[11px]">
                {activeComparison.retest_evidence}
              </pre>
            </div>
          </div>
        </div>
      )}

      {/* Retest History Table */}
      <div className="cyber-card bg-[#0c1222] border border-slate-800 rounded-xl overflow-hidden shadow-xl">
        <div className="px-5 py-3.5 bg-[#090d19] border-b border-slate-800">
          <h3 className="text-xs font-bold font-mono text-slate-200 uppercase tracking-wider">Historical Verification Records</h3>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#0b1020] text-slate-400 font-mono uppercase text-[10px] border-b border-slate-800">
              <tr>
                <th className="px-5 py-3">Timestamp</th>
                <th className="px-5 py-3">Pre-Fix Version</th>
                <th className="px-5 py-3">Post-Fix Version</th>
                <th className="px-5 py-3">Post-Fix Status</th>
                <th className="px-5 py-3">Remaining Risk</th>
                <th className="px-5 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {retestResults.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-5 py-8 text-center text-slate-500">
                    No retest verification records logged yet.
                  </td>
                </tr>
              ) : (
                retestResults.map((res) => (
                  <tr key={res.id} className="hover:bg-slate-900/60">
                    <td className="px-5 py-3 text-slate-400 text-[11px]">
                      {new Date(res.executed_at).toLocaleString()}
                    </td>
                    <td className="px-5 py-3 text-slate-300">{res.package_version_before}</td>
                    <td className="px-5 py-3 text-emerald-400 font-bold">{res.package_version_after}</td>
                    <td className="px-5 py-3">
                      <span className={`inline-block px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                        res.post_fix_status === 'resolved' ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' : 'bg-rose-950 text-rose-400'
                      }`}>
                        {res.post_fix_status}
                      </span>
                    </td>
                    <td className="px-5 py-3 text-slate-200 font-bold">
                      {res.remaining_risk_score.toFixed(1)} / 100
                    </td>
                    <td className="px-5 py-3 text-right">
                      <button
                        onClick={() => loadComparison(res.finding_id)}
                        className="text-cyan-400 hover:underline text-[11px]"
                      >
                        View Diff
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
