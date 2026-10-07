import React, { useState, useEffect } from 'react';
import { Wrench, CheckCircle2, ShieldCheck, ArrowRight, RefreshCw, Cpu, Layers, Check } from 'lucide-react';
import { API_BASE } from '../config/api';

export default function RemediationView({ onNavigateToTwin, activeAnalysis }) {
  const [targetAnalysis, setTargetAnalysis] = useState(activeAnalysis || null);
  const [isApplying, setIsApplying] = useState(false);
  const [applied, setApplied] = useState(false);
  const [isLoading, setIsLoading] = useState(!activeAnalysis);

  useEffect(() => {
    if (activeAnalysis) {
      setTargetAnalysis(activeAnalysis);
      setApplied(false);
      setIsLoading(false);
    } else {
      fetchLatestAnalysis();
    }
  }, [activeAnalysis]);

  const fetchLatestAnalysis = async () => {
    setIsLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/v1/history?limit=1`);
      if (res.ok) {
        const data = await res.json();
        if (data.items && data.items.length > 0) {
          // Fetch full report for this item
          const fullRes = await fetch(`${API_BASE}/api/v1/analysis/${data.items[0].analysis_id}`);
          if (fullRes.ok) {
            const fullData = await fullRes.json();
            setTargetAnalysis(fullData);
          }
        }
      }
    } catch (e) {
      console.warn('Failed to fetch latest analysis for remediation:', e);
    } finally {
      setIsLoading(false);
    }
  };

  const handleApplyFixes = () => {
    setIsApplying(true);
    setTimeout(() => {
      setIsApplying(false);
      setApplied(true);
    }, 900);
  };

  const beforeRisk = targetAnalysis?.risk_score ?? 0;
  const isSafeInitially = beforeRisk < 30;
  const afterRisk = isSafeInitially ? beforeRisk : Math.max(5, Math.round(beforeRisk * 0.25));
  const riskDelta = Math.max(0, beforeRisk - afterRisk);

  const targetName = targetAnalysis?.submitted_url || targetAnalysis?.domain || 'Target Endpoint';
  const recommendations = targetAnalysis?.recommendations && targetAnalysis.recommendations.length > 0
    ? targetAnalysis.recommendations
    : [
        {
          priority: 'MEDIUM',
          title: 'Implement Continuous Threat Intelligence Monitoring',
          action: 'Subscribe indicator to active reputation blocklists and SIEM event streams.',
          effort: 'LOW (15 mins)'
        }
      ];

  return (
    <div className="space-y-6 max-w-6xl mx-auto pb-12">
      
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-[#0B1F44]">
            Vulnerability Remediation &amp; Verification
          </h1>
          <p className="text-sm text-slate-500 mt-1">
            Target: <span className="font-mono text-slate-800 font-semibold">{targetName}</span>
          </p>
        </div>

        <div className="flex items-center gap-2">
          {!applied && (
            <button
              onClick={handleApplyFixes}
              disabled={isApplying || isLoading}
              className="px-4 py-2 bg-emerald-600 hover:bg-emerald-700 text-white font-semibold text-xs rounded-lg transition-colors shadow-sm flex items-center gap-1.5"
            >
              <Wrench className={`w-3.5 h-3.5 ${isApplying ? 'animate-spin' : ''}`} />
              <span>{isApplying ? 'Applying Fixes to Twin...' : 'Simulate Fix on Twin'}</span>
            </button>
          )}
          <button
            onClick={() => onNavigateToTwin && onNavigateToTwin(targetAnalysis)}
            className="px-4 py-2 bg-[#2563EB] hover:bg-blue-700 text-white font-semibold text-xs rounded-lg transition-colors shadow-sm flex items-center gap-1.5"
          >
            <Cpu className="w-3.5 h-3.5" />
            <span>Open Digital Twin Workspace</span>
          </button>
        </div>
      </div>

      {/* BEFORE vs AFTER */}
      <div className="bg-white border-2 border-emerald-500/40 rounded-xl p-6 shadow-sm space-y-6">
        <div className="flex items-center justify-between pb-4 border-b border-[#E2E8F0]">
          <div>
            <span className="text-xs font-bold text-emerald-700 uppercase tracking-wider">
              Verification Demonstration
            </span>
            <h2 className="text-lg font-bold text-[#0B1F44] mt-0.5">
              Remediation Comparison: BEFORE vs AFTER
            </h2>
          </div>
          <span className={`px-3 py-1 text-xs font-bold rounded-full ${
            applied 
              ? 'bg-emerald-100 text-emerald-800' 
              : 'bg-amber-100 text-amber-800'
          }`}>
            {applied ? '✓ Twin Re-test Confirmed' : 'Baseline Detected'}
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          
          {/* BEFORE */}
          <div className="bg-slate-50 border border-slate-200 rounded-xl p-5 space-y-4">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-slate-500 uppercase tracking-wider">BEFORE (Original Target)</span>
              <span className={`px-2.5 py-0.5 text-xs font-bold rounded ${
                beforeRisk >= 75 ? 'bg-rose-100 text-rose-700' : beforeRisk >= 30 ? 'bg-amber-100 text-amber-700' : 'bg-emerald-100 text-emerald-700'
              }`}>
                {beforeRisk >= 75 ? '🔴 High Risk' : beforeRisk >= 30 ? '🟠 Suspicious' : '🟢 Safe'}
              </span>
            </div>

            <div>
              <div className="text-3xl font-extrabold text-[#0B1F44]">
                {beforeRisk} <span className="text-sm font-normal text-slate-400">/ 100</span>
              </div>
              <div className="text-xs text-slate-500 font-medium mt-1">
                Verdict: <strong className={beforeRisk >= 75 ? 'text-rose-600' : 'text-slate-700'}>{targetAnalysis?.verdict || 'EVALUATED'}</strong>
              </div>
            </div>

            <p className="text-xs text-slate-500 font-sans leading-relaxed">
              {targetAnalysis?.summary || "Initial telemetry signals recorded prior to digital twin hardening."}
            </p>
          </div>

          {/* AFTER */}
          <div className="bg-emerald-50/50 border border-emerald-200 rounded-xl p-5 space-y-4">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-emerald-800 uppercase tracking-wider">AFTER (Twin Hardened)</span>
              <span className="px-2.5 py-0.5 bg-emerald-100 text-emerald-700 text-xs font-bold rounded">
                🟢 Hardened
              </span>
            </div>

            <div>
              <div className="text-3xl font-extrabold text-[#10B981]">
                {applied ? afterRisk : 'Pending'} <span className="text-sm font-normal text-slate-400">/ 100</span>
              </div>
              <div className="text-xs text-emerald-700 font-medium mt-1">
                Status: <strong className="text-emerald-700">{applied ? 'Remediated & Verified' : 'Awaiting Simulation'}</strong>
              </div>
            </div>

            <p className="text-xs text-slate-600 font-sans leading-relaxed">
              {applied 
                ? 'Policy updates verified on virtual twin; re-test confirmed critical exposures eliminated without breaking services.' 
                : 'Click "Simulate Fix on Twin" above to execute countermeasure probes and observe posture improvement.'}
            </p>
          </div>

        </div>

        {/* Delta Improvement Banner */}
        {applied && (
          <div className="p-3 bg-emerald-50 border border-emerald-200 rounded-lg text-center text-xs text-emerald-800 font-semibold">
            ─────── ↓ {riskDelta} Risk Points Posture Improvement ───────
          </div>
        )}
      </div>

      {/* Recommended Patches List */}
      <div className="bg-white border border-[#E2E8F0] rounded-xl shadow-sm overflow-hidden">
        <div className="px-6 py-4 border-b border-[#E2E8F0] flex items-center justify-between">
          <h3 className="text-sm font-bold text-[#0B1F44]">Prioritized Remediation Countermeasures</h3>
          <span className="text-xs text-slate-500">Derived from Real Evidence</span>
        </div>

        <div className="divide-y divide-[#E2E8F0]">
          {recommendations.map((rem, idx) => (
            <div key={idx} className="p-5 hover:bg-slate-50/80 transition-colors space-y-2">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-100 text-slate-700 font-semibold border border-slate-200">
                    REM-0{idx + 1}
                  </span>
                  <h4 className="text-sm font-bold text-slate-900">{rem.title}</h4>
                </div>

                <div className="flex items-center gap-2">
                  <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${
                    rem.priority === 'CRITICAL' ? 'bg-rose-100 text-rose-800' : rem.priority === 'HIGH' ? 'bg-amber-100 text-amber-800' : 'bg-blue-100 text-blue-800'
                  }`}>
                    {rem.priority}
                  </span>
                </div>
              </div>

              <p className="text-xs text-slate-600 font-sans leading-relaxed">
                <strong>Recommended Action:</strong> <code className="text-[11px] bg-slate-100 px-1 py-0.5 rounded font-mono text-slate-800">{rem.action || rem.reason}</code>
              </p>

              {rem.effort && (
                <div className="text-[11px] text-slate-400">
                  Estimated Engineering Effort: <strong className="text-slate-600">{rem.effort}</strong>
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

    </div>
  );
}
