import React, { useState, useEffect } from 'react';
import {
  FlaskConical, Play, CheckCircle2, AlertTriangle, RefreshCw,
  Terminal, ShieldCheck, Lock, ArrowRight, Clock
} from 'lucide-react';
import { api } from '../services/api';
import { VulnerabilityFinding, DigitalTwin, ValidationRun } from '../types';
import { StatusBadge } from '../components/Badges';

export const ValidationLabPage: React.FC = () => {
  const [findings, setFindings] = useState<VulnerabilityFinding[]>([]);
  const [twins, setTwins] = useState<DigitalTwin[]>([]);
  const [procedures, setProcedures] = useState<any[]>([]);
  const [runs, setRuns] = useState<ValidationRun[]>([]);
  const [loading, setLoading] = useState(true);

  // Execution state
  const [selectedFindingId, setSelectedFindingId] = useState('');
  const [selectedTwinId, setSelectedTwinId] = useState('');
  const [executing, setExecuting] = useState(false);
  const [latestOutput, setLatestOutput] = useState<string>('');
  const [latestRun, setLatestRun] = useState<ValidationRun | null>(null);

  const fetchData = async () => {
    setLoading(true);
    try {
      const [findingsData, twinsData, procsData, runsData] = await Promise.all([
        api.getVulnerabilities(),
        api.getTwins(),
        api.getValidationProcedures(),
        api.getValidationRuns()
      ]);
      setFindings(findingsData);
      setTwins(twinsData);
      setProcedures(procsData);
      setRuns(runsData);

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

  const handleExecuteValidation = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedFindingId || !selectedTwinId) return;

    setExecuting(true);
    setLatestOutput('>>> Initializing isolated lab sandbox probe...\n>>> Verifying network isolation: VLAN 1099 active...\n>>> Checking safety preconditions...\n');
    
    try {
      const result = await api.executeValidation(selectedFindingId, selectedTwinId);
      setLatestRun(result);
      setLatestOutput(result.test_output);
      // Refresh findings and runs to show state transition
      const [updatedFindings, updatedRuns] = await Promise.all([
        api.getVulnerabilities(),
        api.getValidationRuns()
      ]);
      setFindings(updatedFindings);
      setRuns(updatedRuns);
    } catch (err: any) {
      setLatestOutput(`ERROR: ${err.response?.data?.detail || 'Validation execution failed.'}`);
    } finally {
      setExecuting(false);
    }
  };

  const selectedFinding = findings.find((f) => f.id === selectedFindingId);
  const selectedTwin = twins.find((t) => t.id === selectedTwinId);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-slate-100 flex items-center">
            Controlled Vulnerability Validation Lab
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Execute certified non-destructive test procedures inside isolated digital twins to verify exploitability
          </p>
        </div>

        <button
          onClick={fetchData}
          className="p-2 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 hover:text-cyan-400 text-xs flex items-center space-x-1.5 transition-colors self-start sm:self-auto"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          <span>Refresh Lab</span>
        </button>
      </div>

      {/* Safety Policy Alert Banner */}
      <div className="p-4 rounded-xl bg-cyan-950/40 border border-cyan-800/40 flex items-start space-x-3">
        <Lock className="w-5 h-5 text-cyan-400 flex-shrink-0 mt-0.5" />
        <div className="text-xs text-slate-300">
          <span className="font-bold text-cyan-300">Certified Test Policy Enforced:</span> Arbitrary command execution, unrestricted payloads, or automated exploit weaponization are prohibited by architecture.
          Each test procedure uses safe version handshakes, protocol inquiries, or canary lookups in designated lab replicas only.
        </div>
      </div>

      {/* Execution Control & Terminal Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Configuration Form (5 cols) */}
        <div className="lg:col-span-5 cyber-card p-5 bg-[#0c1222] border border-slate-800 rounded-xl space-y-4 shadow-xl">
          <h3 className="text-sm font-bold text-slate-200 flex items-center font-mono">
            <FlaskConical className="w-4 h-4 text-cyan-400 mr-2" />
            VALIDATION TEST PARAMETERS
          </h3>

          <form onSubmit={handleExecuteValidation} className="space-y-4 text-xs">
            <div>
              <label className="block font-medium text-slate-300 mb-1">Target Finding to Validate</label>
              <select
                value={selectedFindingId}
                onChange={(e) => setSelectedFindingId(e.target.value)}
                className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-100 focus:outline-none focus:border-cyan-500 font-sans"
              >
                {findings.map((f) => (
                  <option key={f.id} value={f.id}>
                    {f.cve_id} - {f.affected_component} ({f.severity.toUpperCase()})
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="block font-medium text-slate-300 mb-1">Target Digital Twin Replica</label>
              <select
                value={selectedTwinId}
                onChange={(e) => setSelectedTwinId(e.target.value)}
                className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-100 focus:outline-none focus:border-cyan-500 font-sans"
              >
                {twins.map((t) => (
                  <option key={t.id} value={t.id}>
                    {t.name} ({t.ip_address}) - {t.status.toUpperCase()}
                  </option>
                ))}
              </select>
            </div>

            {/* Selected Info Summary Card */}
            {selectedFinding && (
              <div className="p-3 bg-slate-900 border border-slate-800 rounded-lg space-y-1.5 font-mono text-[11px]">
                <div className="flex justify-between">
                  <span className="text-slate-400">Target Component:</span>
                  <span className="text-cyan-300 font-bold">{selectedFinding.affected_component}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Installed Version:</span>
                  <span className="text-slate-200">{selectedFinding.installed_version}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Current Status:</span>
                  <StatusBadge status={selectedFinding.detection_status} />
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Realized Risk:</span>
                  <span className="text-amber-400 font-bold">{selectedFinding.risk_score.toFixed(1)} / 100</span>
                </div>
              </div>
            )}

            <button
              type="submit"
              disabled={executing || !selectedFindingId || !selectedTwinId}
              className="w-full py-2.5 px-4 rounded-lg font-bold text-xs bg-cyan-500 hover:bg-cyan-400 text-slate-950 flex items-center justify-center space-x-2 transition-all shadow-md shadow-cyan-500/20 disabled:opacity-50"
            >
              {executing ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  <span>Probing Isolated Replica...</span>
                </>
              ) : (
                <>
                  <Play className="w-3.5 h-3.5" />
                  <span>Execute Non-Destructive Validation</span>
                </>
              )}
            </button>
          </form>
        </div>

        {/* Right: Live Diagnostic Output Console (7 cols) */}
        <div className="lg:col-span-7 cyber-card p-5 bg-[#090d19] border border-slate-800 rounded-xl space-y-3 shadow-xl flex flex-col">
          <div className="flex items-center justify-between pb-2 border-b border-slate-800">
            <span className="text-xs font-mono font-bold text-slate-300 flex items-center">
              <Terminal className="w-4 h-4 text-cyan-400 mr-2" />
              LIVE LAB EXECUTION TELEMETRY
            </span>
            {latestRun && (
              <span className={`text-[11px] font-mono px-2 py-0.5 rounded uppercase font-bold ${
                latestRun.outcome === 'confirmed' ? 'bg-emerald-950 text-emerald-400 border border-emerald-700' : 'bg-slate-800 text-slate-300'
              }`}>
                Verdict: {latestRun.outcome}
              </span>
            )}
          </div>

          <div className="flex-1 bg-black/60 rounded-lg p-4 font-mono text-[11px] text-cyan-400/90 overflow-y-auto max-h-72 whitespace-pre-wrap border border-slate-800/80">
            {latestOutput || (
              <span className="text-slate-600">
                Select a target vulnerability and isolated twin replica, then click 'Execute Non-Destructive Validation' to stream diagnostic output...
              </span>
            )}
          </div>

          <div className="text-[10px] text-slate-500 font-mono flex items-center justify-between">
            <span>Airgap Protocol: Active Sandbox</span>
            <span>Zero Production Degradation Guarantee</span>
          </div>
        </div>
      </div>

      {/* Validation History Table */}
      <div className="cyber-card bg-[#0c1222] border border-slate-800 rounded-xl overflow-hidden shadow-xl">
        <div className="px-5 py-3.5 bg-[#090d19] border-b border-slate-800">
          <h3 className="text-xs font-bold font-mono text-slate-200 uppercase tracking-wider">Historical Validation Audit Records</h3>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#0b1020] text-slate-400 font-mono uppercase text-[10px] border-b border-slate-800">
              <tr>
                <th className="px-5 py-3">Timestamp</th>
                <th className="px-5 py-3">Procedure Code</th>
                <th className="px-5 py-3">Preconditions</th>
                <th className="px-5 py-3">Outcome Verdict</th>
                <th className="px-5 py-3">Sandbox Isolation</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {runs.length === 0 ? (
                <tr>
                  <td colSpan={5} className="px-5 py-8 text-center text-slate-500">
                    No validation runs recorded in this session.
                  </td>
                </tr>
              ) : (
                runs.map((r) => (
                  <tr key={r.id} className="hover:bg-slate-900/60">
                    <td className="px-5 py-3 text-slate-400 text-[11px]">
                      {new Date(r.start_time).toLocaleString()}
                    </td>
                    <td className="px-5 py-3 text-cyan-400 font-bold">{r.procedure_code}</td>
                    <td className="px-5 py-3 text-slate-300">
                      {r.preconditions_met ? 'Met (Verified Ready)' : 'Failed Preconditions'}
                    </td>
                    <td className="px-5 py-3">
                      <span className={`inline-block px-2 py-0.5 rounded text-[10px] uppercase font-bold ${
                        r.outcome === 'confirmed' ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' : 'bg-slate-800 text-slate-300'
                      }`}>
                        {r.outcome}
                      </span>
                    </td>
                    <td className="px-5 py-3 text-slate-400 text-[11px]">
                      VLAN 1099 Airgapped
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
