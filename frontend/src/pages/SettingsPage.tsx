import React, { useState, useEffect } from 'react';
import {
  Settings as SettingsIcon, ShieldCheck, Activity, Cpu,
  Database, RefreshCw, CheckCircle2, AlertTriangle, BrainCircuit, Play
} from 'lucide-react';
import { api } from '../services/api';
import { SystemSettings } from '../types';

export const SettingsPage: React.FC = () => {
  const [settings, setSettings] = useState<SystemSettings | null>(null);
  const [health, setHealth] = useState<any>(null);
  const [modelStatus, setModelStatus] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  // ML Risk Simulator Interactive Sandbox
  const [simCvss, setSimCvss] = useState(8.5);
  const [simCrit, setSimCrit] = useState('critical');
  const [simEnv, setSimEnv] = useState('production');
  const [simExploit, setSimExploit] = useState('functional');
  const [simPatch, setSimPatch] = useState(true);
  const [simEvidence, setSimEvidence] = useState('confirmed');
  const [simResult, setSimResult] = useState<any>(null);
  const [simLoading, setSimLoading] = useState(false);

  const fetchData = async () => {
    setLoading(true);
    try {
      const [settingsData, healthData, modelData] = await Promise.all([
        api.getSettings(),
        api.getHealth(),
        api.getRiskModelStatus().catch(() => null)
      ]);
      setSettings(settingsData);
      setHealth(healthData);
      setModelStatus(modelData);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleRunSimulator = async () => {
    setSimLoading(true);
    try {
      const res = await api.evaluateRisk({
        cvss_score: Number(simCvss),
        asset_criticality: simCrit,
        asset_environment: simEnv,
        exploit_maturity: simExploit,
        patch_available: simPatch,
        evidence_depth: simEvidence,
        detection_status: simEvidence === 'confirmed' ? 'confirmed' : 'detected'
      });
      setSimResult(res);
    } catch (e) {
      console.error(e);
    } finally {
      setSimLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-slate-100 flex items-center">
            Application Settings & Telemetry
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Architecture parameters, hypervisor sandbox interfaces, and live health status
          </p>
        </div>

        <button
          onClick={fetchData}
          className="p-2 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 hover:text-cyan-400 text-xs flex items-center space-x-1.5 transition-colors self-start sm:self-auto"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          <span>Refresh Status</span>
        </button>
      </div>

      {/* System Status Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 font-mono text-xs">
        <div className="cyber-card p-4 bg-[#0c1222] border border-slate-800 rounded-xl space-y-2">
          <div className="flex items-center justify-between text-slate-400">
            <span>DATABASE ENGINE</span>
            <Database className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-sm font-bold text-slate-200">
            {settings?.database_backend || 'SQLite with Foreign Keys'}
          </div>
          <div className="flex items-center text-emerald-400 text-[11px]">
            <CheckCircle2 className="w-3 h-3 mr-1" />
            <span>Connection: {health?.database_connected ? 'HEALTHY' : 'DEGRADED'}</span>
          </div>
        </div>

        <div className="cyber-card p-4 bg-[#0c1222] border border-slate-800 rounded-xl space-y-2">
          <div className="flex items-center justify-between text-slate-400">
            <span>TWIN SANDBOX PROVIDER</span>
            <Cpu className="w-4 h-4 text-purple-400" />
          </div>
          <div className="text-sm font-bold text-slate-200">
            MockIsolatedSandbox (VLAN 1099)
          </div>
          <div className="flex items-center text-emerald-400 text-[11px]">
            <CheckCircle2 className="w-3 h-3 mr-1" />
            <span>Airgap Network Isolation: ACTIVE</span>
          </div>
        </div>

        <div className="cyber-card p-4 bg-[#0c1222] border border-slate-800 rounded-xl space-y-2">
          <div className="flex items-center justify-between text-slate-400">
            <span>AI/ML RISK MODEL</span>
            <BrainCircuit className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-sm font-bold text-slate-200">
            {modelStatus?.model_type || 'GradientBoostingRegressor'}
          </div>
          <div className="flex items-center text-cyan-400 text-[11px]">
            <CheckCircle2 className="w-3 h-3 mr-1" />
            <span>
              {modelStatus?.is_ml_active
                ? `Active (R²=${modelStatus.r2_score}, MAE=±${modelStatus.mean_absolute_error})`
                : 'Baseline Engine Active'}
            </span>
          </div>
        </div>
      </div>

      {/* Architecture & Configuration Details */}
      <div className="cyber-card p-6 bg-[#0c1222] border border-slate-800 rounded-xl space-y-4">
        <h3 className="text-sm font-bold text-slate-200 font-mono flex items-center">
          <SettingsIcon className="w-4 h-4 text-cyan-400 mr-2" />
          SYSTEM CONFIGURATION OVERVIEW
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
          <div className="p-3 bg-slate-900 rounded-lg border border-slate-800 space-y-1">
            <span className="text-slate-400 text-[10px] uppercase">NVD API Integration</span>
            <div className="text-slate-200 font-bold">
              {settings?.nvd_api_connected ? 'CONNECTED (Live NIST Endpoints)' : 'FALLBACK (Air-Gapped Deterministic Catalog)'}
            </div>
            <p className="text-slate-400 text-[10px]">Deterministic catalog size: {health?.offline_cve_catalog_size || 7} certified entries</p>
          </div>

          <div className="p-3 bg-slate-900 rounded-lg border border-slate-800 space-y-1">
            <span className="text-slate-400 text-[10px] uppercase">Supported Operating Systems</span>
            <div className="text-slate-200 font-bold">Linux (Ubuntu/Debian/RHEL) & Windows Server</div>
            <p className="text-slate-400 text-[10px]">Package managers: dpkg, apt, rpm, winreg, winget</p>
          </div>

          <div className="p-3 bg-slate-900 rounded-lg border border-slate-800 space-y-1">
            <span className="text-slate-400 text-[10px] uppercase">Validation Procedure Timeout</span>
            <div className="text-slate-200 font-bold">{settings?.max_validation_timeout || 45} Seconds Max</div>
            <p className="text-slate-400 text-[10px]">Automatic execution cutoff to protect replica resources</p>
          </div>

          <div className="p-3 bg-slate-900 rounded-lg border border-slate-800 space-y-1">
            <span className="text-slate-400 text-[10px] uppercase">Sandbox Subnet</span>
            <div className="text-slate-200 font-bold">{settings?.twin_isolation_network || '192.168.100.0/24-isolated-lab'}</div>
            <p className="text-slate-400 text-[10px]">Virtual switch without default WAN route</p>
          </div>
        </div>
      </div>

      {/* Interactive AI/ML Risk Scoring Sandbox */}
      <div className="cyber-card p-6 bg-[#0c1222] border border-cyan-800/40 rounded-xl space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-bold text-cyan-400 font-mono flex items-center uppercase">
            <BrainCircuit className="w-4 h-4 mr-2" />
            Interactive AI/ML Risk Simulator
          </h3>
          <span className="text-[11px] font-mono text-slate-400">Test Real-Time Weight Dynamics</span>
        </div>

        <p className="text-xs text-slate-300">
          Adjust theoretical security parameters below to observe how the trained scikit-learn model calculates realized risk scores and derives explainable factor weights:
        </p>

        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 text-xs">
          <div>
            <label className="block text-slate-400 font-mono text-[10px] mb-1">CVSS Base (0-10)</label>
            <input
              type="number"
              step="0.1"
              min="0"
              max="10"
              value={simCvss}
              onChange={(e) => setSimCvss(parseFloat(e.target.value))}
              className="w-full px-2 py-1.5 bg-slate-900 border border-slate-700 rounded font-mono text-slate-200"
            />
          </div>

          <div>
            <label className="block text-slate-400 font-mono text-[10px] mb-1">Asset Criticality</label>
            <select
              value={simCrit}
              onChange={(e) => setSimCrit(e.target.value)}
              className="w-full px-2 py-1.5 bg-slate-900 border border-slate-700 rounded font-mono text-slate-200"
            >
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>

          <div>
            <label className="block text-slate-400 font-mono text-[10px] mb-1">Environment</label>
            <select
              value={simEnv}
              onChange={(e) => setSimEnv(e.target.value)}
              className="w-full px-2 py-1.5 bg-slate-900 border border-slate-700 rounded font-mono text-slate-200"
            >
              <option value="production">Production</option>
              <option value="staging">Staging</option>
              <option value="development">Dev</option>
            </select>
          </div>

          <div>
            <label className="block text-slate-400 font-mono text-[10px] mb-1">Exploit Maturity</label>
            <select
              value={simExploit}
              onChange={(e) => setSimExploit(e.target.value)}
              className="w-full px-2 py-1.5 bg-slate-900 border border-slate-700 rounded font-mono text-slate-200"
            >
              <option value="high">Weaponized / High</option>
              <option value="functional">Functional</option>
              <option value="poc">PoC</option>
              <option value="unproven">Unproven</option>
            </select>
          </div>

          <div>
            <label className="block text-slate-400 font-mono text-[10px] mb-1">Twin Verification</label>
            <select
              value={simEvidence}
              onChange={(e) => setSimEvidence(e.target.value)}
              className="w-full px-2 py-1.5 bg-slate-900 border border-slate-700 rounded font-mono text-slate-200"
            >
              <option value="confirmed">Confirmed in Twin</option>
              <option value="manifest">Manifest Only</option>
              <option value="heuristic">Heuristic</option>
            </select>
          </div>

          <div className="flex items-end">
            <button
              type="button"
              onClick={handleRunSimulator}
              disabled={simLoading}
              className="w-full py-1.5 px-3 rounded bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold font-mono text-xs flex items-center justify-center space-x-1"
            >
              <Play className="w-3 h-3" />
              <span>{simLoading ? 'Scoring...' : 'Evaluate'}</span>
            </button>
          </div>
        </div>

        {/* Simulator Result Output */}
        {simResult && (
          <div className="mt-4 p-5 rounded-lg bg-slate-950 border border-cyan-800/60 font-mono text-xs space-y-4">
            {/* Top Score Bar */}
            <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-2 pb-3 border-b border-slate-800">
              <div>
                <span className="text-slate-400 text-[10px] block uppercase">Composite Realized Risk</span>
                <span className="text-xl font-extrabold text-cyan-400">
                  {simResult.risk_score} <span className="text-xs text-slate-500">/ 100</span> ({simResult.risk_category})
                </span>
              </div>
              <div className="text-left sm:text-right">
                <span className="text-slate-400 text-[10px] block uppercase">Recommended Action</span>
                <span className="text-xs font-bold text-amber-400">{simResult.recommended_priority}</span>
              </div>
            </div>

            {/* Separated Dimensions: Severity vs Exploitability vs Context */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              {/* Intrinsic Severity */}
              <div className="p-3 rounded bg-slate-900 border border-slate-800 space-y-1">
                <span className="text-slate-400 text-[10px] uppercase block">1. Intrinsic Severity</span>
                <div className="text-sm font-bold text-amber-400">
                  CVSS {simResult.severity_metrics?.cvss_base_score || simResult.severity}
                </div>
                <p className="text-[10px] text-slate-400 font-sans">
                  Property of flaw alone; independent of target environment.
                </p>
              </div>

              {/* Exploitability */}
              <div className="p-3 rounded bg-slate-900 border border-slate-800 space-y-1">
                <span className="text-slate-400 text-[10px] uppercase block">2. Exploit Intelligence</span>
                <div className="text-sm font-bold text-purple-400">
                  {simResult.exploitability_metrics?.exploit_maturity || 'PoC Code'}
                </div>
                <p className="text-[10px] text-slate-400 font-sans">
                  {simResult.exploitability_metrics?.weaponized ? 'Weaponized public exploit' : 'Public code / advisory available'}
                </p>
              </div>

              {/* Contextual Asset Risk */}
              <div className="p-3 rounded bg-slate-900 border border-slate-800 space-y-1">
                <span className="text-slate-400 text-[10px] uppercase block">3. Contextual Asset Risk</span>
                <div className="text-sm font-bold text-cyan-400">
                  {simResult.contextual_metrics?.asset_criticality} on {simResult.contextual_metrics?.asset_environment}
                </div>
                <p className="text-[10px] text-slate-400 font-sans">
                  {simResult.contextual_metrics?.reachability} context.
                </p>
              </div>
            </div>

            {/* Baseline vs Model Comparison & Uncertainty */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2 border-t border-slate-800/80">
              <div className="p-3 rounded bg-slate-900/60 border border-slate-800 space-y-1">
                <span className="text-slate-400 text-[10px] uppercase block">Calculation Transparency</span>
                <div className="flex items-center space-x-3 text-xs">
                  <span>Baseline Formula: <strong className="text-slate-200">{simResult.baseline_risk_score}</strong></span>
                  {simResult.ml_risk_score !== null && (
                    <span>ML Ensemble: <strong className="text-cyan-400">{simResult.ml_risk_score}</strong></span>
                  )}
                </div>
                <p className="text-[10px] text-slate-500 font-sans">Engine: {simResult.scoring_engine}</p>
              </div>

              <div className="p-3 rounded bg-slate-900/60 border border-slate-800 space-y-1">
                <span className="text-slate-400 text-[10px] uppercase block">Uncertainty & Confidence</span>
                <div className="flex items-center space-x-3 text-xs">
                  <span>Confidence: <strong className="text-emerald-400">{Math.round((simResult.confidence_score || 0.85) * 100)}%</strong></span>
                  <span>Margin: <strong className="text-slate-300">±{simResult.uncertainty?.margin_of_error || 5.0} pts</strong></span>
                </div>
                <p className="text-[10px] text-slate-400 font-sans">
                  Interval: [{simResult.uncertainty?.confidence_interval?.[0]} - {simResult.uncertainty?.confidence_interval?.[1]}]
                </p>
              </div>
            </div>

            {/* Contributing Factor Breakdown */}
            {simResult.contributing_factors && (
              <div className="space-y-1.5 pt-2 border-t border-slate-800/80">
                <span className="text-slate-400 text-[10px] uppercase block">Contributing Factors & Weights</span>
                <div className="grid grid-cols-2 sm:grid-cols-5 gap-2 text-[10px]">
                  {Object.entries(simResult.contributing_factors).map(([key, item]: any) => (
                    <div key={key} className="p-2 bg-slate-900 rounded border border-slate-800">
                      <span className="text-slate-400 block truncate">{key.replace(/_/g, ' ').toUpperCase()}</span>
                      <span className="text-cyan-400 font-bold">{item.weight} ({item.points_contributed || 0} pts)</span>
                      <p className="text-slate-500 truncate mt-0.5">{item.detail}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}

            <p className="text-slate-300 font-sans text-xs bg-slate-900/50 p-2.5 rounded border border-slate-800">
              {simResult.risk_explanation}
            </p>
          </div>
        )}
      </div>
    </div>
  );
};
