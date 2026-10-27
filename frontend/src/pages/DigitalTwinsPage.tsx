import React, { useState, useEffect } from 'react';
import {
  Cpu, Plus, RefreshCw, ShieldCheck, CheckCircle2, RotateCcw,
  Camera, Lock, Play, Pause, AlertTriangle, X, Terminal, GitCompare,
  Trash2, Layers, Server, Activity, ShieldAlert
} from 'lucide-react';
import { api } from '../services/api';
import { DigitalTwin, Asset, ConfigComparisonReport } from '../types';

export const DigitalTwinsPage: React.FC = () => {
  const [twins, setTwins] = useState<DigitalTwin[]>([]);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [templates, setTemplates] = useState<any[]>([]);
  const [providers, setProviders] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [showCreateModal, setShowCreateModal] = useState(false);

  // Comparison modal state
  const [comparisonReport, setComparisonReport] = useState<ConfigComparisonReport | null>(null);
  const [comparingTwin, setComparingTwin] = useState<DigitalTwin | null>(null);
  const [comparisonLoading, setComparisonLoading] = useState(false);

  // Isolation modal state
  const [isolationData, setIsolationData] = useState<any | null>(null);

  // Create form state
  const [selectedAssetId, setSelectedAssetId] = useState('');
  const [twinName, setTwinName] = useState('');
  const [templateName, setTemplateName] = useState('ubuntu-22.04-cve-lab');
  const [actionLoading, setActionLoading] = useState<string | null>(null);

  const fetchData = async () => {
    setLoading(true);
    try {
      const [twinsData, assetsData, templatesData, providersData] = await Promise.all([
        api.getTwins(),
        api.getAssets(),
        api.getTwinTemplates(),
        api.getTwinProviders()
      ]);
      setTwins(twinsData);
      setAssets(assetsData);
      setTemplates(templatesData);
      setProviders(providersData);
      if (assetsData.length > 0 && !selectedAssetId) {
        setSelectedAssetId(assetsData[0].id);
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

  const handleCreateTwin = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedAssetId) return;
    try {
      await api.createTwin({
        asset_id: selectedAssetId,
        name: twinName,
        template_name: templateName,
        provider: 'mock_isolated'
      });
      setShowCreateModal(false);
      setTwinName('');
      fetchData();
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to create digital twin');
    }
  };

  const handleTwinAction = async (twinId: string, action: string, snapshotName?: string) => {
    setActionLoading(`${twinId}-${action}`);
    try {
      const res = await api.executeTwinAction(twinId, action, snapshotName);
      if (action === 'verify_isolation') {
        setIsolationData(res.result);
      } else {
        alert(`Action '${action}' completed successfully: ${res.result?.message || JSON.stringify(res.result)}`);
      }
      fetchData();
    } catch (err: any) {
      alert(`Action failed: ${err.response?.data?.detail || 'Error'}`);
    } finally {
      setActionLoading(null);
    }
  };

  const handleCompareConfig = async (twin: DigitalTwin) => {
    setComparingTwin(twin);
    setComparisonLoading(true);
    try {
      const report = await api.compareTwinConfig(twin.id);
      setComparisonReport(report);
    } catch (err: any) {
      alert(`Configuration comparison failed: ${err.response?.data?.detail || 'Error'}`);
    } finally {
      setComparisonLoading(false);
    }
  };

  const handleDeleteTwin = async (twinId: string, name: string) => {
    if (!confirm(`Are you sure you want to decommission and delete twin replica '${name}'?`)) return;
    try {
      await api.deleteTwin(twinId);
      fetchData();
    } catch (err: any) {
      alert(`Decommissioning failed: ${err.response?.data?.detail || 'Error'}`);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2">
            <h2 className="text-xl font-bold tracking-tight text-slate-100 flex items-center">
              Digital Twin Virtualization Lab
            </h2>
            <span className="px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-amber-950/80 text-amber-400 border border-amber-800">
              SIMULATION PLATFORM
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Air-gapped virtual replica environments for non-destructive exploit validation & patch testing
          </p>
        </div>

        <div className="flex items-center space-x-3">
          <button
            onClick={fetchData}
            className="p-2 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 hover:text-cyan-400 text-xs flex items-center space-x-1 transition-colors"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">Refresh</span>
          </button>
          <button
            onClick={() => setShowCreateModal(true)}
            className="px-3.5 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs flex items-center space-x-2 transition-all shadow-md shadow-cyan-500/20"
          >
            <Plus className="w-4 h-4" />
            <span>Deploy Twin Replica</span>
          </button>
        </div>
      </div>

      {/* Provider & Safety Notice */}
      <div className="p-4 rounded-xl bg-gradient-to-r from-blue-950/60 via-slate-900 to-amber-950/40 border border-cyan-800/40 flex items-start space-x-3">
        <ShieldCheck className="w-5 h-5 text-cyan-400 flex-shrink-0 mt-0.5" />
        <div className="text-xs text-slate-300 space-y-1">
          <div>
            <span className="font-bold text-cyan-300">Air-Gapped Sandbox Policy Active:</span> Digital Twins run inside simulated isolated virtual networks (Subnet 192.168.100.0/24, VLAN 1099).
            Zero WAN egress is permitted. All validation tests run strictly against virtualized clones, never production targets.
          </div>
          <div className="text-[11px] text-amber-300/90 font-mono">
            Provider Architecture: {providers?.active_provider || 'mock_isolated'} (Deterministic Sandboxed Simulation) • Validation Probes Blocked if Isolation Fails
          </div>
        </div>
      </div>

      {/* Digital Twins Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {loading ? (
          <div className="col-span-2 py-16 text-center text-slate-500 font-mono">
            <RefreshCw className="w-6 h-6 mx-auto animate-spin text-cyan-400 mb-2" />
            Connecting to Digital Twin virtualization provider...
          </div>
        ) : twins.length === 0 ? (
          <div className="col-span-2 py-16 text-center text-slate-500 font-mono">
            No digital twin replicas provisioned yet. Click "Deploy Twin Replica" to instantiate an isolated lab.
          </div>
        ) : (
          twins.map((twin) => {
            const parentAsset = assets.find((a) => a.id === twin.asset_id);
            const isReady = twin.status === 'ready';
            const isStopped = twin.status === 'stopped';
            const isTesting = twin.status === 'testing';

            return (
              <div key={twin.id} className="cyber-card p-6 bg-[#0c1222] border border-slate-800 rounded-xl space-y-4 shadow-xl">
                {/* Header */}
                <div className="flex justify-between items-start">
                  <div>
                    <div className="flex items-center space-x-2">
                      <span className={`w-2.5 h-2.5 rounded-full ${isReady ? 'bg-emerald-400 animate-pulse' : isStopped ? 'bg-slate-500' : 'bg-amber-400 animate-ping'}`} />
                      <h3 className="font-bold text-base text-slate-100">{twin.name}</h3>
                    </div>
                    <div className="flex items-center space-x-2 mt-1">
                      <span className="text-[11px] font-mono text-cyan-400">{twin.template_name}</span>
                      <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-amber-950/80 text-amber-300 border border-amber-700/60">
                        SIMULATION
                      </span>
                    </div>
                  </div>

                  <div className="flex items-center space-x-2">
                    <span className={`px-2.5 py-1 rounded text-xs font-mono font-bold uppercase border ${
                      isReady ? 'bg-emerald-950/80 text-emerald-400 border-emerald-700' :
                      isStopped ? 'bg-slate-900 text-slate-400 border-slate-700' :
                      'bg-amber-950/80 text-amber-400 border-amber-700'
                    }`}>
                      {twin.status}
                    </span>
                    <button
                      onClick={() => handleDeleteTwin(twin.id, twin.name)}
                      className="p-1 rounded text-slate-500 hover:text-rose-400 hover:bg-slate-900 transition-colors"
                      title="Decommission Twin"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>

                {/* Simulation Notice Banner */}
                <div className="px-3 py-1.5 rounded bg-slate-900/90 border border-amber-900/40 text-[11px] text-amber-200/80 flex items-center space-x-2 font-mono">
                  <Activity className="w-3.5 h-3.5 text-amber-400 flex-shrink-0" />
                  <span className="truncate">{twin.simulation_notice || 'Air-gapped lab simulation replica. Zero production risk.'}</span>
                </div>

                {/* Details Metrics */}
                <div className="grid grid-cols-2 gap-3 text-xs font-mono">
                  <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
                    <span className="text-[10px] text-slate-400 uppercase block">Linked Asset</span>
                    <span className="text-slate-200 font-semibold truncate block">{parentAsset?.name || 'Production Target'}</span>
                    <span className="text-slate-400 text-[10px]">Target IP: {parentAsset?.ip_address}</span>
                  </div>
                  <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
                    <span className="text-[10px] text-slate-400 uppercase block">Twin Sandbox IP</span>
                    <span className="text-cyan-300 font-bold block">{twin.ip_address}</span>
                    <span className="text-emerald-400 text-[10px]">Airgap: {twin.network_isolated ? 'VERIFIED (VLAN 1099)' : 'FAILED'}</span>
                  </div>
                  <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
                    <div className="flex justify-between items-center">
                      <span className="text-[10px] text-slate-400 uppercase block">Config Parity</span>
                      <button
                        onClick={() => handleCompareConfig(twin)}
                        className="text-[10px] text-cyan-400 hover:underline flex items-center space-x-0.5"
                      >
                        <GitCompare className="w-3 h-3" />
                        <span>Diff</span>
                      </button>
                    </div>
                    <span className="text-slate-100 font-bold block text-sm">{twin.config_parity_score}% Match</span>
                    <span className="text-slate-400 text-[10px]">Config fidelity score</span>
                  </div>
                  <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
                    <span className="text-[10px] text-slate-400 uppercase block">Snapshot Status</span>
                    <span className="text-slate-200 font-semibold truncate block">{twin.snapshot_status}</span>
                    <span className="text-slate-400 text-[10px]">Provider: {twin.provider}</span>
                  </div>
                </div>

                {/* Control Actions */}
                <div className="pt-2 border-t border-slate-800/80 flex flex-wrap gap-2 text-xs">
                  {isStopped ? (
                    <button
                      onClick={() => handleTwinAction(twin.id, 'start')}
                      disabled={actionLoading === `${twin.id}-start`}
                      className="px-3 py-1.5 rounded bg-emerald-950 hover:bg-emerald-900 text-emerald-300 border border-emerald-700 font-medium inline-flex items-center space-x-1.5 transition-colors disabled:opacity-50"
                    >
                      <Play className="w-3.5 h-3.5" />
                      <span>Start Twin</span>
                    </button>
                  ) : (
                    <button
                      onClick={() => handleTwinAction(twin.id, 'stop')}
                      disabled={actionLoading === `${twin.id}-stop` || isTesting}
                      className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-amber-400 border border-slate-700 font-medium inline-flex items-center space-x-1.5 transition-colors disabled:opacity-50"
                    >
                      <Pause className="w-3.5 h-3.5" />
                      <span>Stop Twin</span>
                    </button>
                  )}

                  <button
                    onClick={() => handleTwinAction(twin.id, 'reset_snapshot')}
                    disabled={actionLoading === `${twin.id}-reset_snapshot`}
                    className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-cyan-400 border border-slate-700 font-medium inline-flex items-center space-x-1.5 transition-colors disabled:opacity-50"
                  >
                    <RotateCcw className="w-3.5 h-3.5" />
                    <span>Reset Baseline</span>
                  </button>

                  <button
                    onClick={() => handleTwinAction(twin.id, 'create_snapshot')}
                    disabled={actionLoading === `${twin.id}-create_snapshot`}
                    className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-cyan-400 border border-slate-700 font-medium inline-flex items-center space-x-1.5 transition-colors disabled:opacity-50"
                  >
                    <Camera className="w-3.5 h-3.5" />
                    <span>Take Snapshot</span>
                  </button>

                  <button
                    onClick={() => handleTwinAction(twin.id, 'verify_isolation')}
                    disabled={actionLoading === `${twin.id}-verify_isolation`}
                    className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-emerald-400 border border-slate-700 font-medium inline-flex items-center space-x-1.5 transition-colors disabled:opacity-50"
                  >
                    <Lock className="w-3.5 h-3.5" />
                    <span>Verify Isolation</span>
                  </button>

                  <button
                    onClick={() => handleTwinAction(twin.id, 'sync_config')}
                    disabled={actionLoading === `${twin.id}-sync_config`}
                    className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-cyan-400 border border-slate-700 font-medium inline-flex items-center space-x-1.5 transition-colors disabled:opacity-50"
                  >
                    <Layers className="w-3.5 h-3.5" />
                    <span>Sync Config</span>
                  </button>
                </div>
              </div>
            );
          })
        )}
      </div>

      {/* Configuration Comparison Modal */}
      {comparisonReport && comparingTwin && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="cyber-card bg-[#0e1628] border border-cyan-800/80 rounded-xl max-w-2xl w-full p-6 shadow-2xl space-y-4">
            <div className="flex justify-between items-center pb-3 border-b border-slate-800">
              <div className="flex items-center space-x-2">
                <GitCompare className="w-5 h-5 text-cyan-400" />
                <h3 className="font-bold text-base text-slate-100">
                  Configuration Parity Report: {comparingTwin.name}
                </h3>
              </div>
              <button onClick={() => setComparisonReport(null)} className="text-slate-400 hover:text-slate-200">
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="flex items-center justify-between p-3 rounded-lg bg-slate-900 border border-slate-800 font-mono">
              <div>
                <span className="text-xs text-slate-400 block">Overall Parity Score</span>
                <span className="text-xl font-bold text-cyan-400">{comparisonReport.config_parity_score}%</span>
              </div>
              <p className="text-xs text-slate-300 max-w-xs">{comparisonReport.summary}</p>
            </div>

            {/* Matched parameters */}
            <div>
              <h4 className="text-xs font-bold text-emerald-400 uppercase tracking-wider mb-2 font-mono flex items-center">
                <CheckCircle2 className="w-3.5 h-3.5 mr-1.5" />
                Matched Directives ({Object.keys(comparisonReport.matched_parameters).length})
              </h4>
              <div className="max-h-32 overflow-y-auto space-y-1 font-mono text-[11px] p-2 rounded bg-slate-900/60 border border-slate-800">
                {Object.keys(comparisonReport.matched_parameters).length === 0 ? (
                  <span className="text-slate-500">None</span>
                ) : (
                  Object.entries(comparisonReport.matched_parameters).map(([k, v]) => (
                    <div key={k} className="flex justify-between text-slate-300">
                      <span className="text-slate-400">{k}:</span>
                      <span className="text-emerald-400 font-bold">{String(v)}</span>
                    </div>
                  ))
                )}
              </div>
            </div>

            {/* Differing parameters */}
            <div>
              <h4 className="text-xs font-bold text-amber-400 uppercase tracking-wider mb-2 font-mono flex items-center">
                <AlertTriangle className="w-3.5 h-3.5 mr-1.5" />
                Differing Parameters ({Object.keys(comparisonReport.differing_parameters).length})
              </h4>
              <div className="max-h-32 overflow-y-auto space-y-1 font-mono text-[11px] p-2 rounded bg-slate-900/60 border border-slate-800">
                {Object.keys(comparisonReport.differing_parameters).length === 0 ? (
                  <span className="text-slate-500">No discrepancies detected</span>
                ) : (
                  Object.entries(comparisonReport.differing_parameters).map(([k, v]) => (
                    <div key={k} className="p-1 rounded bg-slate-900/90 border border-slate-800/80">
                      <span className="text-amber-300 font-semibold">{k}</span>
                      <div className="flex justify-between text-[10px] mt-0.5">
                        <span className="text-slate-400">Target Asset: {String(v.target_value)}</span>
                        <span className="text-cyan-400">Twin Lab: {String(v.twin_value)}</span>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>

            <div className="flex justify-end pt-3 border-t border-slate-800">
              <button
                onClick={() => setComparisonReport(null)}
                className="px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs"
              >
                Close Report
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Isolation Telemetry Modal */}
      {isolationData && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="cyber-card bg-[#0e1628] border border-emerald-700/80 rounded-xl max-w-lg w-full p-6 shadow-2xl space-y-4">
            <div className="flex justify-between items-center pb-3 border-b border-slate-800">
              <div className="flex items-center space-x-2">
                <Lock className="w-5 h-5 text-emerald-400" />
                <h3 className="font-bold text-base text-slate-100">Air-Gap Isolation Telemetry</h3>
              </div>
              <button onClick={() => setIsolationData(null)} className="text-slate-400 hover:text-slate-200">
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-2 text-xs font-mono">
              <div className="p-3 rounded bg-emerald-950/50 border border-emerald-800 text-emerald-300 flex items-center space-x-2">
                <CheckCircle2 className="w-4 h-4 flex-shrink-0" />
                <span>Sandbox isolation verified. Safe for controlled non-destructive validation.</span>
              </div>
              <div className="p-3 rounded bg-slate-900 border border-slate-800 space-y-1.5 text-slate-300">
                <div className="flex justify-between"><span>VLAN Tag:</span><span className="text-cyan-400 font-bold">{isolationData.vlan_tag}</span></div>
                <div className="flex justify-between"><span>WAN Default Route:</span><span className="text-emerald-400 font-bold">{isolationData.internet_gateway_blocked ? 'BLOCKED (DROP 0.0.0.0/0)' : 'ACTIVE'}</span></div>
                <div className="flex justify-between"><span>Production Route:</span><span className="text-emerald-400 font-bold">{isolationData.production_traffic_blocked ? 'BLOCKED' : 'EXPOSED'}</span></div>
                <div className="flex justify-between"><span>Safe for Validation:</span><span className="text-emerald-400 font-bold">CONFIRMED</span></div>
              </div>
            </div>

            <div className="flex justify-end pt-3 border-t border-slate-800">
              <button
                onClick={() => setIsolationData(null)}
                className="px-4 py-2 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-xs"
              >
                Acknowledge Isolation
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Deploy Twin Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="cyber-card bg-[#0e1628] border border-slate-700 rounded-xl max-w-lg w-full p-6 shadow-2xl">
            <div className="flex justify-between items-center pb-4 border-b border-slate-800">
              <h3 className="font-bold text-base text-slate-100 flex items-center">
                <Cpu className="w-4 h-4 text-cyan-400 mr-2" />
                Deploy Isolated Digital Twin Replica
              </h3>
              <button onClick={() => setShowCreateModal(false)} className="text-slate-400 hover:text-slate-200">
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleCreateTwin} className="space-y-4 mt-4 text-xs">
              <div>
                <label className="block font-medium text-slate-300 mb-1">Target Production Asset</label>
                <select
                  value={selectedAssetId}
                  onChange={(e) => setSelectedAssetId(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-100 focus:outline-none focus:border-cyan-500 font-sans"
                >
                  {assets.map((a) => (
                    <option key={a.id} value={a.id}>
                      {a.name} ({a.ip_address}) - {a.os_type.toUpperCase()}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block font-medium text-slate-300 mb-1">Twin Replica Name</label>
                <input
                  type="text"
                  value={twinName}
                  onChange={(e) => setTwinName(e.target.value)}
                  placeholder="e.g. Twin-WebGateway-IsolatedLab"
                  className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-100 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div>
                <label className="block font-medium text-slate-300 mb-1">Certified Lab Sandbox Template</label>
                <select
                  value={templateName}
                  onChange={(e) => setTemplateName(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-100 focus:outline-none focus:border-cyan-500 font-sans"
                >
                  {templates.map((t) => (
                    <option key={t.template_name} value={t.template_name}>
                      {t.template_name} ({t.os_type.toUpperCase()}) - {t.isolation_mode}
                    </option>
                  ))}
                </select>
                <p className="text-[11px] text-amber-400/90 mt-1 font-mono">
                  [Simulation Notice]: All templates instantiate in virtual sandboxes with air-gapped VLAN tags.
                </p>
              </div>

              <div className="flex justify-end space-x-3 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold"
                >
                  Instantiate Twin Sandbox
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

