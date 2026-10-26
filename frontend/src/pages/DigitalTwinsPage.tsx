import React, { useState, useEffect } from 'react';
import {
  Cpu, Plus, RefreshCw, ShieldCheck, CheckCircle2, RotateCcw,
  Camera, Lock, Play, Pause, AlertTriangle, X, Terminal
} from 'lucide-react';
import { api } from '../services/api';
import { DigitalTwin, Asset } from '../types';

export const DigitalTwinsPage: React.FC = () => {
  const [twins, setTwins] = useState<DigitalTwin[]>([]);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [templates, setTemplates] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreateModal, setShowCreateModal] = useState(false);

  // Create form state
  const [selectedAssetId, setSelectedAssetId] = useState('');
  const [twinName, setTwinName] = useState('');
  const [templateName, setTemplateName] = useState('ubuntu-22.04-cve-lab');
  const [actionLoading, setActionLoading] = useState<string | null>(null);

  const fetchData = async () => {
    setLoading(true);
    try {
      const [twinsData, assetsData, templatesData] = await Promise.all([
        api.getTwins(),
        api.getAssets(),
        api.getTwinTemplates()
      ]);
      setTwins(twinsData);
      setAssets(assetsData);
      setTemplates(templatesData);
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
        template_name: templateName
      });
      setShowCreateModal(false);
      setTwinName('');
      fetchData();
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to create digital twin');
    }
  };

  const handleTwinAction = async (twinId: string, action: string) => {
    setActionLoading(`${twinId}-${action}`);
    try {
      const res = await api.executeTwinAction(twinId, action);
      alert(`Action '${action}' executed successfully: ${JSON.stringify(res.result?.message || res.result)}`);
      fetchData();
    } catch (err: any) {
      alert(`Action failed: ${err.response?.data?.detail || 'Error'}`);
    } finally {
      setActionLoading(null);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-slate-100 flex items-center">
            Isolated Digital Twin Lab Sandbox
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Production-safe replica environments for non-destructive exploit validation & patch testing
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
      <div className="p-4 rounded-xl bg-gradient-to-r from-blue-950/60 to-slate-900 border border-cyan-800/40 flex items-start space-x-3">
        <ShieldCheck className="w-5 h-5 text-cyan-400 flex-shrink-0 mt-0.5" />
        <div className="text-xs text-slate-300">
          <span className="font-bold text-cyan-300">Air-Gapped Sandbox Policy Active:</span> Digital Twins run inside simulated isolated virtual networks (Subnet 192.168.100.0/24).
          All traffic between target assets and their replicas is strictly routed to an internal host-only switch. Real production hosts are never contacted during validation or remediation testing.
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
            return (
              <div key={twin.id} className="cyber-card p-6 bg-[#0c1222] border border-slate-800 rounded-xl space-y-4 shadow-xl">
                {/* Header */}
                <div className="flex justify-between items-start">
                  <div>
                    <div className="flex items-center space-x-2">
                      <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse" />
                      <h3 className="font-bold text-base text-slate-100">{twin.name}</h3>
                    </div>
                    <p className="text-[11px] font-mono text-cyan-400 mt-0.5">Template: {twin.template_name}</p>
                  </div>

                  <span className="px-2.5 py-1 rounded text-xs font-mono font-bold bg-emerald-950/80 text-emerald-400 border border-emerald-700 uppercase">
                    {twin.status}
                  </span>
                </div>

                {/* Details Metrics */}
                <div className="grid grid-cols-2 gap-3 text-xs font-mono">
                  <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
                    <span className="text-[10px] text-slate-400 uppercase block">Linked Asset</span>
                    <span className="text-slate-200 font-semibold truncate block">{parentAsset?.name || 'Production Target'}</span>
                    <span className="text-slate-400 text-[10px]">Host IP: {parentAsset?.ip_address}</span>
                  </div>
                  <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
                    <span className="text-[10px] text-slate-400 uppercase block">Twin Sandbox IP</span>
                    <span className="text-cyan-300 font-bold block">{twin.ip_address}</span>
                    <span className="text-emerald-400 text-[10px]">Isolated: {twin.network_isolated ? 'YES (VLAN 1099)' : 'NO'}</span>
                  </div>
                  <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
                    <span className="text-[10px] text-slate-400 uppercase block">Config Parity Score</span>
                    <span className="text-slate-100 font-bold block text-sm">{twin.config_parity_score}% Match</span>
                    <span className="text-slate-400 text-[10px]">Kernel & package fidelity</span>
                  </div>
                  <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
                    <span className="text-[10px] text-slate-400 uppercase block">Snapshot Status</span>
                    <span className="text-slate-200 font-semibold truncate block">{twin.snapshot_status}</span>
                    <span className="text-slate-400 text-[10px]">Rollback enabled</span>
                  </div>
                </div>

                {/* Control Actions */}
                <div className="pt-2 border-t border-slate-800/80 flex flex-wrap gap-2 text-xs">
                  <button
                    onClick={() => handleTwinAction(twin.id, 'reset_snapshot')}
                    disabled={actionLoading === `${twin.id}-reset_snapshot`}
                    className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-cyan-400 border border-slate-700 font-medium inline-flex items-center space-x-1.5 transition-colors disabled:opacity-50"
                  >
                    <RotateCcw className="w-3.5 h-3.5" />
                    <span>Reset to Baseline</span>
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
                </div>
              </div>
            );
          })
        )}
      </div>

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
                      {t.template_name} ({t.os_type}) - {t.isolation_mode}
                    </option>
                  ))}
                </select>
                <p className="text-[11px] text-slate-400 mt-1 font-mono">
                  Enforces strict network sandboxing and snapshot baseline initialization.
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
