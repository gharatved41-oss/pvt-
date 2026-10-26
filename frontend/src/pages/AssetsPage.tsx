import React, { useState, useEffect } from 'react';
import {
  Server, Plus, Upload, Trash2, ArrowRight, RefreshCw, FileText,
  CheckCircle2, AlertCircle, X, Shield, Terminal
} from 'lucide-react';
import { api } from '../services/api';
import { Asset } from '../types';

export const AssetsPage: React.FC = () => {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [loading, setLoading] = useState(true);
  const [showAddModal, setShowAddModal] = useState(false);
  const [showImportModal, setShowImportModal] = useState(false);
  const [selectedAsset, setSelectedAsset] = useState<Asset | null>(null);

  // Add Asset Form state
  const [name, setName] = useState('');
  const [ipAddress, setIpAddress] = useState('10.0.15.22');
  const [hostname, setHostname] = useState('app-worker-02');
  const [osType, setOsType] = useState<'linux' | 'windows'>('linux');
  const [osVersion, setOsVersion] = useState('Ubuntu 22.04 LTS');
  const [environment, setEnvironment] = useState<'production' | 'staging' | 'development'>('staging');
  const [criticality, setCriticality] = useState<'critical' | 'high' | 'medium' | 'low'>('high');
  const [description, setDescription] = useState('');

  // Import Inventory state
  const [importFile, setImportFile] = useState<File | null>(null);
  const [rawText, setRawText] = useState('');
  const [importLoading, setImportLoading] = useState(false);
  const [importMsg, setImportMsg] = useState('');

  const fetchAssets = async () => {
    setLoading(true);
    try {
      const data = await api.getAssets();
      setAssets(data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAssets();
  }, []);

  const handleCreateAsset = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await api.createAsset({
        name,
        ip_address: ipAddress,
        hostname,
        os_type: osType,
        os_version: osVersion,
        environment,
        criticality,
        description
      });
      setShowAddModal(false);
      resetAddForm();
      fetchAssets();
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to create asset');
    }
  };

  const resetAddForm = () => {
    setName('');
    setDescription('');
  };

  const handleDeleteAsset = async (id: string, assetName: string) => {
    if (window.confirm(`Are you sure you want to deactivate and remove asset "${assetName}"?`)) {
      await api.deleteAsset(id);
      fetchAssets();
    }
  };

  const handleImportSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedAsset) return;
    setImportLoading(true);
    setImportMsg('');

    try {
      const formData = new FormData();
      if (importFile) {
        formData.append('file', importFile);
      } else if (rawText) {
        formData.append('raw_content', rawText);
        formData.append('format_type', rawText.trim().startsWith('{') || rawText.trim().startsWith('[') ? 'json' : 'csv');
      } else {
        alert('Please attach a file or paste manifest text');
        setImportLoading(false);
        return;
      }

      const res = await api.importInventory(selectedAsset.id, formData);
      setImportMsg(`Successfully imported ${res.packages_count} packages!`);
      setTimeout(() => {
        setShowImportModal(false);
        setImportFile(null);
        setRawText('');
        setImportMsg('');
      }, 1200);
    } catch (err: any) {
      setImportMsg(`Import failed: ${err.response?.data?.detail || 'Unknown error'}`);
    } finally {
      setImportLoading(false);
    }
  };

  // Sample fixture injector helpers for testing convenience
  const injectSampleInventory = (type: 'ubuntu' | 'windows') => {
    if (type === 'ubuntu') {
      setRawText(`package_name,version,architecture,status,description
policykit-1,0.105-26ubuntu0.1,amd64,installed,authorization toolkit
openssh-server,1:8.9p1-3ubuntu0.1,amd64,installed,secure shell server
nginx,1.24.0-1ubuntu1,amd64,installed,reverse proxy
curl,7.81.0-1ubuntu1.13,amd64,installed,command line transfer tool
log4j-core,2.14.1,all,installed,Apache Log4j Core`);
    } else {
      setRawText(`package_name,version,architecture,status,description
windows-clfs,10.0.20348.1607,x64,installed,Common Log File System driver
curl,8.1.2,x64,installed,curl for Windows
log4j-core,2.14.0,all,installed,Log4j Enterprise Library`);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-slate-100 flex items-center">
            Authorized Asset Inventory
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Explicitly enrolled target systems for inventory collection and digital twin replication
          </p>
        </div>

        <div className="flex items-center space-x-3">
          <button
            onClick={fetchAssets}
            className="p-2 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 hover:text-cyan-400 text-xs flex items-center space-x-1 transition-colors"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">Refresh</span>
          </button>
          <button
            onClick={() => setShowAddModal(true)}
            className="px-3.5 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs flex items-center space-x-2 transition-all shadow-md shadow-cyan-500/20"
          >
            <Plus className="w-4 h-4" />
            <span>Add Asset</span>
          </button>
        </div>
      </div>

      {/* Asset Table Card */}
      <div className="cyber-card bg-[#0c1222] border border-slate-800 rounded-xl overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#090d19] border-b border-slate-800 text-slate-400 font-mono uppercase tracking-wider text-[11px]">
              <tr>
                <th className="px-5 py-3.5">Asset Name</th>
                <th className="px-5 py-3.5">IP & Hostname</th>
                <th className="px-5 py-3.5">Platform / OS</th>
                <th className="px-5 py-3.5">Tier & Criticality</th>
                <th className="px-5 py-3.5">Status</th>
                <th className="px-5 py-3.5 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-sans">
              {loading ? (
                <tr>
                  <td colSpan={6} className="px-5 py-12 text-center text-slate-500 font-mono">
                    <RefreshCw className="w-5 h-5 mx-auto animate-spin text-cyan-400 mb-2" />
                    Querying asset repository...
                  </td>
                </tr>
              ) : assets.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-5 py-12 text-center text-slate-500 font-mono">
                    No authorized assets found. Click "Add Asset" to register your first host.
                  </td>
                </tr>
              ) : (
                assets.map((asset) => (
                  <tr key={asset.id} className="hover:bg-slate-900/60 transition-colors">
                    <td className="px-5 py-4">
                      <div className="font-semibold text-slate-200 text-sm">{asset.name}</div>
                      <div className="text-[11px] text-slate-400 truncate max-w-xs">{asset.description || 'No description provided'}</div>
                    </td>
                    <td className="px-5 py-4 font-mono">
                      <div className="text-slate-300 font-medium">{asset.ip_address}</div>
                      <div className="text-[11px] text-slate-400">{asset.hostname}</div>
                    </td>
                    <td className="px-5 py-4">
                      <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono bg-slate-800 border border-slate-700 text-slate-300">
                        {asset.os_type.toUpperCase()}: {asset.os_version}
                      </span>
                    </td>
                    <td className="px-5 py-4">
                      <div className="space-y-1">
                        <span className="inline-block px-2 py-0.5 rounded text-[10px] font-mono uppercase bg-blue-950/80 border border-blue-700 text-blue-300">
                          {asset.environment}
                        </span>
                        <span className={`block text-[11px] font-semibold ${
                          asset.criticality === 'critical' ? 'text-red-400' : 'text-amber-400'
                        }`}>
                          {asset.criticality.toUpperCase()} CRITICALITY
                        </span>
                      </div>
                    </td>
                    <td className="px-5 py-4">
                      <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono bg-emerald-950/60 text-emerald-400 border border-emerald-800">
                        <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 mr-1.5" />
                        {asset.status.toUpperCase()}
                      </span>
                    </td>
                    <td className="px-5 py-4 text-right space-x-2">
                      <button
                        onClick={() => {
                          setSelectedAsset(asset);
                          setShowImportModal(true);
                        }}
                        className="px-2.5 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-cyan-400 text-xs font-medium border border-slate-700 transition-colors inline-flex items-center space-x-1"
                        title="Import Software Inventory"
                      >
                        <Upload className="w-3.5 h-3.5 mr-1" />
                        <span>Inventory</span>
                      </button>
                      <button
                        onClick={() => handleDeleteAsset(asset.id, asset.name)}
                        className="p-1.5 rounded hover:bg-rose-950 text-slate-500 hover:text-rose-400 border border-transparent hover:border-rose-800 transition-colors inline-flex items-center"
                        title="Delete Asset"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Add Asset Modal */}
      {showAddModal && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="cyber-card bg-[#0e1628] border border-slate-700 rounded-xl max-w-lg w-full p-6 shadow-2xl">
            <div className="flex justify-between items-center pb-4 border-b border-slate-800">
              <h3 className="font-bold text-base text-slate-100 flex items-center">
                <Server className="w-4 h-4 text-cyan-400 mr-2" />
                Register Authorized Test Asset
              </h3>
              <button onClick={() => setShowAddModal(false)} className="text-slate-400 hover:text-slate-200">
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleCreateAsset} className="space-y-4 mt-4 text-xs">
              <div>
                <label className="block font-medium text-slate-300 mb-1">Asset Name</label>
                <input
                  type="text"
                  required
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="e.g. Core Banking Application Cluster"
                  className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-100 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block font-medium text-slate-300 mb-1">IP Address</label>
                  <input
                    type="text"
                    required
                    value={ipAddress}
                    onChange={(e) => setIpAddress(e.target.value)}
                    className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-100 focus:outline-none focus:border-cyan-500 font-mono"
                  />
                </div>
                <div>
                  <label className="block font-medium text-slate-300 mb-1">Hostname</label>
                  <input
                    type="text"
                    required
                    value={hostname}
                    onChange={(e) => setHostname(e.target.value)}
                    className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-100 focus:outline-none focus:border-cyan-500 font-mono"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block font-medium text-slate-300 mb-1">Operating System</label>
                  <select
                    value={osType}
                    onChange={(e: any) => setOsType(e.target.value)}
                    className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-100 focus:outline-none focus:border-cyan-500"
                  >
                    <option value="linux">Linux (Debian/Ubuntu/RHEL)</option>
                    <option value="windows">Windows Server</option>
                  </select>
                </div>
                <div>
                  <label className="block font-medium text-slate-300 mb-1">OS Version String</label>
                  <input
                    type="text"
                    required
                    value={osVersion}
                    onChange={(e) => setOsVersion(e.target.value)}
                    placeholder="Ubuntu 22.04 LTS / Server 2022"
                    className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-100 focus:outline-none focus:border-cyan-500"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block font-medium text-slate-300 mb-1">Environment Tier</label>
                  <select
                    value={environment}
                    onChange={(e: any) => setEnvironment(e.target.value)}
                    className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-100 focus:outline-none focus:border-cyan-500"
                  >
                    <option value="production">Production</option>
                    <option value="staging">Staging</option>
                    <option value="development">Development</option>
                  </select>
                </div>
                <div>
                  <label className="block font-medium text-slate-300 mb-1">Criticality</label>
                  <select
                    value={criticality}
                    onChange={(e: any) => setCriticality(e.target.value)}
                    className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-100 focus:outline-none focus:border-cyan-500"
                  >
                    <option value="critical">Critical (Tier-1 Core)</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block font-medium text-slate-300 mb-1">Description / Notes</label>
                <textarea
                  rows={2}
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  placeholder="Security notes, business service mapping, or network zone..."
                  className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-100 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="flex justify-end space-x-3 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold"
                >
                  Register Asset
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Import Inventory Modal */}
      {showImportModal && selectedAsset && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="cyber-card bg-[#0e1628] border border-slate-700 rounded-xl max-w-xl w-full p-6 shadow-2xl">
            <div className="flex justify-between items-center pb-4 border-b border-slate-800">
              <div>
                <h3 className="font-bold text-base text-slate-100 flex items-center">
                  <Upload className="w-4 h-4 text-cyan-400 mr-2" />
                  Import Package & System Inventory
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">Target: {selectedAsset.name} ({selectedAsset.ip_address})</p>
              </div>
              <button onClick={() => setShowImportModal(false)} className="text-slate-400 hover:text-slate-200">
                <X className="w-4 h-4" />
              </button>
            </div>

            {importMsg && (
              <div className={`mt-3 p-3 rounded-lg text-xs font-mono ${
                importMsg.includes('Successfully') ? 'bg-emerald-950/60 border border-emerald-800 text-emerald-300' : 'bg-rose-950/60 border border-rose-800 text-rose-300'
              }`}>
                {importMsg}
              </div>
            )}

            <form onSubmit={handleImportSubmit} className="space-y-4 mt-4 text-xs">
              {/* Quick Fixture Injection Buttons */}
              <div className="p-3 bg-slate-900 border border-slate-800 rounded-lg">
                <span className="block text-[11px] font-mono text-cyan-400 mb-2 uppercase font-semibold">Load Sample Fixture Manifest</span>
                <div className="flex gap-2">
                  <button
                    type="button"
                    onClick={() => injectSampleInventory('ubuntu')}
                    className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 font-mono text-[11px] border border-slate-700"
                  >
                    Ubuntu Server CVE Fixture
                  </button>
                  <button
                    type="button"
                    onClick={() => injectSampleInventory('windows')}
                    className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 font-mono text-[11px] border border-slate-700"
                  >
                    Windows Server CVE Fixture
                  </button>
                </div>
              </div>

              <div>
                <label className="block font-medium text-slate-300 mb-1">Upload File (JSON or CSV)</label>
                <input
                  type="file"
                  accept=".json,.csv"
                  onChange={(e) => {
                    if (e.target.files?.[0]) {
                      setImportFile(e.target.files[0]);
                      setRawText('');
                    }
                  }}
                  className="w-full text-xs text-slate-400 file:mr-3 file:py-1.5 file:px-3 file:rounded-md file:border-0 file:text-xs file:font-semibold file:bg-slate-800 file:text-cyan-400 hover:file:bg-slate-700"
                />
              </div>

              <div className="text-center text-slate-500 font-mono text-[11px]">- OR PASTE RAW CSV / JSON -</div>

              <div>
                <textarea
                  rows={6}
                  value={rawText}
                  onChange={(e) => {
                    setRawText(e.target.value);
                    setImportFile(null);
                  }}
                  placeholder="Paste CSV format (package_name,version,architecture) or JSON manifest..."
                  className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-200 font-mono text-[11px] focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="flex justify-end space-x-3 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowImportModal(false)}
                  className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300"
                >
                  Close
                </button>
                <button
                  type="submit"
                  disabled={importLoading}
                  className="px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold disabled:opacity-50"
                >
                  {importLoading ? 'Validating & Parsing...' : 'Parse & Save Snapshot'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
