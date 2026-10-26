import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import {
  Activity, PlayCircle, RefreshCw, FileText, ArrowRight,
  ShieldAlert, CheckCircle2, AlertTriangle, X
} from 'lucide-react';
import { api } from '../services/api';
import { Assessment, Asset } from '../types';

export const AssessmentsPage: React.FC = () => {
  const [assessments, setAssessments] = useState<Assessment[]>([]);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [loading, setLoading] = useState(true);
  const [showRunModal, setShowRunModal] = useState(false);
  const [selectedAssetId, setSelectedAssetId] = useState('');
  const [title, setTitle] = useState('');
  const [notes, setNotes] = useState('');
  const [runLoading, setRunLoading] = useState(false);

  const fetchData = async () => {
    setLoading(true);
    try {
      const [assData, assetData] = await Promise.all([
        api.getAssessments(),
        api.getAssets()
      ]);
      setAssessments(assData);
      setAssets(assetData);
      if (assetData.length > 0 && !selectedAssetId) {
        setSelectedAssetId(assetData[0].id);
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

  const handleRunAssessment = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedAssetId) return;
    setRunLoading(true);
    try {
      await api.runAssessment(selectedAssetId, title, notes);
      setShowRunModal(false);
      setTitle('');
      setNotes('');
      fetchData();
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to start assessment. Please ensure an inventory snapshot is imported for this asset.');
    } finally {
      setRunLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-slate-100 flex items-center">
            Vulnerability & Risk Assessments
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Automated CVE matching, ML risk evaluation, and evidence extraction pipeline
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
            onClick={() => setShowRunModal(true)}
            className="px-3.5 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs flex items-center space-x-2 transition-all shadow-md shadow-cyan-500/20"
          >
            <PlayCircle className="w-4 h-4" />
            <span>Execute Assessment</span>
          </button>
        </div>
      </div>

      {/* Assessment Table */}
      <div className="cyber-card bg-[#0c1222] border border-slate-800 rounded-xl overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#090d19] border-b border-slate-800 text-slate-400 font-mono uppercase tracking-wider text-[11px]">
              <tr>
                <th className="px-5 py-3.5">Assessment Details</th>
                <th className="px-5 py-3.5">Target Host</th>
                <th className="px-5 py-3.5">Findings Severity Breakdown</th>
                <th className="px-5 py-3.5">Avg Realized Risk</th>
                <th className="px-5 py-3.5">Status</th>
                <th className="px-5 py-3.5 text-right">Reports & Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {loading ? (
                <tr>
                  <td colSpan={6} className="px-5 py-12 text-center text-slate-500 font-mono">
                    <RefreshCw className="w-5 h-5 mx-auto animate-spin text-cyan-400 mb-2" />
                    Loading assessments...
                  </td>
                </tr>
              ) : assessments.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-5 py-12 text-center text-slate-500 font-mono">
                    No assessments executed yet. Click "Execute Assessment" to begin.
                  </td>
                </tr>
              ) : (
                assessments.map((ass) => {
                  const targetAsset = assets.find((a) => a.id === ass.asset_id);
                  return (
                    <tr key={ass.id} className="hover:bg-slate-900/60 transition-colors">
                      <td className="px-5 py-4">
                        <div className="font-semibold text-slate-200 text-sm">{ass.title}</div>
                        <div className="text-[11px] font-mono text-slate-400 mt-0.5">
                          Started: {new Date(ass.started_at).toLocaleString()}
                        </div>
                      </td>
                      <td className="px-5 py-4">
                        <div className="font-semibold text-slate-300">{targetAsset?.name || 'Authorized Target'}</div>
                        <div className="text-[11px] font-mono text-slate-400">{targetAsset?.ip_address}</div>
                      </td>
                      <td className="px-5 py-4">
                        <div className="flex items-center space-x-1.5 font-mono text-[11px]">
                          <span className="px-2 py-0.5 rounded bg-red-950/80 text-red-400 border border-red-800">
                            {ass.critical_count} Crit
                          </span>
                          <span className="px-2 py-0.5 rounded bg-orange-950/80 text-orange-400 border border-orange-800">
                            {ass.high_count} High
                          </span>
                          <span className="px-2 py-0.5 rounded bg-amber-950/80 text-amber-400 border border-amber-800">
                            {ass.medium_count} Med
                          </span>
                          <span className="px-2 py-0.5 rounded bg-blue-950/80 text-blue-400 border border-blue-800">
                            {ass.low_count} Low
                          </span>
                        </div>
                      </td>
                      <td className="px-5 py-4">
                        <div className="font-bold text-slate-100 font-mono text-sm">
                          {ass.average_risk_score.toFixed(1)} <span className="text-slate-500 text-xs">/ 100</span>
                        </div>
                      </td>
                      <td className="px-5 py-4">
                        <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono bg-emerald-950/60 text-emerald-400 border border-emerald-800 uppercase">
                          <CheckCircle2 className="w-3.5 h-3.5 mr-1" />
                          {ass.status}
                        </span>
                      </td>
                      <td className="px-5 py-4 text-right space-x-2">
                        <Link
                          to={`/vulnerabilities?assessment_id=${ass.id}`}
                          className="px-2.5 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-cyan-400 font-medium text-xs border border-slate-700 transition-colors inline-flex items-center space-x-1"
                        >
                          <span>Findings ({ass.findings_count})</span>
                          <ArrowRight className="w-3 h-3 ml-1" />
                        </Link>
                        <button
                          onClick={() => api.downloadPdfReport(ass.id)}
                          className="p-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-cyan-400 border border-slate-700 transition-colors inline-flex items-center"
                          title="Download PDF Report"
                        >
                          <FileText className="w-3.5 h-3.5" />
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Execute Assessment Modal */}
      {showRunModal && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="cyber-card bg-[#0e1628] border border-slate-700 rounded-xl max-w-lg w-full p-6 shadow-2xl">
            <div className="flex justify-between items-center pb-4 border-b border-slate-800">
              <h3 className="font-bold text-base text-slate-100 flex items-center">
                <PlayCircle className="w-4 h-4 text-cyan-400 mr-2" />
                Launch Automated Security Assessment
              </h3>
              <button onClick={() => setShowRunModal(false)} className="text-slate-400 hover:text-slate-200">
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleRunAssessment} className="space-y-4 mt-4 text-xs">
              <div>
                <label className="block font-medium text-slate-300 mb-1">Target Asset</label>
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
                <p className="text-[11px] text-slate-400 mt-1 font-mono">
                  Assessment will parse the latest package manifest, match known CVEs, and score risk.
                </p>
              </div>

              <div>
                <label className="block font-medium text-slate-300 mb-1">Assessment Title</label>
                <input
                  type="text"
                  value={title}
                  onChange={(e) => setTitle(e.target.value)}
                  placeholder="e.g. Q4 Infrastructure Vulnerability Scan"
                  className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-100 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div>
                <label className="block font-medium text-slate-300 mb-1">Scope & Operator Notes</label>
                <textarea
                  rows={3}
                  value={notes}
                  onChange={(e) => setNotes(e.target.value)}
                  placeholder="Add scope details, compliance framework reference, or testing rationale..."
                  className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-100 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="flex justify-end space-x-3 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowRunModal(false)}
                  className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={runLoading}
                  className="px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold disabled:opacity-50 flex items-center space-x-1.5"
                >
                  {runLoading ? (
                    <>
                      <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                      <span>Scanning & Evaluating...</span>
                    </>
                  ) : (
                    <>
                      <PlayCircle className="w-3.5 h-3.5" />
                      <span>Start Assessment</span>
                    </>
                  )}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
