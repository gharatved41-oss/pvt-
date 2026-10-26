import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import {
  Wrench, CheckCircle2, XCircle, ArrowRight, RefreshCw,
  Cpu, ExternalLink, ShieldCheck, AlertCircle, X, Terminal
} from 'lucide-react';
import { api } from '../services/api';
import { RemediationRecommendation, DigitalTwin } from '../types';
import { StatusBadge } from '../components/Badges';

export const RemediationPage: React.FC = () => {
  const [recommendations, setRecommendations] = useState<RemediationRecommendation[]>([]);
  const [twins, setTwins] = useState<DigitalTwin[]>([]);
  const [loading, setLoading] = useState(true);

  // Approval modal state
  const [activeRec, setActiveRec] = useState<RemediationRecommendation | null>(null);
  const [justification, setJustification] = useState('Approved for non-destructive sandbox verification inside digital twin.');
  const [approvalAction, setApprovalAction] = useState<'approved' | 'rejected'>('approved');

  // Apply in twin state
  const [selectedTwinId, setSelectedTwinId] = useState('');
  const [applyLoading, setApplyLoading] = useState(false);
  const [applyMsg, setApplyMsg] = useState('');

  const fetchData = async () => {
    setLoading(true);
    try {
      const [recsData, twinsData] = await Promise.all([
        api.getRemediations(),
        api.getTwins()
      ]);
      setRecommendations(recsData);
      setTwins(twinsData);
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

  const handleReviewSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!activeRec) return;

    try {
      await api.reviewRemediation(activeRec.id, approvalAction, justification);
      setActiveRec(null);
      fetchData();
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to submit review');
    }
  };

  const handleApplyInTwin = async (recId: string) => {
    if (!selectedTwinId) {
      alert('Please select an active Digital Twin replica.');
      return;
    }

    setApplyLoading(true);
    setApplyMsg('');
    try {
      const res = await api.applyRemediationInTwin(recId, selectedTwinId);
      setApplyMsg(`Remediation successfully applied in twin sandbox! Component upgraded.`);
      fetchData();
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Application failed');
    } finally {
      setApplyLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-slate-100 flex items-center">
            AI-Assisted Remediation & Approval Workflow
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Vendor-aligned patch recommendations requiring explicit human review before application in digital twins
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

      {/* Safety Policy Alert */}
      <div className="p-4 rounded-xl bg-purple-950/40 border border-purple-800/40 flex items-start space-x-3">
        <ShieldCheck className="w-5 h-5 text-purple-400 flex-shrink-0 mt-0.5" />
        <div className="text-xs text-slate-300">
          <span className="font-bold text-purple-300">Human-In-The-Loop Governance:</span> Autonomous direct modifications to live production assets are strictly prohibited.
          Patches must be reviewed by an authorized analyst and applied exclusively inside the designated digital twin replica for before-and-after retest verification.
        </div>
      </div>

      {applyMsg && (
        <div className="p-3 rounded-lg bg-emerald-950/60 border border-emerald-800 text-emerald-300 text-xs font-mono flex items-center justify-between">
          <span>{applyMsg}</span>
          <Link to="/retesting" className="text-cyan-400 font-bold hover:underline flex items-center ml-2">
            <span>Proceed to Retest Verification</span>
            <ArrowRight className="w-3 h-3 ml-1" />
          </Link>
        </div>
      )}

      {/* Recommendations Cards List */}
      <div className="space-y-4">
        {loading ? (
          <div className="py-16 text-center text-slate-500 font-mono">
            <RefreshCw className="w-6 h-6 mx-auto animate-spin text-cyan-400 mb-2" />
            Loading remediation advisories...
          </div>
        ) : recommendations.length === 0 ? (
          <div className="cyber-card p-12 bg-[#0c1222] border border-slate-800 rounded-xl text-center text-slate-500 font-mono">
            No remediation recommendations pending. Execute an assessment to generate patch advisories.
          </div>
        ) : (
          recommendations.map((rec) => (
            <div key={rec.id} className="cyber-card p-6 bg-[#0c1222] border border-slate-800 rounded-xl shadow-xl space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-3">
                <div>
                  <div className="flex items-center space-x-2">
                    <span className="text-xs font-mono font-bold text-cyan-400 uppercase tracking-wider">{rec.action_type}</span>
                    <StatusBadge status={rec.status} />
                  </div>
                  <h3 className="text-base font-bold text-slate-100 mt-1">{rec.title}</h3>
                  <p className="text-xs text-slate-300 mt-1">{rec.description}</p>
                </div>

                {/* Status-specific action controls */}
                <div className="flex items-center space-x-2 flex-shrink-0">
                  {rec.status === 'recommended' && (
                    <button
                      onClick={() => {
                        setActiveRec(rec);
                        setApprovalAction('approved');
                      }}
                      className="px-3.5 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs flex items-center space-x-1.5 transition-all shadow-md shadow-cyan-500/20"
                    >
                      <span>Review & Approve</span>
                      <ArrowRight className="w-3.5 h-3.5" />
                    </button>
                  )}

                  {rec.status === 'approved' && (
                    <div className="flex items-center space-x-2">
                      <select
                        value={selectedTwinId}
                        onChange={(e) => setSelectedTwinId(e.target.value)}
                        className="px-2.5 py-1.5 bg-slate-900 border border-slate-700 rounded-lg text-xs text-slate-200 font-sans"
                      >
                        {twins.map((t) => (
                          <option key={t.id} value={t.id}>
                            Apply in: {t.name}
                          </option>
                        ))}
                      </select>
                      <button
                        onClick={() => handleApplyInTwin(rec.id)}
                        disabled={applyLoading}
                        className="px-3.5 py-2 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-xs flex items-center space-x-1.5 transition-all shadow-md shadow-emerald-500/20 disabled:opacity-50"
                      >
                        <Cpu className="w-3.5 h-3.5" />
                        <span>Apply in Twin</span>
                      </button>
                    </div>
                  )}

                  {rec.status === 'applied_in_twin' && (
                    <Link
                      to="/retesting"
                      className="px-3.5 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-bold text-xs flex items-center space-x-1.5 transition-all shadow-md shadow-blue-600/20"
                    >
                      <span>Verify in Retest Lab</span>
                      <ArrowRight className="w-3.5 h-3.5" />
                    </Link>
                  )}

                  {rec.status === 'resolved' && (
                    <span className="text-xs font-mono font-bold text-emerald-400 flex items-center">
                      <CheckCircle2 className="w-4 h-4 mr-1" />
                      VERIFIED RESOLVED
                    </span>
                  )}
                </div>
              </div>

              {/* Command Preview */}
              <div className="p-3 bg-black/60 rounded-lg border border-slate-800 font-mono text-xs text-slate-300">
                <span className="text-[10px] text-slate-500 uppercase tracking-wider block mb-1">Execution Command Preview (Sandbox Enforced)</span>
                <code>{rec.command_preview}</code>
              </div>

              {/* Meta details */}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs font-mono text-slate-400 pt-2 border-t border-slate-800/80">
                <div>
                  <span className="block text-[10px] uppercase text-slate-500">Prerequisites</span>
                  <span className="text-slate-300">{rec.prerequisites?.join(', ') || 'Standard root in twin'}</span>
                </div>
                <div>
                  <span className="block text-[10px] uppercase text-slate-500">Compatibility Impact</span>
                  <span className="text-slate-300">{rec.compatibility_concerns || 'Low impact'}</span>
                </div>
                <div>
                  <span className="block text-[10px] uppercase text-slate-500">Vendor Advisory</span>
                  {rec.vendor_advisory_url ? (
                    <a href={rec.vendor_advisory_url} target="_blank" rel="noreferrer" className="text-cyan-400 hover:underline flex items-center">
                      <ExternalLink className="w-3 h-3 mr-1" />
                      <span>Security Advisory</span>
                    </a>
                  ) : (
                    <span className="text-slate-500">Included in patch bulletin</span>
                  )}
                </div>
              </div>
            </div>
          ))
        )}
      </div>

      {/* Human Approval Review Modal */}
      {activeRec && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="cyber-card bg-[#0e1628] border border-slate-700 rounded-xl max-w-lg w-full p-6 shadow-2xl">
            <div className="flex justify-between items-center pb-4 border-b border-slate-800">
              <h3 className="font-bold text-base text-slate-100 flex items-center">
                <ShieldCheck className="w-4 h-4 text-cyan-400 mr-2" />
                Human-in-the-Loop Remediation Sign-Off
              </h3>
              <button onClick={() => setActiveRec(null)} className="text-slate-400 hover:text-slate-200">
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleReviewSubmit} className="space-y-4 mt-4 text-xs">
              <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 space-y-1">
                <span className="text-[10px] uppercase font-mono text-cyan-400">Target Change</span>
                <p className="font-bold text-slate-200">{activeRec.title}</p>
                <code className="text-slate-400 text-[11px] block mt-1 font-mono">{activeRec.command_preview}</code>
              </div>

              <div>
                <label className="block font-medium text-slate-300 mb-1">Approval Decision</label>
                <div className="grid grid-cols-2 gap-3">
                  <button
                    type="button"
                    onClick={() => setApprovalAction('approved')}
                    className={`py-2 px-3 rounded-lg font-bold border transition-all ${
                      approvalAction === 'approved'
                        ? 'bg-emerald-950/80 border-emerald-500 text-emerald-400 shadow-sm shadow-emerald-500/20'
                        : 'bg-slate-900 border-slate-700 text-slate-400'
                    }`}
                  >
                    Approve for Sandbox
                  </button>
                  <button
                    type="button"
                    onClick={() => setApprovalAction('rejected')}
                    className={`py-2 px-3 rounded-lg font-bold border transition-all ${
                      approvalAction === 'rejected'
                        ? 'bg-rose-950/80 border-rose-500 text-rose-400 shadow-sm shadow-rose-500/20'
                        : 'bg-slate-900 border-slate-700 text-slate-400'
                    }`}
                  >
                    Reject Change
                  </button>
                </div>
              </div>

              <div>
                <label className="block font-medium text-slate-300 mb-1">Justification / Audit Reason</label>
                <textarea
                  rows={3}
                  required
                  value={justification}
                  onChange={(e) => setJustification(e.target.value)}
                  placeholder="Record justification for compliance audit trail..."
                  className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-100 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="flex justify-end space-x-3 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setActiveRec(null)}
                  className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold"
                >
                  Commit Review Decision
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
