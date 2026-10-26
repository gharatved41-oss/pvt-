import React, { useState, useEffect } from 'react';
import { useSearchParams, Link } from 'react-router-dom';
import {
  ShieldAlert, Search, Filter, RefreshCw, ExternalLink,
  Cpu, Wrench, X, Info, CheckCircle2, ChevronRight, BrainCircuit
} from 'lucide-react';
import { api } from '../services/api';
import { VulnerabilityFinding, EvidenceRecord } from '../types';
import { SeverityBadge, StatusBadge, RiskGauge } from '../components/Badges';

export const VulnerabilitiesPage: React.FC = () => {
  const [searchParams] = useSearchParams();
  const assessmentIdParam = searchParams.get('assessment_id') || '';

  const [findings, setFindings] = useState<VulnerabilityFinding[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState('');
  const [selectedStatus, setSelectedStatus] = useState('');
  const [activeFinding, setActiveFinding] = useState<VulnerabilityFinding | null>(null);
  const [evidenceList, setEvidenceList] = useState<EvidenceRecord[]>([]);

  const fetchFindings = async () => {
    setLoading(true);
    try {
      const data = await api.getVulnerabilities({
        assessment_id: assessmentIdParam || undefined,
        severity: selectedSeverity || undefined,
        detection_status: selectedStatus || undefined,
        search: search || undefined
      });
      setFindings(data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchFindings();
  }, [assessmentIdParam, selectedSeverity, selectedStatus]);

  const handleOpenDetail = async (finding: VulnerabilityFinding) => {
    setActiveFinding(finding);
    try {
      const ev = await api.getFindingEvidence(finding.id);
      setEvidenceList(ev);
    } catch {
      setEvidenceList([]);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-slate-100 flex items-center">
            Vulnerability Intelligence & Findings
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Prioritized by GradientBoosting ML risk model with evidence-backed package matching
          </p>
        </div>

        <button
          onClick={fetchFindings}
          className="p-2 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 hover:text-cyan-400 text-xs flex items-center space-x-1.5 transition-colors self-start sm:self-auto"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          <span>Refresh</span>
        </button>
      </div>

      {/* Filter and Search Bar */}
      <div className="cyber-card p-4 bg-[#0c1222] border border-slate-800 rounded-xl grid grid-cols-1 sm:grid-cols-4 gap-3">
        {/* Search */}
        <div className="sm:col-span-2 relative">
          <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
            <Search className="w-4 h-4" />
          </div>
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && fetchFindings()}
            placeholder="Search CVE ID, component (openssh, curl, log4j), or keyword..."
            className="w-full pl-9 pr-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-xs text-slate-100 focus:outline-none focus:border-cyan-500"
          />
        </div>

        {/* Severity Filter */}
        <div>
          <select
            value={selectedSeverity}
            onChange={(e) => setSelectedSeverity(e.target.value)}
            className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-xs text-slate-100 focus:outline-none focus:border-cyan-500"
          >
            <option value="">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>

        {/* Status Filter */}
        <div>
          <select
            value={selectedStatus}
            onChange={(e) => setSelectedStatus(e.target.value)}
            className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-xs text-slate-100 focus:outline-none focus:border-cyan-500"
          >
            <option value="">All Verification States</option>
            <option value="detected">Detected</option>
            <option value="confirmed">Confirmed in Twin</option>
            <option value="fixed">Fixed & Verified</option>
            <option value="suspected">Suspected / Retest Pending</option>
            <option value="unresolved">Unresolved</option>
            <option value="inconclusive">Inconclusive</option>
          </select>
        </div>
      </div>

      {/* Findings Table */}
      <div className="cyber-card bg-[#0c1222] border border-slate-800 rounded-xl overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#090d19] border-b border-slate-800 text-slate-400 font-mono uppercase tracking-wider text-[11px]">
              <tr>
                <th className="px-5 py-3.5">CVE & Title</th>
                <th className="px-5 py-3.5">Affected Component</th>
                <th className="px-5 py-3.5">CVSS / Severity</th>
                <th className="px-5 py-3.5 w-44">ML Realized Risk</th>
                <th className="px-5 py-3.5">State</th>
                <th className="px-5 py-3.5 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-sans">
              {loading ? (
                <tr>
                  <td colSpan={6} className="px-5 py-12 text-center text-slate-500 font-mono">
                    <RefreshCw className="w-5 h-5 mx-auto animate-spin text-cyan-400 mb-2" />
                    Querying vulnerability repository...
                  </td>
                </tr>
              ) : findings.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-5 py-12 text-center text-slate-500 font-mono">
                    No matching vulnerabilities found.
                  </td>
                </tr>
              ) : (
                findings.map((f) => (
                  <tr key={f.id} className="hover:bg-slate-900/60 transition-colors">
                    <td className="px-5 py-4">
                      <div className="font-mono font-bold text-slate-100 text-sm">{f.cve_id}</div>
                      <div className="text-[11px] text-slate-400 truncate max-w-sm mt-0.5">{f.title}</div>
                    </td>
                    <td className="px-5 py-4">
                      <div className="font-mono text-cyan-300 font-semibold">{f.affected_component}</div>
                      <div className="text-[11px] font-mono text-slate-400">Ver: {f.installed_version}</div>
                    </td>
                    <td className="px-5 py-4">
                      <div className="flex items-center space-x-2">
                        <span className="font-mono font-bold text-slate-200">{f.cvss_v3_score.toFixed(1)}</span>
                        <SeverityBadge severity={f.severity} />
                      </div>
                    </td>
                    <td className="px-5 py-4">
                      <RiskGauge score={f.risk_score} priority={f.recommended_priority} />
                    </td>
                    <td className="px-5 py-4">
                      <StatusBadge status={f.detection_status} />
                    </td>
                    <td className="px-5 py-4 text-right space-x-2">
                      <button
                        onClick={() => handleOpenDetail(f)}
                        className="px-2.5 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-cyan-400 font-medium text-xs border border-slate-700 transition-colors inline-flex items-center space-x-1"
                      >
                        <span>Inspect Risk</span>
                        <ChevronRight className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Finding Deep-Dive & ML Risk Modal */}
      {activeFinding && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="cyber-card bg-[#0e1628] border border-slate-700 rounded-xl max-w-3xl w-full p-6 shadow-2xl max-h-[90vh] overflow-y-auto">
            {/* Top Bar */}
            <div className="flex justify-between items-start pb-4 border-b border-slate-800">
              <div>
                <div className="flex items-center space-x-2">
                  <span className="text-base font-mono font-extrabold text-cyan-400">{activeFinding.cve_id}</span>
                  <SeverityBadge severity={activeFinding.severity} />
                  <StatusBadge status={activeFinding.detection_status} />
                </div>
                <h3 className="text-base font-bold text-slate-100 mt-1">{activeFinding.title}</h3>
              </div>
              <button onClick={() => setActiveFinding(null)} className="text-slate-400 hover:text-slate-200">
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Content Body */}
            <div className="space-y-6 mt-5 text-xs">
              {/* AI/ML Risk Scoring & Explainability Panel */}
              <div className="p-4 rounded-xl bg-gradient-to-br from-slate-900 to-[#10192e] border border-cyan-800/40">
                <div className="flex items-center justify-between mb-3">
                  <span className="font-mono text-cyan-400 text-xs font-bold flex items-center">
                    <BrainCircuit className="w-4 h-4 mr-1.5" />
                    AI/ML RISK PRIORITIZATION & EXPLANATION
                  </span>
                  <span className="font-mono text-slate-400 text-[11px]">
                    Confidence: {(activeFinding.confidence_score * 100).toFixed(0)}%
                  </span>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 mb-3">
                  <div className="p-3 rounded-lg bg-slate-950/80 border border-slate-800">
                    <span className="text-slate-400 block text-[10px] uppercase font-mono">Realized Risk Index</span>
                    <span className="text-xl font-extrabold text-cyan-400 font-mono">
                      {activeFinding.risk_score.toFixed(1)} <span className="text-xs text-slate-500">/ 100</span>
                    </span>
                  </div>
                  <div className="p-3 rounded-lg bg-slate-950/80 border border-slate-800">
                    <span className="text-slate-400 block text-[10px] uppercase font-mono">Intrinsic CVSS v3.1</span>
                    <span className="text-xl font-extrabold text-amber-400 font-mono">
                      {activeFinding.cvss_v3_score.toFixed(1)} <span className="text-xs text-slate-500">Base</span>
                    </span>
                  </div>
                  <div className="p-3 rounded-lg bg-slate-950/80 border border-slate-800">
                    <span className="text-slate-400 block text-[10px] uppercase font-mono">Recommended Action</span>
                    <span className="text-xs font-bold text-slate-200 font-mono mt-1 block">
                      {activeFinding.recommended_priority}
                    </span>
                  </div>
                </div>

                <p className="text-slate-300 leading-relaxed font-sans bg-slate-950/50 p-3 rounded-lg border border-slate-800/80">
                  {activeFinding.risk_explanation}
                </p>

                {/* Contributing factor weights */}
                {activeFinding.contributing_factors && (
                  <div className="mt-3 grid grid-cols-2 sm:grid-cols-3 gap-2 text-[11px] font-mono">
                    {Object.entries(activeFinding.contributing_factors).map(([key, val]: any) => (
                      <div key={key} className="p-2 rounded bg-slate-900 border border-slate-800">
                        <span className="text-slate-400 block text-[10px] truncate">{key.replace(/_/g, ' ').toUpperCase()}</span>
                        <span className="text-slate-200 font-bold">{val.weight || 'Active'}</span>
                        <p className="text-[10px] text-slate-400 truncate mt-0.5">{val.detail}</p>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Component & Version Details */}
              <div className="grid grid-cols-2 gap-4">
                <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                  <span className="text-slate-400 font-mono text-[10px] uppercase block">Installed Component</span>
                  <span className="text-sm font-bold font-mono text-cyan-300">{activeFinding.affected_component}</span>
                  <p className="text-slate-400 mt-1 font-mono">Version: {activeFinding.installed_version}</p>
                </div>
                <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                  <span className="text-slate-400 font-mono text-[10px] uppercase block">Vendor Fixed Release</span>
                  <span className="text-sm font-bold font-mono text-emerald-400">{activeFinding.fixed_version || 'Vendor Patched'}</span>
                  <p className="text-slate-400 mt-1 font-mono">Target Upgrade Threshold</p>
                </div>
              </div>

              {/* Description */}
              <div>
                <h4 className="font-bold text-slate-200 uppercase tracking-wider text-[11px] mb-1 font-mono">Vulnerability Description</h4>
                <p className="text-slate-300 leading-relaxed">{activeFinding.description}</p>
              </div>

              {/* Evidence Records */}
              <div>
                <h4 className="font-bold text-slate-200 uppercase tracking-wider text-[11px] mb-2 font-mono">Collected System Evidence</h4>
                {evidenceList.length === 0 ? (
                  <p className="text-slate-500 font-mono text-[11px]">No granular evidence records recorded.</p>
                ) : (
                  evidenceList.map((ev) => (
                    <div key={ev.id} className="p-3 rounded-lg bg-slate-950 border border-slate-800 mb-2 font-mono text-[11px]">
                      <div className="flex justify-between items-center text-cyan-400 mb-1">
                        <span>{ev.title}</span>
                        <span className="text-slate-500 text-[10px]">{new Date(ev.collected_at).toLocaleTimeString()}</span>
                      </div>
                      <pre className="text-slate-300 bg-slate-900 p-2 rounded overflow-x-auto whitespace-pre-wrap">{ev.raw_evidence}</pre>
                    </div>
                  ))
                )}
              </div>

              {/* External References */}
              {activeFinding.references && activeFinding.references.length > 0 && (
                <div>
                  <h4 className="font-bold text-slate-200 uppercase tracking-wider text-[11px] mb-1 font-mono">Authoritative References</h4>
                  <ul className="space-y-1">
                    {activeFinding.references.map((ref, idx) => (
                      <li key={idx}>
                        <a
                          href={ref}
                          target="_blank"
                          rel="noreferrer"
                          className="text-cyan-400 hover:underline flex items-center font-mono text-[11px]"
                        >
                          <ExternalLink className="w-3 h-3 mr-1" />
                          <span>{ref}</span>
                        </a>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Action Buttons */}
              <div className="flex justify-between items-center pt-4 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setActiveFinding(null)}
                  className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300"
                >
                  Close
                </button>

                <div className="flex space-x-2">
                  <Link
                    to="/validation"
                    className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-bold flex items-center space-x-1.5"
                  >
                    <Cpu className="w-3.5 h-3.5" />
                    <span>Test in Digital Twin</span>
                  </Link>
                  <Link
                    to="/remediation"
                    className="px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold flex items-center space-x-1.5"
                  >
                    <Wrench className="w-3.5 h-3.5" />
                    <span>View Remediation</span>
                  </Link>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
