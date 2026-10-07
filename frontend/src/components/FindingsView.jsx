import React, { useState, useEffect } from 'react';
import { AlertTriangle, Filter, Search, ArrowRight, ShieldAlert, Cpu, ExternalLink, RefreshCw } from 'lucide-react';
import { API_BASE } from '../config/api';

export default function FindingsView({ onNavigateToTwin, activeAnalysis }) {
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [searchTerm, setSearchTerm] = useState('');
  const [findingsData, setFindingsData] = useState([]);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    fetchFindings();
  }, [activeAnalysis]);

  const fetchFindings = async () => {
    setIsLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/v1/findings`);
      if (res.ok) {
        const data = await res.json();
        
        // If active analysis exists and has evidence items, prepend them
        if (activeAnalysis?.evidence && activeAnalysis.evidence.length > 0) {
          const activeFindings = activeAnalysis.evidence.map((ev, i) => ({
            id: `ACTIVE-${i + 1}`,
            title: ev.title,
            cve: `CWE-${(ev.category || 'VULN').replace('_', '-').toUpperCase()}`,
            target: activeAnalysis.submitted_url || activeAnalysis.domain,
            component: (ev.category || 'Endpoint').replace('_', ' ').toUpperCase(),
            risk: ev.impact_score > 0 ? ev.impact_score : activeAnalysis.risk_score,
            severity: (ev.severity || 'MEDIUM').toUpperCase(),
            confidence: `${Math.round((activeAnalysis.confidence || 0.9) * 100)}%`,
            exploitability: activeAnalysis.exploitability?.level ? `${activeAnalysis.exploitability.level.toUpperCase()}` : 'High',
            status: 'VERIFIED_ON_TWIN',
            recommendation: ev.description,
            isCurrent: true
          }));

          // Merge without exact duplicates
          const merged = [...activeFindings, ...data.filter(d => d.analysis_id !== activeAnalysis.analysis_id)];
          setFindingsData(merged);
        } else {
          setFindingsData(data);
        }
      }
    } catch (e) {
      console.warn('Findings fetch error:', e);
    } finally {
      setIsLoading(false);
    }
  };

  const filtered = findingsData.filter((item) => {
    const matchesSev = severityFilter === 'ALL' || item.severity === severityFilter;
    const matchesSearch = searchTerm === '' || 
      item.title?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      item.target?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      item.component?.toLowerCase().includes(searchTerm.toLowerCase());
    return matchesSev && matchesSearch;
  });

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12">
      
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-[#0B1F44]">
            Security Findings Inventory
          </h1>
          <p className="text-sm text-slate-500 mt-1">
            Verified vulnerabilities and telemetry signals extracted from recorded database analyses.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={fetchFindings}
            disabled={isLoading}
            className="p-2 border border-[#E2E8F0] hover:bg-slate-50 text-slate-600 rounded-lg transition-colors shadow-sm"
            title="Refresh Findings"
          >
            <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
          </button>
          <button
            onClick={() => onNavigateToTwin && onNavigateToTwin()}
            className="px-4 py-2 bg-[#2563EB] hover:bg-blue-700 text-white font-semibold text-xs rounded-lg transition-colors shadow-sm flex items-center gap-1.5"
          >
            <Cpu className="w-3.5 h-3.5" />
            <span>Open Digital Twin Workspace</span>
          </button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-white border border-[#E2E8F0] rounded-xl p-4 shadow-sm flex flex-col sm:flex-row items-center justify-between gap-4">
        
        {/* Severity Chips */}
        <div className="flex items-center gap-1.5 flex-wrap">
          <span className="text-xs font-semibold text-slate-400 mr-1">Filter:</span>
          {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map((sev) => (
            <button
              key={sev}
              onClick={() => setSeverityFilter(sev)}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors ${
                severityFilter === sev
                  ? 'bg-[#2563EB] text-white shadow-sm'
                  : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
              }`}
            >
              {sev.charAt(0) + sev.slice(1).toLowerCase()}
            </button>
          ))}
        </div>

        {/* Search Input */}
        <div className="w-full sm:w-64 relative">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search findings, CVEs, targets..."
            className="w-full pl-9 pr-3 py-1.5 bg-slate-50 border border-[#E2E8F0] rounded-lg text-xs text-slate-800 placeholder-slate-400 focus:outline-none focus:ring-1 focus:ring-[#2563EB]"
          />
        </div>

      </div>

      {/* Professional Data Table */}
      <div className="bg-white border border-[#E2E8F0] rounded-xl shadow-sm overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="bg-[#F8FAFC] border-b border-[#E2E8F0] text-slate-600 font-semibold uppercase text-[11px]">
                <th className="py-3 px-6">ID / Finding Title</th>
                <th className="py-3 px-4">Component</th>
                <th className="py-3 px-4">Risk</th>
                <th className="py-3 px-4">Confidence</th>
                <th className="py-3 px-4">Exploitability</th>
                <th className="py-3 px-4">Twin Status</th>
                <th className="py-3 px-6 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#E2E8F0] text-slate-700">
              {filtered.length > 0 ? (
                filtered.map((item) => (
                  <tr key={item.id} className="hover:bg-slate-50/80 transition-colors">
                    
                    {/* Title & Target */}
                    <td className="py-4 px-6 max-w-sm">
                      <div className="flex items-center gap-2">
                        <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-slate-100 text-slate-600 font-semibold border border-slate-200">
                          {item.cve}
                        </span>
                        <span className="font-semibold text-slate-900 truncate">
                          {item.title}
                        </span>
                        {item.isCurrent && (
                          <span className="text-[9px] bg-blue-100 text-blue-700 px-1.5 py-0.5 rounded font-bold uppercase">
                            Active Scan
                          </span>
                        )}
                      </div>
                      <div className="text-[11px] font-mono text-slate-400 truncate mt-1">
                        Target: {item.target}
                      </div>
                    </td>

                    {/* Component */}
                    <td className="py-4 px-4 text-slate-600 font-medium whitespace-nowrap">
                      {item.component}
                    </td>

                    {/* Risk */}
                    <td className="py-4 px-4 font-bold whitespace-nowrap">
                      <span className={item.risk >= 80 ? 'text-[#EF4444]' : item.risk >= 40 ? 'text-[#F59E0B]' : 'text-[#10B981]'}>
                        {item.risk}/100
                      </span>
                    </td>

                    {/* Confidence */}
                    <td className="py-4 px-4 text-slate-500 font-medium whitespace-nowrap">
                      {item.confidence}
                    </td>

                    {/* Exploitability */}
                    <td className="py-4 px-4 font-medium whitespace-nowrap">
                      <span className={item.risk >= 70 ? 'text-[#EF4444] font-semibold' : item.risk >= 30 ? 'text-[#F59E0B] font-semibold' : 'text-slate-500'}>
                        {item.exploitability}
                      </span>
                    </td>

                    {/* Twin Status */}
                    <td className="py-4 px-4 whitespace-nowrap">
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold bg-blue-50 text-[#2563EB] border border-blue-200">
                        Verified on Twin
                      </span>
                    </td>

                    {/* Action Button */}
                    <td className="py-4 px-6 text-right whitespace-nowrap">
                      <button
                        onClick={() => onNavigateToTwin && onNavigateToTwin({ submitted_url: item.target, risk_score: item.risk, verdict: item.risk >= 75 ? 'MALICIOUS' : 'SUSPICIOUS' })}
                        className="px-3 py-1.5 bg-white border border-[#E2E8F0] hover:bg-[#EFF6FF] hover:border-[#BFDBFE] text-[#2563EB] font-semibold text-xs rounded-lg transition-colors"
                      >
                        Test on Twin →
                      </button>
                    </td>

                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan="7" className="py-12 text-center text-slate-400">
                    {isLoading ? 'Loading findings from database...' : 'No findings matched the current criteria. Run a security analysis to populate.'}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

    </div>
  );
}
