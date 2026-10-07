import React, { useState, useEffect } from 'react';
import { History, Search, Filter, ArrowRight, RefreshCw, Eye, ShieldAlert, CheckCircle2 } from 'lucide-react';
import { API_BASE } from '../config/api';

export default function HistoryView({ onSelectAnalysis }) {
  const [history, setHistory] = useState([]);
  const [total, setTotal] = useState(0);
  const [isLoading, setIsLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [verdictFilter, setVerdictFilter] = useState('ALL');

  useEffect(() => {
    fetchHistory();
  }, [verdictFilter, search]);

  const fetchHistory = async () => {
    setIsLoading(true);
    try {
      const params = new URLSearchParams({
        page: '1',
        limit: '50',
      });
      if (verdictFilter !== 'ALL') params.append('verdict', verdictFilter);
      if (search.trim()) params.append('search', search.trim());

      const res = await fetch(`${API_BASE}/api/v1/history?${params.toString()}`);
      if (res.ok) {
        const data = await res.json();
        setHistory(data.items || []);
        setTotal(data.total || 0);
      }
    } catch (e) {
      console.warn('Failed to load history:', e);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12">
      
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-[#0B1F44]">
            Security Memory Vault
          </h1>
          <p className="text-sm text-slate-500 mt-1">
            Historical intelligence graph tracking how threat indicators evolve across repeated evaluations.
          </p>
        </div>

        <button
          onClick={fetchHistory}
          className="px-3.5 py-2 bg-white border border-[#E2E8F0] hover:bg-slate-50 text-slate-700 font-semibold text-xs rounded-lg transition-colors flex items-center gap-1.5 shadow-2xs"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
          <span>Refresh Memory</span>
        </button>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-white border border-[#E2E8F0] rounded-xl p-4 shadow-sm flex flex-col sm:flex-row items-center justify-between gap-4">
        
        {/* Severity Filter Chips */}
        <div className="flex items-center gap-1.5 flex-wrap">
          <span className="text-xs font-semibold text-slate-400 mr-1">Filter:</span>
          {['ALL', 'MALICIOUS', 'SUSPICIOUS', 'SAFE'].map((verdict) => (
            <button
              key={verdict}
              onClick={() => setVerdictFilter(verdict)}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors ${
                verdictFilter === verdict
                  ? 'bg-[#2563EB] text-white shadow-sm'
                  : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
              }`}
            >
              {verdict === 'ALL' ? 'All Records' : verdict.charAt(0) + verdict.slice(1).toLowerCase()}
            </button>
          ))}
        </div>

        {/* Search Bar */}
        <div className="w-full sm:w-64 relative">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search URL, domain, or ID..."
            className="w-full pl-9 pr-3 py-1.5 bg-slate-50 border border-[#E2E8F0] rounded-lg text-xs text-slate-800 placeholder-slate-400 focus:outline-none focus:ring-1 focus:ring-[#2563EB]"
          />
        </div>

      </div>

      {/* History Data Table */}
      <div className="bg-white border border-[#E2E8F0] rounded-xl shadow-sm overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="bg-[#F8FAFC] border-b border-[#E2E8F0] text-slate-600 font-semibold uppercase text-[11px]">
                <th className="py-3 px-6">Analysis ID / Target</th>
                <th className="py-3 px-4">Risk Score</th>
                <th className="py-3 px-4">Verdict</th>
                <th className="py-3 px-4">Confidence</th>
                <th className="py-3 px-4">Recorded Date</th>
                <th className="py-3 px-6 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#E2E8F0] text-slate-700">
              {history.length > 0 ? (
                history.map((record) => (
                  <tr key={record.analysis_id} className="hover:bg-slate-50/80 transition-colors">
                    
                    <td className="py-4 px-6 max-w-sm">
                      <div className="font-mono text-[10px] text-slate-500 font-semibold">
                        {record.analysis_id}
                      </div>
                      <div className="font-medium text-slate-900 truncate font-mono text-[11px] mt-0.5">
                        {record.submitted_url}
                      </div>
                    </td>

                    <td className="py-4 px-4 font-bold whitespace-nowrap">
                      <span className={record.risk_score >= 70 ? 'text-[#EF4444]' : record.risk_score >= 40 ? 'text-[#F59E0B]' : 'text-[#10B981]'}>
                        {record.risk_score}/100
                      </span>
                    </td>

                    <td className="py-4 px-4 whitespace-nowrap">
                      <span className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold ${
                        record.verdict === 'MALICIOUS'
                          ? 'bg-rose-50 text-rose-700 border border-rose-200'
                          : record.verdict === 'SUSPICIOUS'
                          ? 'bg-amber-50 text-amber-700 border border-amber-200'
                          : 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                      }`}>
                        {record.verdict === 'MALICIOUS' ? '● High Risk' : record.verdict === 'SUSPICIOUS' ? '● Suspicious' : '● Safe'}
                      </span>
                    </td>

                    <td className="py-4 px-4 text-slate-500 whitespace-nowrap">
                      {Math.round((record.confidence || 0.95) * 100)}%
                    </td>

                    <td className="py-4 px-4 text-slate-500 whitespace-nowrap">
                      {new Date(record.created_at).toLocaleString([], { dateStyle: 'short', timeStyle: 'short' })}
                    </td>

                    <td className="py-4 px-6 text-right whitespace-nowrap">
                      <button
                        onClick={() => onSelectAnalysis && onSelectAnalysis(record)}
                        className="px-3 py-1.5 bg-white border border-[#E2E8F0] hover:bg-[#EFF6FF] text-[#2563EB] font-semibold text-xs rounded-lg transition-colors"
                      >
                        Inspect →
                      </button>
                    </td>

                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan="6" className="py-12 text-center text-slate-400">
                    No historical analyses found matching current filters.
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
