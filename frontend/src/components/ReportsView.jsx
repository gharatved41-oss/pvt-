import React, { useState, useEffect } from 'react';
import { FileText, Download, CheckCircle2, Shield, Printer, ExternalLink, RefreshCw } from 'lucide-react';
import { API_BASE } from '../config/api';

export default function ReportsView() {
  const [reportsList, setReportsList] = useState([]);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    fetchReports();
  }, []);

  const fetchReports = async () => {
    setIsLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/v1/history?limit=25`);
      if (res.ok) {
        const data = await res.json();
        setReportsList(data.items || []);
      }
    } catch (e) {
      console.warn('Failed to fetch reports list:', e);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="space-y-6 max-w-6xl mx-auto pb-12">
      
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-[#0B1F44]">
            Executive Security Reports &amp; Compliance Audits
          </h1>
          <p className="text-sm text-slate-500 mt-1">
            Export formal cybersecurity assessment reports validated by the VulnTwin AI Risk Engine.
          </p>
        </div>

        <button
          onClick={fetchReports}
          disabled={isLoading}
          className="px-3.5 py-2 bg-white border border-[#E2E8F0] hover:bg-slate-50 text-slate-700 font-semibold text-xs rounded-lg transition-colors flex items-center gap-1.5 shadow-sm"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
          <span>Refresh Reports</span>
        </button>
      </div>

      {/* Attestation Banner */}
      <div className="bg-white border border-[#E2E8F0] rounded-xl p-5 shadow-sm space-y-2">
        <div className="flex items-center gap-2 text-xs font-bold text-[#2563EB] uppercase tracking-wider">
          <Shield className="w-4 h-4 text-[#2563EB]" />
          <span>Security Attestation Guarantee</span>
        </div>
        <p className="text-sm text-slate-600 leading-relaxed font-sans">
          Every report issued by VulnTwin AI is grounded in verifiable evidence. Zero untrusted code is executed on live host or production environments. Exploitation hypotheses are tested exclusively against controlled Digital Twin representations.
        </p>
      </div>

      {/* Reports Data Table */}
      <div className="bg-white border border-[#E2E8F0] rounded-xl shadow-sm overflow-hidden">
        <div className="px-6 py-4 border-b border-[#E2E8F0] flex items-center justify-between">
          <h3 className="text-sm font-bold text-[#0B1F44]">Generated Compliance Reports</h3>
          <span className="text-xs text-slate-500">{reportsList.length} Reports Available</span>
        </div>

        <div className="divide-y divide-[#E2E8F0] text-xs">
          {reportsList.length > 0 ? (
            reportsList.map((rep) => (
              <div key={rep.analysis_id} className="p-5 hover:bg-slate-50/80 transition-colors flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-[10px] text-slate-500 font-bold px-1.5 py-0.5 rounded bg-slate-100 border border-slate-200">
                      {rep.analysis_id}
                    </span>
                    <span className="font-bold text-slate-900 text-sm">
                      Security Verification Audit: {rep.domain || rep.submitted_url}
                    </span>
                  </div>
                  <div className="font-mono text-[11px] text-slate-500">
                    Target: {rep.submitted_url}
                  </div>
                  <div className="text-[11px] text-slate-400">
                    Generated: {new Date(rep.created_at).toLocaleString()} • Verdict: <strong className={rep.risk_score >= 75 ? 'text-rose-600' : rep.risk_score >= 30 ? 'text-amber-600' : 'text-emerald-600'}>{rep.verdict} ({rep.risk_score}/100)</strong>
                  </div>
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  <a
                    href={`${API_BASE}/api/v1/analysis/${rep.analysis_id}/export/markdown`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="px-4 py-2 bg-[#2563EB] hover:bg-blue-700 text-white font-semibold text-xs rounded-lg transition-colors flex items-center gap-1.5 shadow-sm"
                  >
                    <Download className="w-3.5 h-3.5" />
                    <span>Download Audit (.md)</span>
                  </a>
                </div>

              </div>
            ))
          ) : (
            <div className="p-12 text-center text-slate-400">
              {isLoading ? 'Loading compliance reports from database...' : 'No reports generated yet. Run an analysis from the Scanner to generate audits.'}
            </div>
          )}
        </div>
      </div>

    </div>
  );
}
