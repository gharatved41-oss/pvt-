import React, { useState, useEffect } from 'react';
import {
  FileText, Download, RefreshCw, Calendar, Server,
  ShieldCheck, AlertTriangle, ArrowRight
} from 'lucide-react';
import { api } from '../services/api';
import { Assessment, Asset } from '../types';

export const ReportsPage: React.FC = () => {
  const [assessments, setAssessments] = useState<Assessment[]>([]);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchData = async () => {
    setLoading(true);
    try {
      const [assData, assetData] = await Promise.all([
        api.getAssessments(),
        api.getAssets()
      ]);
      setAssessments(assData);
      setAssets(assetData);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-slate-100 flex items-center">
            Security Assessment Reports
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Export executive-ready PDF dossiers and CSV data sheets with full twin validation audit trails
          </p>
        </div>

        <button
          onClick={fetchData}
          className="p-2 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 hover:text-cyan-400 text-xs flex items-center space-x-1.5 transition-colors self-start sm:self-auto"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          <span>Refresh Reports</span>
        </button>
      </div>

      {/* Reports Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {loading ? (
          <div className="col-span-full py-16 text-center text-slate-500 font-mono">
            <RefreshCw className="w-6 h-6 mx-auto animate-spin text-cyan-400 mb-2" />
            Compiling report catalog...
          </div>
        ) : assessments.length === 0 ? (
          <div className="col-span-full cyber-card p-12 bg-[#0c1222] border border-slate-800 rounded-xl text-center text-slate-500 font-mono">
            No assessment reports generated yet. Execute an assessment from the Assessments tab.
          </div>
        ) : (
          assessments.map((ass) => {
            const asset = assets.find((a) => a.id === ass.asset_id);
            return (
              <div key={ass.id} className="cyber-card p-5 bg-[#0c1222] border border-slate-800 rounded-xl shadow-xl flex flex-col justify-between space-y-4">
                <div>
                  <div className="flex justify-between items-start">
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950/80 border border-cyan-800 text-cyan-400 font-bold">
                      VT-{ass.id.slice(0, 8).toUpperCase()}
                    </span>
                    <span className="text-[10px] font-mono text-slate-400 flex items-center">
                      <Calendar className="w-3 h-3 mr-1" />
                      {new Date(ass.started_at).toLocaleDateString()}
                    </span>
                  </div>

                  <h3 className="font-bold text-sm text-slate-100 mt-2.5 truncate">{ass.title}</h3>
                  <p className="text-xs text-slate-400 mt-0.5 font-mono">Host: {asset?.name || 'Authorized Target'}</p>

                  <div className="mt-4 p-3 rounded-lg bg-slate-900 border border-slate-800 space-y-1.5 text-xs font-mono">
                    <div className="flex justify-between">
                      <span className="text-slate-400">Total Findings:</span>
                      <span className="font-bold text-cyan-400">{ass.findings_count} CVEs</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">Critical / High:</span>
                      <span className="font-bold text-rose-400">{ass.critical_count} / {ass.high_count}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">Average Risk:</span>
                      <span className="font-bold text-amber-400">{ass.average_risk_score.toFixed(1)} / 100</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">Sandbox Verification:</span>
                      <span className="text-emerald-400">Isolated Lab Tested</span>
                    </div>
                  </div>
                </div>

                <div className="pt-3 border-t border-slate-800/80 grid grid-cols-2 gap-2 text-xs">
                  <button
                    onClick={() => api.downloadPdfReport(ass.id)}
                    className="py-2 px-3 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-bold flex items-center justify-center space-x-1.5 shadow-md shadow-cyan-600/20 transition-all"
                  >
                    <Download className="w-3.5 h-3.5" />
                    <span>PDF Dossier</span>
                  </button>

                  <button
                    onClick={() => api.downloadCsvReport(ass.id)}
                    className="py-2 px-3 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 font-medium flex items-center justify-center space-x-1.5 border border-slate-700 transition-colors"
                  >
                    <FileText className="w-3.5 h-3.5 text-cyan-400" />
                    <span>CSV Export</span>
                  </button>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
