import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import {
  Server, ShieldAlert, Activity, CheckCircle2, AlertTriangle,
  ArrowUpRight, RefreshCw, Layers, ShieldCheck, PlayCircle
} from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';
import { api } from '../services/api';
import { DashboardMetrics } from '../types';
import { SeverityBadge, StatusBadge } from '../components/Badges';

export const DashboardPage: React.FC = () => {
  const [metrics, setMetrics] = useState<DashboardMetrics | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const fetchMetrics = async () => {
    setLoading(true);
    setError('');
    try {
      const data = await api.getDashboardMetrics();
      setMetrics(data);
    } catch (err: any) {
      setError('Failed to load dashboard metrics from backend database.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchMetrics();
  }, []);

  if (loading && !metrics) {
    return (
      <div className="flex flex-col items-center justify-center h-96 space-y-4">
        <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin" />
        <p className="text-sm font-mono text-slate-400">Querying live security telemetry & database metrics...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-6 rounded-xl bg-rose-950/40 border border-rose-800 text-rose-300">
        <h3 className="font-bold text-base mb-1">Database Connectivity Error</h3>
        <p className="text-xs">{error}</p>
        <button
          onClick={fetchMetrics}
          className="mt-4 px-4 py-1.5 rounded bg-rose-900 hover:bg-rose-800 text-xs font-semibold"
        >
          Retry Query
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Top Header & Actions */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-slate-100 flex items-center">
            Security Intelligence Dashboard
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Real-time telemetry aggregated from authorized assets, vulnerability scans, and digital twin labs
          </p>
        </div>

        <div className="flex items-center space-x-3">
          <button
            onClick={fetchMetrics}
            className="p-2 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 hover:text-cyan-400 text-xs flex items-center space-x-1.5 transition-colors"
            title="Refresh Metrics"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">Refresh</span>
          </button>
          <Link
            to="/assessments"
            className="px-3.5 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs flex items-center space-x-2 transition-all shadow-md shadow-cyan-500/20"
          >
            <PlayCircle className="w-4 h-4" />
            <span>New Assessment</span>
          </Link>
        </div>
      </div>

      {/* Primary KPI Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total Assets */}
        <div className="cyber-card p-5 bg-[#0e1628] border border-slate-800 rounded-xl relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Registered Assets</span>
            <div className="w-8 h-8 rounded-lg bg-blue-950/80 border border-blue-700/50 flex items-center justify-center text-blue-400">
              <Server className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline space-x-2">
            <span className="text-2xl font-extrabold text-slate-100">{metrics?.total_assets || 0}</span>
            <span className="text-[11px] text-cyan-400 font-mono">Managed Hosts</span>
          </div>
          <Link to="/assets" className="mt-3 flex items-center text-[11px] text-slate-400 hover:text-cyan-400 font-mono">
            <span>Manage asset inventory</span>
            <ArrowUpRight className="w-3 h-3 ml-1" />
          </Link>
        </div>

        {/* Total Findings */}
        <div className="cyber-card p-5 bg-[#0e1628] border border-slate-800 rounded-xl relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Detected CVEs</span>
            <div className="w-8 h-8 rounded-lg bg-red-950/80 border border-red-700/50 flex items-center justify-center text-red-400">
              <ShieldAlert className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline space-x-2">
            <span className="text-2xl font-extrabold text-slate-100">{metrics?.total_findings || 0}</span>
            <span className="text-[11px] text-rose-400 font-mono">
              {metrics?.critical_findings || 0} Critical / {metrics?.high_findings || 0} High
            </span>
          </div>
          <Link to="/vulnerabilities" className="mt-3 flex items-center text-[11px] text-slate-400 hover:text-cyan-400 font-mono">
            <span>Inspect findings</span>
            <ArrowUpRight className="w-3 h-3 ml-1" />
          </Link>
        </div>

        {/* Confirmed in Twin */}
        <div className="cyber-card p-5 bg-[#0e1628] border border-slate-800 rounded-xl relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Twin Validated</span>
            <div className="w-8 h-8 rounded-lg bg-emerald-950/80 border border-emerald-700/50 flex items-center justify-center text-emerald-400">
              <CheckCircle2 className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline space-x-2">
            <span className="text-2xl font-extrabold text-slate-100">{metrics?.status_breakdown?.confirmed || 0}</span>
            <span className="text-[11px] text-emerald-400 font-mono">
              {metrics?.status_breakdown?.fixed || 0} Resolved
            </span>
          </div>
          <Link to="/validation" className="mt-3 flex items-center text-[11px] text-slate-400 hover:text-cyan-400 font-mono">
            <span>Validation lab status</span>
            <ArrowUpRight className="w-3 h-3 ml-1" />
          </Link>
        </div>

        {/* Avg Realized Risk */}
        <div className="cyber-card p-5 bg-[#0e1628] border border-slate-800 rounded-xl relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Avg ML Risk Score</span>
            <div className="w-8 h-8 rounded-lg bg-amber-950/80 border border-amber-700/50 flex items-center justify-center text-amber-400">
              <Activity className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline space-x-2">
            <span className="text-2xl font-extrabold text-slate-100">{metrics?.average_risk_score?.toFixed(1) || '0.0'}</span>
            <span className="text-[11px] text-slate-400 font-mono">/ 100 Realized</span>
          </div>
          <div className="mt-3 flex items-center text-[11px] text-cyan-400 font-mono">
            <span>GradientBoosting Ensemble Active</span>
          </div>
        </div>
      </div>

      {/* Visual Analytics Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Severity Distribution Chart */}
        <div className="cyber-card p-5 bg-[#0c1222] border border-slate-800 rounded-xl">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-bold text-slate-200">Vulnerability Severity Distribution</h3>
            <span className="text-[11px] font-mono text-slate-400">CVSS v3.1 Standards</span>
          </div>
          <div className="h-56">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={metrics?.severity_distribution || []}>
                <XAxis dataKey="name" stroke="#64748b" fontSize={11} />
                <YAxis stroke="#64748b" fontSize={11} allowDecimals={false} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b', borderRadius: '8px' }}
                  itemStyle={{ color: '#38bdf8', fontSize: '12px' }}
                />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {(metrics?.severity_distribution || []).map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Verification Status Breakdown */}
        <div className="cyber-card p-5 bg-[#0c1222] border border-slate-800 rounded-xl">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-bold text-slate-200">Twin Verification & Remediation Lifecycle</h3>
            <span className="text-[11px] font-mono text-slate-400">Safe Sandboxing</span>
          </div>
          <div className="h-56 flex items-center justify-center">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={metrics?.status_distribution || []}
                  dataKey="count"
                  nameKey="name"
                  cx="50%"
                  cy="50%"
                  innerRadius={48}
                  outerRadius={75}
                  paddingAngle={4}
                >
                  {(metrics?.status_distribution || []).map((entry, index) => (
                    <Cell key={`status-cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b', borderRadius: '8px' }}
                  itemStyle={{ color: '#38bdf8', fontSize: '12px' }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
          {/* Legend */}
          <div className="flex flex-wrap items-center justify-center gap-3 text-[11px] text-slate-400 font-mono mt-1">
            {(metrics?.status_distribution || []).map((item) => (
              <span key={item.name} className="flex items-center space-x-1.5">
                <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: item.color }} />
                <span>{item.name}: {item.count}</span>
              </span>
            ))}
          </div>
        </div>
      </div>

      {/* Recent Activity Section */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recent Assessments */}
        <div className="cyber-card p-5 bg-[#0c1222] border border-slate-800 rounded-xl">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-bold text-slate-200">Recent Security Assessments</h3>
            <Link to="/assessments" className="text-xs text-cyan-400 hover:underline">View all</Link>
          </div>

          <div className="space-y-3">
            {(metrics?.recent_assessments || []).length === 0 ? (
              <p className="text-xs text-slate-500 py-6 text-center font-mono">No assessments executed yet.</p>
            ) : (
              (metrics?.recent_assessments || []).map((ass: any) => (
                <div key={ass.id} className="p-3 rounded-lg bg-slate-900/80 border border-slate-800 flex items-center justify-between">
                  <div className="min-w-0 pr-3">
                    <h4 className="text-xs font-semibold text-slate-200 truncate">{ass.title}</h4>
                    <p className="text-[11px] text-slate-400 font-mono mt-0.5">Asset: {ass.asset_name}</p>
                  </div>
                  <div className="text-right flex-shrink-0">
                    <span className="text-xs font-bold text-cyan-400">{ass.findings_count} CVEs</span>
                    <p className="text-[10px] text-slate-400 font-mono">Risk: {ass.average_risk_score}/100</p>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Priority Findings Requiring Attention */}
        <div className="cyber-card p-5 bg-[#0c1222] border border-slate-800 rounded-xl">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-bold text-slate-200">Top Priority Vulnerabilities</h3>
            <Link to="/vulnerabilities" className="text-xs text-cyan-400 hover:underline">View all</Link>
          </div>

          <div className="space-y-3">
            {(metrics?.recent_findings || []).length === 0 ? (
              <p className="text-xs text-slate-500 py-6 text-center font-mono">No vulnerabilities detected.</p>
            ) : (
              (metrics?.recent_findings || []).map((f: any) => (
                <div key={f.id} className="p-3 rounded-lg bg-slate-900/80 border border-slate-800 flex items-center justify-between">
                  <div className="min-w-0 pr-3">
                    <div className="flex items-center space-x-2">
                      <span className="text-xs font-mono font-bold text-slate-200">{f.cve_id}</span>
                      <SeverityBadge severity={f.severity} />
                    </div>
                    <p className="text-[11px] text-slate-400 truncate mt-1">{f.title}</p>
                  </div>
                  <div className="text-right flex-shrink-0">
                    <StatusBadge status={f.detection_status} />
                    <p className="text-[10px] text-slate-400 font-mono mt-1">Risk: {f.risk_score.toFixed(1)}</p>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
