import React, { useState, useEffect } from 'react';
import { 
  ShieldAlert, ShieldCheck, AlertTriangle, TrendingUp, TrendingDown, 
  Cpu, CheckCircle2, ArrowRight, ExternalLink, Activity, Filter, Eye, RefreshCw
} from 'lucide-react';
import { API_BASE } from '../config/api';

export default function DashboardView({ onNavigateToAnalyze, onNavigateToTwin }) {
  const [metrics, setMetrics] = useState(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    fetchDashboardMetrics();
  }, []);

  const fetchDashboardMetrics = async () => {
    setIsLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/v1/dashboard`);
      if (res.ok) {
        const data = await res.json();
        setMetrics(data);
      }
    } catch (e) {
      console.warn('Dashboard fetch fallback:', e);
    } finally {
      setIsLoading(false);
    }
  };

  const getVerdictBadge = (verdict) => {
    switch (verdict) {
      case 'SAFE':
        return <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">● Safe</span>;
      case 'SUSPICIOUS':
        return <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-amber-50 text-amber-700 border border-amber-200">● Suspicious</span>;
      case 'MALICIOUS':
        return <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-rose-50 text-rose-700 border border-rose-200">● High Risk</span>;
      default:
        return <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-slate-50 text-slate-700 border border-slate-200">● Unknown</span>;
    }
  };

  // Dynamic calculations from real database telemetry
  const total = metrics?.total_analyses || 0;
  const avgRisk = metrics?.average_risk_score !== undefined 
    ? Math.round(metrics.average_risk_score) 
    : (total > 0 && metrics?.latest_analyses?.length 
        ? Math.round(metrics.latest_analyses.reduce((acc, x) => acc + (x.risk_score || 0), 0) / metrics.latest_analyses.length) 
        : 0);

  const highRiskCount = metrics?.high_risk_count ?? 0;
  const lowRiskCount = metrics?.low_risk_count ?? 0;
  const suspiciousCount = metrics?.suspicious_count ?? 0;
  const postureScore = total > 0 ? Math.max(0, 100 - avgRisk) : 100;

  // Timeline geometry
  const timelineData = metrics?.timeline_activity || [];
  const svgWidth = 600;
  const padding = 30;
  const chartW = svgWidth - padding * 2;
  const chartH = 85;
  const chartBaseY = 120;

  const coords = timelineData.length > 0 
    ? timelineData.map((d, i) => {
        const x = padding + (i / Math.max(1, timelineData.length - 1)) * chartW;
        const y = chartBaseY - ((d.average_risk || 0) / 100) * chartH;
        return { x, y, risk: d.average_risk, date: d.date, count: d.count };
      })
    : [];

  const pointsPolyline = coords.map(c => `${c.x},${c.y}`).join(' ');
  const pointsPolygon = coords.length > 0 
    ? `${coords[0].x},${chartBaseY + 15} ` + pointsPolyline + ` ${coords[coords.length - 1].x},${chartBaseY + 15}`
    : '';

  const circumference = 326.7;
  const donutOffset = circumference - (circumference * postureScore) / 100;

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12">
      
      {/* 1. Header Overview & Digital Twin Value Proposition */}
      <div className="bg-white border border-[#E2E8F0] rounded-xl p-6 shadow-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-[#0B1F44]">
            Security Operations &amp; Digital Twin Overview
          </h1>
          <p className="text-sm text-slate-500 mt-1">
            Real-time telemetry grounded in persistent security memory and isolated twin verification.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={fetchDashboardMetrics}
            disabled={isLoading}
            className="p-2 border border-[#E2E8F0] hover:bg-slate-50 text-slate-600 rounded-lg transition-colors shadow-sm"
            title="Refresh Metrics"
          >
            <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
          </button>
          <button
            onClick={() => onNavigateToAnalyze && onNavigateToAnalyze()}
            className="px-4 py-2 bg-[#2563EB] hover:bg-blue-700 text-white font-semibold text-xs rounded-lg transition-colors shadow-sm flex items-center gap-1.5"
          >
            <span>Run New Security Analysis</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* 2. Key Metrics Row (4 Clean White Cards) */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        
        {/* Card 1: Risk Score */}
        <div className="bg-white border border-[#E2E8F0] rounded-xl p-5 shadow-sm">
          <div className="flex items-center justify-between text-slate-500 text-xs font-semibold uppercase tracking-wider">
            <span>Average Threat Risk</span>
            <span className="p-1.5 rounded-md bg-amber-50 text-amber-600">
              <AlertTriangle className="w-4 h-4" />
            </span>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-bold text-[#0B1F44]">{avgRisk}</span>
            <span className="text-xs text-slate-400 font-medium">/100</span>
          </div>
          <div className="mt-2 flex items-center gap-1 text-xs text-slate-500 font-medium">
            <TrendingUp className="w-3.5 h-3.5 text-blue-600" />
            <span>Trend: <strong>{metrics?.risk_trend || 'STABLE'}</strong></span>
          </div>
        </div>

        {/* Card 2: Critical Findings */}
        <div className="bg-white border border-[#E2E8F0] rounded-xl p-5 shadow-sm">
          <div className="flex items-center justify-between text-slate-500 text-xs font-semibold uppercase tracking-wider">
            <span>Critical Threats</span>
            <span className="p-1.5 rounded-md bg-rose-50 text-rose-600">
              <ShieldAlert className="w-4 h-4" />
            </span>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-bold text-[#EF4444]">{String(highRiskCount).padStart(2, '0')}</span>
            <span className="text-xs text-slate-400 font-medium">active items</span>
          </div>
          <div className="mt-2 text-xs text-slate-500 font-medium">
            Requires Digital Twin remediation
          </div>
        </div>

        {/* Card 3: Safe / Low Risk */}
        <div className="bg-white border border-[#E2E8F0] rounded-xl p-5 shadow-sm">
          <div className="flex items-center justify-between text-slate-500 text-xs font-semibold uppercase tracking-wider">
            <span>Safe Indicators</span>
            <span className="p-1.5 rounded-md bg-emerald-50 text-emerald-600">
              <ShieldCheck className="w-4 h-4" />
            </span>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-bold text-emerald-600">{String(lowRiskCount).padStart(2, '0')}</span>
            <span className="text-xs text-slate-400 font-medium">verified clean</span>
          </div>
          <div className="mt-2 text-xs text-emerald-600 font-medium flex items-center gap-1">
            <CheckCircle2 className="w-3.5 h-3.5" />
            <span>0% impact on live production</span>
          </div>
        </div>

        {/* Card 4: Total Memory Analyses */}
        <div className="bg-white border border-[#E2E8F0] rounded-xl p-5 shadow-sm">
          <div className="flex items-center justify-between text-slate-500 text-xs font-semibold uppercase tracking-wider">
            <span>Security Memory Records</span>
            <span className="p-1.5 rounded-md bg-blue-50 text-[#2563EB]">
              <Cpu className="w-4 h-4" />
            </span>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-bold text-[#2563EB]">{String(total).padStart(2, '0')}</span>
            <span className="text-xs text-slate-400 font-medium">historical scans</span>
          </div>
          <div className="mt-2 text-xs text-slate-500 font-medium">
            {metrics?.changed_since_previous || 0} trackable shifts recorded
          </div>
        </div>

      </div>

      {/* 3. Middle Charts Section: Dynamic Risk Timeline & Security Posture */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Left: Risk Timeline (2 columns) */}
        <div className="lg:col-span-2 bg-white border border-[#E2E8F0] rounded-xl p-6 shadow-sm">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-bold text-[#0B1F44]">Risk Timeline &amp; Indicator Evaluation</h3>
              <p className="text-xs text-slate-500">Real daily average risk computed from database history</p>
            </div>
            <span className="text-xs text-[#2563EB] font-semibold bg-[#EFF6FF] px-2.5 py-1 rounded border border-[#BFDBFE]">
              Last 7 Days
            </span>
          </div>

          {/* Dynamic Blue SVG Line Chart */}
          <div className="h-48 w-full pt-4">
            {coords.length > 0 ? (
              <svg className="w-full h-full overflow-visible" viewBox="0 0 600 150">
                {/* Grid lines */}
                <line x1="0" y1="35" x2="600" y2="35" stroke="#F1F5F9" strokeWidth="1" />
                <line x1="0" y1="77" x2="600" y2="77" stroke="#F1F5F9" strokeWidth="1" />
                <line x1="0" y1="120" x2="600" y2="120" stroke="#F1F5F9" strokeWidth="1" />

                {/* Area fill */}
                <defs>
                  <linearGradient id="blueGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#2563EB" stopOpacity="0.18" />
                    <stop offset="100%" stopColor="#2563EB" stopOpacity="0.0" />
                  </linearGradient>
                </defs>
                {pointsPolygon && (
                  <polygon
                    points={pointsPolygon}
                    fill="url(#blueGradient)"
                  />
                )}

                {/* Polyline */}
                {pointsPolyline && (
                  <polyline
                    points={pointsPolyline}
                    fill="none"
                    stroke="#2563EB"
                    strokeWidth="2.5"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                )}

                {/* Nodes */}
                {coords.map((pt, i) => (
                  <g key={i}>
                    <circle cx={pt.x} cy={pt.y} r="4" fill="#FFFFFF" stroke="#2563EB" strokeWidth="2" />
                    {pt.count > 0 && (
                      <text x={pt.x} y={pt.y - 8} textAnchor="middle" fontSize="9" fill="#2563EB" fontWeight="bold">
                        {Math.round(pt.risk)}
                      </text>
                    )}
                  </g>
                ))}
              </svg>
            ) : (
              <div className="h-full flex items-center justify-center text-xs text-slate-400">
                No historical scans recorded yet.
              </div>
            )}

            <div className="flex justify-between text-[11px] text-slate-400 mt-2 px-2">
              {timelineData.map((d, i) => {
                const parts = d.date.split('-');
                const label = parts.length === 3 ? `${parts[1]}/${parts[2]}` : d.date;
                return <span key={i}>{label}</span>;
              })}
            </div>
          </div>
        </div>

        {/* Right: Security Posture Score (1 column) */}
        <div className="bg-white border border-[#E2E8F0] rounded-xl p-6 shadow-sm flex flex-col justify-between">
          <div>
            <h3 className="text-sm font-bold text-[#0B1F44]">Digital Twin Posture Score</h3>
            <p className="text-xs text-slate-500">Calculated defense health across inspected indicators</p>
          </div>

          {/* Clean Donut Indicator */}
          <div className="py-6 flex flex-col items-center justify-center">
            <div className="relative w-32 h-32 flex items-center justify-center">
              <svg className="w-32 h-32 transform -rotate-90">
                <circle
                  cx="64"
                  cy="64"
                  r="52"
                  stroke="#F1F5F9"
                  strokeWidth="10"
                  fill="transparent"
                />
                <circle
                  cx="64"
                  cy="64"
                  r="52"
                  stroke={postureScore >= 70 ? '#10B981' : postureScore >= 40 ? '#F59E0B' : '#EF4444'}
                  strokeWidth="10"
                  strokeDasharray={circumference}
                  strokeDashoffset={donutOffset}
                  strokeLinecap="round"
                  fill="transparent"
                />
              </svg>
              <div className="absolute text-center">
                <div className="text-2xl font-bold text-[#0B1F44]">{postureScore}%</div>
                <div className="text-[10px] text-slate-400 font-semibold uppercase">Health</div>
              </div>
            </div>
          </div>

          <div className="space-y-1.5 pt-2 border-t border-[#F1F5F9] text-xs">
            <div className="flex justify-between text-slate-600">
              <span>Clean / Safe Targets</span>
              <span className="font-semibold text-emerald-600">{lowRiskCount} items</span>
            </div>
            <div className="flex justify-between text-slate-600">
              <span>Suspicious Targets</span>
              <span className="font-semibold text-amber-600">{suspiciousCount} items</span>
            </div>
            <div className="flex justify-between text-slate-600">
              <span>High Risk / Malicious</span>
              <span className="font-semibold text-rose-600">{highRiskCount} items</span>
            </div>
          </div>
        </div>

      </div>

      {/* 4. Recent Security Analyses Table (Live from database) */}
      <div className="bg-white border border-[#E2E8F0] rounded-xl shadow-sm overflow-hidden">
        <div className="px-6 py-4 border-b border-[#E2E8F0] flex items-center justify-between">
          <div>
            <h3 className="text-sm font-bold text-[#0B1F44]">Recent Threat Evaluations</h3>
            <p className="text-xs text-slate-500">Live records retrieved directly from persistent database memory</p>
          </div>
          <button 
            onClick={() => onNavigateToAnalyze && onNavigateToAnalyze()}
            className="text-xs font-semibold text-[#2563EB] hover:text-blue-700 flex items-center gap-1"
          >
            <span>Run New Target</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="bg-[#F8FAFC] border-b border-[#E2E8F0] text-slate-600 font-semibold uppercase text-[11px]">
                <th className="py-3 px-6">Target Indicator</th>
                <th className="py-3 px-4">Domain / ID</th>
                <th className="py-3 px-4">Risk Score</th>
                <th className="py-3 px-4">Verdict</th>
                <th className="py-3 px-4">Timestamp</th>
                <th className="py-3 px-6 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#E2E8F0] text-slate-700">
              {metrics?.latest_analyses && metrics.latest_analyses.length > 0 ? (
                metrics.latest_analyses.map((item, idx) => (
                  <tr key={idx} className="hover:bg-slate-50/80 transition-colors">
                    <td className="py-3.5 px-6 font-medium text-slate-900 max-w-xs truncate font-mono text-[11px]">
                      {item.submitted_url}
                    </td>
                    <td className="py-3.5 px-4 text-slate-500 font-medium">
                      {item.domain || item.analysis_id}
                    </td>
                    <td className="py-3.5 px-4 font-semibold">
                      <span className={item.risk_score > 70 ? 'text-[#EF4444]' : item.risk_score > 30 ? 'text-[#F59E0B]' : 'text-[#10B981]'}>
                        {item.risk_score}/100
                      </span>
                    </td>
                    <td className="py-3.5 px-4">
                      {getVerdictBadge(item.verdict)}
                    </td>
                    <td className="py-3.5 px-4 text-slate-400 text-[11px]">
                      {new Date(item.created_at).toLocaleString()}
                    </td>
                    <td className="py-3.5 px-6 text-right">
                      <button
                        onClick={() => onNavigateToTwin && onNavigateToTwin(item)}
                        className="px-2.5 py-1 text-xs text-[#2563EB] hover:bg-[#EFF6FF] rounded font-medium border border-transparent hover:border-[#BFDBFE] transition-colors"
                      >
                        Verify on Twin →
                      </button>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan="6" className="py-8 text-center text-slate-400">
                    No threat evaluations recorded yet. Run a target to view telemetry.
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
