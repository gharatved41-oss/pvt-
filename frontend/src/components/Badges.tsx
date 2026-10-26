import React from 'react';
import { Severity, DetectionStatus, RemediationStatus } from '../types';

export const SeverityBadge: React.FC<{ severity: Severity | string }> = ({ severity }) => {
  const s = severity.toLowerCase();
  let bg = 'bg-blue-950/80 text-blue-400 border-blue-800';
  if (s === 'critical') bg = 'bg-red-950/80 text-red-400 border-red-700 font-semibold';
  else if (s === 'high') bg = 'bg-orange-950/80 text-orange-400 border-orange-700';
  else if (s === 'medium') bg = 'bg-amber-950/80 text-amber-400 border-amber-700';

  return (
    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs border uppercase tracking-wider ${bg}`}>
      {severity}
    </span>
  );
};

export const StatusBadge: React.FC<{ status: DetectionStatus | RemediationStatus | string }> = ({ status }) => {
  const s = status.toLowerCase();
  let style = 'bg-slate-800 text-slate-300 border-slate-700';

  if (s === 'confirmed' || s === 'resolved') {
    style = 'bg-emerald-950/80 text-emerald-400 border-emerald-600';
  } else if (s === 'fixed' || s === 'approved') {
    style = 'bg-green-950/80 text-green-400 border-green-600';
  } else if (s === 'detected' || s === 'recommended') {
    style = 'bg-cyan-950/80 text-cyan-400 border-cyan-700';
  } else if (s === 'suspected' || s === 'awaiting_approval') {
    style = 'bg-amber-950/80 text-amber-400 border-amber-600';
  } else if (s === 'applied_in_twin') {
    style = 'bg-purple-950/80 text-purple-400 border-purple-600';
  } else if (s === 'unresolved' || s === 'failed' || s === 'rejected') {
    style = 'bg-rose-950/80 text-rose-400 border-rose-700';
  } else if (s === 'inconclusive') {
    style = 'bg-zinc-800 text-zinc-400 border-zinc-600';
  }

  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs border font-medium uppercase tracking-wide ${style}`}>
      <span className="w-1.5 h-1.5 mr-1.5 rounded-full bg-current opacity-75"></span>
      {status.replace(/_/g, ' ')}
    </span>
  );
};

export const RiskGauge: React.FC<{ score: number; priority?: string }> = ({ score, priority }) => {
  let color = 'bg-blue-500';
  if (score >= 85) color = 'bg-red-500 shadow-red-500/50';
  else if (score >= 70) color = 'bg-orange-500 shadow-orange-500/50';
  else if (score >= 40) color = 'bg-amber-500 shadow-amber-500/50';

  return (
    <div className="w-full">
      <div className="flex justify-between items-center text-xs mb-1">
        <span className="font-bold text-slate-200">{score.toFixed(1)} <span className="text-slate-500">/ 100</span></span>
        {priority && <span className="text-slate-400 text-[11px] font-mono">{priority}</span>}
      </div>
      <div className="w-full bg-slate-800 rounded-full h-1.5 overflow-hidden">
        <div
          className={`h-full rounded-full transition-all duration-500 ${color}`}
          style={{ width: `${Math.min(100, Math.max(3, score))}%` }}
        />
      </div>
    </div>
  );
};
