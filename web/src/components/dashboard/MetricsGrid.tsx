"use client";

import React from 'react';
import { useTwinStore } from '@/store/useTwinStore';
import { ShieldAlert, Target, ShieldCheck, Database } from 'lucide-react';

export function MetricsGrid() {
  const { nodes, riskScore } = useTwinStore();

  // Dynamically calculate metrics based on nodes state
  const criticalThreats = nodes.filter(n => n.status === 'compromised').length;
  const safeIndicators = nodes.filter(n => n.status === 'healthy' || n.status === 'patched').length;
  
  // Just mock Security Memory Records incrementing based on logs if we want, or a fixed number + log length
  const { terminalLogs } = useTwinStore();
  const memoryRecords = 1420 + terminalLogs.length;

  return (
    <div className="grid grid-cols-1 md:grid-cols-4 gap-0 border-b border-zinc-800 bg-zinc-950 select-none">
      {/* Metric 1: Average Threat Risk */}
      <div className="p-4 border-r border-zinc-800 flex flex-col justify-center">
        <div className="flex items-center gap-2 mb-2">
          <Target className="w-4 h-4 text-amber-500" />
          <span className="font-mono text-[10px] text-zinc-500 uppercase tracking-widest font-bold">
            Average Threat Risk
          </span>
        </div>
        <div className="font-mono text-3xl font-bold text-amber-500">
          {riskScore}<span className="text-sm text-zinc-600 ml-1">/100</span>
        </div>
      </div>

      {/* Metric 2: Critical Threats */}
      <div className="p-4 border-r border-zinc-800 flex flex-col justify-center">
        <div className="flex items-center gap-2 mb-2">
          <ShieldAlert className="w-4 h-4 text-red-500" />
          <span className="font-mono text-[10px] text-zinc-500 uppercase tracking-widest font-bold">
            Critical Threats
          </span>
        </div>
        <div className="font-mono text-3xl font-bold text-red-500">
          {criticalThreats}
        </div>
      </div>

      {/* Metric 3: Safe Indicators */}
      <div className="p-4 border-r border-zinc-800 flex flex-col justify-center">
        <div className="flex items-center gap-2 mb-2">
          <ShieldCheck className="w-4 h-4 text-emerald-500" />
          <span className="font-mono text-[10px] text-zinc-500 uppercase tracking-widest font-bold">
            Safe Indicators
          </span>
        </div>
        <div className="font-mono text-3xl font-bold text-emerald-500">
          {safeIndicators}
        </div>
      </div>

      {/* Metric 4: Security Memory Records */}
      <div className="p-4 flex flex-col justify-center">
        <div className="flex items-center gap-2 mb-2">
          <Database className="w-4 h-4 text-blue-500" />
          <span className="font-mono text-[10px] text-zinc-500 uppercase tracking-widest font-bold">
            Security Memory Records
          </span>
        </div>
        <div className="font-mono text-3xl font-bold text-blue-500">
          {memoryRecords.toLocaleString()}
        </div>
      </div>
    </div>
  );
}
