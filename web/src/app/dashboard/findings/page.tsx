"use client";

import React from 'react';
import ModuleWrapper from '@/components/layout/ModuleWrapper';
import { AlertTriangle, ShieldAlert, Shield } from 'lucide-react';

export default function FindingsPage() {
  const mockFindings = [
    { id: 'CVE-2024-2101', severity: 'CRITICAL', title: 'Remote Code Execution in Commerce API', asset: '10.0.1.15', date: '2026-10-08' },
    { id: 'CVE-2023-4521', severity: 'HIGH', title: 'Privilege Escalation via JWT Misconfiguration', asset: '10.0.1.22', date: '2026-10-07' },
    { id: 'CWE-79', severity: 'MEDIUM', title: 'Stored Cross-Site Scripting (XSS) in Reviews Module', asset: '10.0.1.15', date: '2026-10-05' },
  ];

  return (
    <ModuleWrapper 
      title="Vulnerability Findings" 
      description="Aggregated threat intelligence and validated exploits from the active digital twin."
    >
      <div className="space-y-4">
        {mockFindings.map((finding, idx) => (
          <div key={idx} className="border border-zinc-800 bg-zinc-900 flex items-center justify-between p-4 hover:bg-zinc-800/50 transition-colors cursor-pointer group">
            <div className="flex items-center gap-4">
              <div className={`p-2 border ${
                finding.severity === 'CRITICAL' ? 'bg-red-950 border-red-900 text-red-500' :
                finding.severity === 'HIGH' ? 'bg-amber-950 border-amber-900 text-amber-500' :
                'bg-blue-950 border-blue-900 text-blue-500'
              }`}>
                {finding.severity === 'CRITICAL' ? <ShieldAlert className="w-4 h-4" /> : 
                 finding.severity === 'HIGH' ? <AlertTriangle className="w-4 h-4" /> : 
                 <Shield className="w-4 h-4" />}
              </div>
              <div>
                <div className="text-zinc-200 font-bold mb-1 group-hover:text-white transition-colors">{finding.title}</div>
                <div className="flex items-center gap-3 text-xs text-zinc-500 font-mono">
                  <span className="text-zinc-400">{finding.id}</span>
                  <span>|</span>
                  <span className="uppercase">Target: {finding.asset}</span>
                </div>
              </div>
            </div>
            
            <div className="text-right">
              <span className="text-zinc-600 text-xs">{finding.date}</span>
            </div>
          </div>
        ))}
      </div>
    </ModuleWrapper>
  );
}
