"use client";

import React, { useState, useMemo } from 'react';
import ModuleWrapper from '@/components/layout/ModuleWrapper';
import { Database, Search, Filter, RotateCw, AlertTriangle, ShieldCheck, HelpCircle } from 'lucide-react';

interface ScanHistory {
  id: string;
  target: string;
  risk: number;
  verdict: 'MALICIOUS' | 'SUSPICIOUS' | 'SAFE';
  timestamp: string;
}

export default function MemoryPage() {
  const [searchQuery, setSearchQuery] = useState('');
  const [filterVerdict, setFilterVerdict] = useState<string>('ALL');

  // Mock data representing the analyses SQLite table
  const [mockHistory] = useState<ScanHistory[]>([
    { id: 'SCN-8891', target: '10.0.1.15', risk: 85, verdict: 'MALICIOUS', timestamp: '2026-10-07 14:32:01' },
    { id: 'SCN-8890', target: 'api.commerce.internal', risk: 12, verdict: 'SAFE', timestamp: '2026-10-07 10:15:22' },
    { id: 'SCN-8889', target: '10.0.2.55', risk: 92, verdict: 'MALICIOUS', timestamp: '2026-10-06 09:05:44' },
    { id: 'SCN-8888', target: 'auth.service.local', risk: 55, verdict: 'SUSPICIOUS', timestamp: '2026-10-05 16:44:12' },
    { id: 'SCN-8887', target: '192.168.1.100', risk: 5, verdict: 'SAFE', timestamp: '2026-10-04 11:20:00' },
  ]);

  const filteredHistory = useMemo(() => {
    return mockHistory.filter(scan => {
      const matchesSearch = 
        scan.id.toLowerCase().includes(searchQuery.toLowerCase()) || 
        scan.target.toLowerCase().includes(searchQuery.toLowerCase());
      
      const matchesVerdict = filterVerdict === 'ALL' || scan.verdict === filterVerdict;

      return matchesSearch && matchesVerdict;
    });
  }, [mockHistory, searchQuery, filterVerdict]);

  const handleReRun = (id: string, target: string) => {
    console.log(`[SYSTEM] Initiating re-test for scan ${id} against target ${target}...`);
    alert(`[SYSTEM] Re-test initiated for ${target}`);
  };

  const getVerdictStyle = (verdict: string) => {
    switch(verdict) {
      case 'MALICIOUS': return 'bg-red-950 border-red-900 text-red-500';
      case 'SUSPICIOUS': return 'bg-amber-950 border-amber-900 text-amber-500';
      case 'SAFE': return 'bg-emerald-950 border-emerald-900 text-emerald-500';
      default: return 'bg-zinc-900 border-zinc-700 text-zinc-400';
    }
  };

  const getVerdictIcon = (verdict: string) => {
    switch(verdict) {
      case 'MALICIOUS': return <AlertTriangle className="w-3 h-3" />;
      case 'SUSPICIOUS': return <HelpCircle className="w-3 h-3" />;
      case 'SAFE': return <ShieldCheck className="w-3 h-3" />;
      default: return null;
    }
  };

  return (
    <ModuleWrapper 
      title="Security Memory" 
      description="Persistent historical ledger of adversarial simulations and AI-validated remediation states."
    >
      <div className="flex flex-col gap-4 font-mono text-xs">
        
        {/* Top Control Bar */}
        <div className="flex flex-wrap gap-4 bg-zinc-900 border border-zinc-800 p-4 items-center justify-between">
          <div className="flex-1 relative min-w-[250px]">
            <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-zinc-500" />
            <input 
              type="text" 
              placeholder="Filter by Target or ID..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full bg-zinc-950 border border-zinc-800 p-2 pl-10 text-zinc-200 focus:outline-none focus:border-zinc-500 transition-colors placeholder:text-zinc-600"
            />
          </div>
          <div className="flex items-center gap-2">
            <Filter className="w-4 h-4 text-zinc-500" />
            <select
              value={filterVerdict}
              onChange={(e) => setFilterVerdict(e.target.value)}
              className="bg-zinc-950 border border-zinc-800 p-2 text-zinc-300 focus:outline-none focus:border-zinc-500 transition-colors uppercase cursor-pointer"
            >
              <option value="ALL">All Verdicts</option>
              <option value="MALICIOUS">Malicious</option>
              <option value="SUSPICIOUS">Suspicious</option>
              <option value="SAFE">Safe</option>
            </select>
          </div>
        </div>

        {/* Data Grid */}
        <div className="border border-zinc-800 bg-zinc-950 overflow-x-auto">
          <table className="w-full border-collapse border border-zinc-800 text-left">
            <thead className="bg-zinc-900/80 border-b border-zinc-800 text-[10px] text-zinc-500 uppercase tracking-widest font-bold">
              <tr>
                <th className="p-4 border-r border-zinc-800">Analysis ID</th>
                <th className="p-4 border-r border-zinc-800">Target Indicator</th>
                <th className="p-4 border-r border-zinc-800">Risk Score</th>
                <th className="p-4 border-r border-zinc-800">Verdict</th>
                <th className="p-4 border-r border-zinc-800">Timestamp</th>
                <th className="p-4 text-center">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800">
              {filteredHistory.length === 0 ? (
                <tr>
                  <td colSpan={6} className="p-8 text-center text-zinc-600 italic">
                    No historical records match the active filters.
                  </td>
                </tr>
              ) : (
                filteredHistory.map((scan, idx) => (
                  <tr key={scan.id} className="hover:bg-zinc-800/30 transition-colors even:bg-zinc-900/30">
                    <td className="p-4 border-r border-zinc-800 text-zinc-300 font-bold">{scan.id}</td>
                    <td className="p-4 border-r border-zinc-800 text-zinc-400">{scan.target}</td>
                    <td className="p-4 border-r border-zinc-800 font-bold">
                      <span className={scan.risk >= 70 ? 'text-red-400' : scan.risk >= 40 ? 'text-amber-400' : 'text-emerald-400'}>
                        {scan.risk} / 100
                      </span>
                    </td>
                    <td className="p-4 border-r border-zinc-800">
                      <span className={`px-2 py-1 border text-[10px] uppercase font-bold flex items-center gap-1.5 w-fit ${getVerdictStyle(scan.verdict)}`}>
                        {getVerdictIcon(scan.verdict)}
                        {scan.verdict}
                      </span>
                    </td>
                    <td className="p-4 border-r border-zinc-800 text-[10px] text-zinc-500">{scan.timestamp}</td>
                    <td className="p-4 text-center">
                      <button 
                        onClick={() => handleReRun(scan.id, scan.target)}
                        className="bg-zinc-800 hover:bg-blue-900 border border-zinc-700 hover:border-blue-700 text-zinc-300 hover:text-blue-300 px-3 py-1.5 transition-colors uppercase tracking-widest text-[10px] font-bold flex items-center gap-2 mx-auto"
                      >
                        <RotateCw className="w-3 h-3" />
                        [ RE-RUN ]
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
        
        {/* Footer */}
        <div className="p-3 bg-zinc-900/30 border border-t-0 border-zinc-800 text-[10px] text-zinc-500 flex justify-between items-center">
          <div className="flex items-center gap-2">
            <Database className="w-3 h-3" />
            <span>SQLite backend synced</span>
          </div>
          <span>Showing {filteredHistory.length} records</span>
        </div>

      </div>
    </ModuleWrapper>
  );
}
