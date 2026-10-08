"use client";

import React, { useState } from 'react';
import ModuleWrapper from '@/components/layout/ModuleWrapper';
import { Search, Loader2, AlertTriangle, ShieldCheck, HelpCircle } from 'lucide-react';

type ScanStatus = 'idle' | 'scanning' | 'complete';

interface OSINTResult {
  indicator: string;
  type: string;
  score: number;
  lastSeen: string;
}

export default function AnalyzePage() {
  const [searchQuery, setSearchQuery] = useState('');
  const [scanStatus, setScanStatus] = useState<ScanStatus>('idle');
  const [results, setResults] = useState<OSINTResult[]>([]);

  const handleScan = (e: React.FormEvent) => {
    e.preventDefault();
    if (!searchQuery.trim()) return;

    setScanStatus('scanning');
    setResults([]);

    // Simulate OSINT scan delay
    setTimeout(() => {
      // Mock results based on query type approximation
      const isIp = /^[0-9.]+$/.test(searchQuery);
      const isHash = searchQuery.length === 64 || searchQuery.length === 32;

      setResults([
        {
          indicator: searchQuery,
          type: isIp ? 'IPv4' : isHash ? 'SHA-256' : 'URL/Domain',
          score: Math.floor(Math.random() * 100),
          lastSeen: new Date().toISOString().split('T')[0],
        }
      ]);
      setScanStatus('complete');
    }, 1500);
  };

  const getReputationColor = (score: number) => {
    if (score >= 80) return 'text-red-500 bg-red-950 border-red-900';
    if (score >= 40) return 'text-amber-500 bg-amber-950 border-amber-900';
    return 'text-emerald-500 bg-emerald-950 border-emerald-900';
  };

  return (
    <ModuleWrapper 
      title="Threat Analysis & OSINT" 
      description="Real-time adversarial intelligence gathering and active reconnaissance."
    >
      <div className="flex flex-col gap-6 font-mono text-xs">
        
        {/* Search Interface */}
        <div className="bg-zinc-900 border border-zinc-800 p-4">
          <form onSubmit={handleScan} className="flex flex-col gap-2">
            <label className="block text-[10px] text-zinc-500 uppercase tracking-widest font-bold">
              Target Asset (URL / IPv4 / SHA-256)
            </label>
            <div className="flex gap-2">
              <div className="relative flex-1">
                <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-zinc-500" />
                <input 
                  type="text" 
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="w-full bg-zinc-950 border border-zinc-800 p-2 pl-10 text-xs text-zinc-200 font-mono focus:outline-none focus:border-zinc-500 transition-colors placeholder:text-zinc-600"
                  placeholder="e.g. https://target.com or 192.168.1.100"
                  disabled={scanStatus === 'scanning'}
                />
              </div>
              <button 
                type="submit"
                disabled={scanStatus === 'scanning' || !searchQuery.trim()}
                className="bg-zinc-200 text-zinc-950 font-bold px-6 py-2 hover:bg-white transition-colors text-xs uppercase tracking-widest disabled:opacity-50 flex items-center justify-center min-w-[160px]"
              >
                {scanStatus === 'scanning' ? (
                  <Loader2 className="w-4 h-4 animate-spin" />
                ) : (
                  'Run OSINT Scan'
                )}
              </button>
            </div>
          </form>
        </div>

        {/* Results Table */}
        <div>
          <h2 className="text-[10px] text-zinc-500 uppercase tracking-widest mb-3 font-bold border-b border-zinc-800 pb-2">
            Analysis Results
          </h2>
          <div className="border border-zinc-800 bg-zinc-900/50">
            <table className="w-full border-collapse">
              <thead className="bg-zinc-900/80 border-b border-zinc-800 text-[10px] text-zinc-500 uppercase tracking-wider text-left">
                <tr>
                  <th className="p-3 font-bold">Indicator</th>
                  <th className="p-3 font-bold">Type</th>
                  <th className="p-3 font-bold">Reputation Score</th>
                  <th className="p-3 font-bold">Last Seen</th>
                  <th className="p-3 font-bold text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800">
                {results.length === 0 && scanStatus !== 'scanning' && (
                  <tr>
                    <td colSpan={5} className="p-8 text-center text-zinc-600 italic text-xs">
                      No active analysis results. Enter an indicator above to begin.
                    </td>
                  </tr>
                )}
                {scanStatus === 'scanning' && (
                  <tr>
                    <td colSpan={5} className="p-8 text-center text-zinc-500 text-xs flex items-center justify-center gap-2">
                      <Loader2 className="w-4 h-4 animate-spin text-zinc-400" />
                      [SYSTEM] Querying global threat intelligence feeds...
                    </td>
                  </tr>
                )}
                {results.map((res, idx) => (
                  <tr key={idx} className="hover:bg-zinc-900/80 transition-colors">
                    <td className="p-3 text-zinc-300 font-bold">{res.indicator}</td>
                    <td className="p-3 text-zinc-400">{res.type}</td>
                    <td className="p-3">
                      <span className={`px-2 py-1 border text-[10px] uppercase font-bold flex items-center gap-1 w-fit ${getReputationColor(res.score)}`}>
                        {res.score >= 80 ? <AlertTriangle className="w-3 h-3" /> : res.score >= 40 ? <HelpCircle className="w-3 h-3" /> : <ShieldCheck className="w-3 h-3" />}
                        {res.score}/100
                      </span>
                    </td>
                    <td className="p-3 text-zinc-500">{res.lastSeen}</td>
                    <td className="p-3 text-right">
                      <button className="text-blue-500 hover:text-blue-400 underline decoration-blue-500/30 underline-offset-4 text-[10px] uppercase tracking-widest font-bold transition-colors">
                        Pivot Graph
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </ModuleWrapper>
  );
}
