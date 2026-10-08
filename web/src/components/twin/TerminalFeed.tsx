"use client";

import React, { useEffect, useRef } from 'react';
import { useTwinStore } from '@/store/useTwinStore';

export default function TerminalFeed({ className }: { className?: string }) {
  const { terminalLogs, clearLogs } = useTwinStore();
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [terminalLogs]);

  const getLogStyle = (log: string) => {
    if (log.includes('[CRIT]')) return 'text-red-500 font-bold';
    if (log.includes('[SUCCESS]')) return 'text-emerald-400 font-bold';
    if (log.includes('[INFO]')) return 'text-sky-400';
    if (log.includes('[WARN]')) return 'text-amber-400';
    return 'text-zinc-300';
  };

  return (
    <div className={`flex flex-col h-full border border-zinc-800 bg-zinc-950 font-mono text-[11px] rounded-none ${className || ''}`}>
      {/* Header */}
      <div className="flex items-center justify-between border-b border-zinc-800 bg-zinc-900/50 px-3 py-2 shrink-0">
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 bg-emerald-500 rounded-none animate-pulse" />
          <span className="text-zinc-300 font-bold tracking-widest uppercase">&gt; LIVE AUDIT TELEMETRY // STREAM ID: SEC-TWIN-01</span>
        </div>
        <button 
          onClick={clearLogs}
          className="text-zinc-500 hover:text-zinc-200 transition-colors uppercase shrink-0"
        >
          [Clear]
        </button>
      </div>

      {/* Feed with Custom Scrollbar */}
      <div className="flex-1 overflow-y-auto p-3 space-y-1">
        {terminalLogs.map((log, idx) => (
          <div key={idx} className={`leading-relaxed whitespace-pre-wrap ${getLogStyle(log)}`}>
            {log}
          </div>
        ))}
        {terminalLogs.length === 0 && (
          <div className="text-zinc-600 italic">No telemetry data available. Awaiting simulation trigger...</div>
        )}
        <div ref={bottomRef} />
      </div>
    </div>
  );
}
