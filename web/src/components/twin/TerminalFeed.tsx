"use client";

import React, { useEffect, useRef } from 'react';
import { useTwinStore } from '@/store/useTwinStore';

export default function TerminalFeed({ className }: { className?: string }) {
  const { logs, clearLogs } = useTwinStore();
  const feedRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (feedRef.current) {
      feedRef.current.scrollTop = feedRef.current.scrollHeight;
    }
  }, [logs]);

  const getSeverityColor = (sev: string) => {
    switch (sev) {
      case 'INFO': return 'text-sky-400';
      case 'WARN': return 'text-amber-400';
      case 'CRIT': return 'text-red-400 font-bold';
      case 'SUCCESS': return 'text-emerald-400 font-bold';
      default: return 'text-zinc-400';
    }
  };

  return (
    <div className={`flex flex-col h-full border border-zinc-800 bg-zinc-950 font-mono text-[11px] rounded-none ${className || ''}`}>
      {/* Header */}
      <div className="flex items-center justify-between border-b border-zinc-800 bg-zinc-900/50 px-3 py-2">
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 bg-emerald-500 rounded-none animate-pulse" />
          <span className="text-zinc-300 font-bold tracking-widest">&gt; LIVE AUDIT TELEMETRY // STREAM ID: SEC-TWIN-01</span>
        </div>
        <button 
          onClick={clearLogs}
          className="text-zinc-500 hover:text-zinc-200 transition-colors uppercase"
        >
          [Clear]
        </button>
      </div>

      {/* Feed */}
      <div 
        ref={feedRef}
        className="flex-1 overflow-y-auto p-3 space-y-1"
      >
        {logs.map((log) => (
          <div key={log.id} className="flex gap-2 leading-relaxed">
            <span className="text-zinc-500 shrink-0">[{log.timestamp}]</span>
            <span className={`${getSeverityColor(log.severity)} shrink-0`}>[{log.severity}]</span>
            <span className="text-zinc-400 shrink-0">[{log.targetNodeId}]</span>
            <span className="text-zinc-300 whitespace-pre-wrap">{log.message}</span>
          </div>
        ))}
        {logs.length === 0 && (
          <div className="text-zinc-600 italic">No telemetry data available. Awaiting simulation trigger...</div>
        )}
      </div>
    </div>
  );
}
