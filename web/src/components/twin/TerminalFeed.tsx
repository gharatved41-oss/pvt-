'use client';

import React, { useEffect, useRef, useState } from 'react';
import { Terminal, Copy, Check, Trash2 } from 'lucide-react';
import { useTwinStore } from '@/store/useTwinStore';
import { TelemetryEvent } from '@/lib/mockData';

export function TerminalFeed({ className }: { className?: string }) {
  const { logs, clearLogs, simulationStatus } = useTwinStore();
  const [copied, setCopied] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);

  // Auto-scroll on new logs
  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [logs]);

  const handleCopyLogs = () => {
    const text = logs
      .map(
        (l) =>
          `[${l.timestamp}] [${l.severity}] [${l.step}] ${l.message} (Target: ${l.targetNodeId})`
      )
      .join('\n');
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const getSeverityBadge = (severity: TelemetryEvent['severity']) => {
    switch (severity) {
      case 'CRIT':
        return (
          <span className="px-1.5 py-0.2 rounded font-bold text-[9px] bg-red-950 text-red-400 border border-red-800">
            CRIT
          </span>
        );
      case 'WARN':
        return (
          <span className="px-1.5 py-0.2 rounded font-bold text-[9px] bg-amber-950 text-amber-400 border border-amber-800">
            WARN
          </span>
        );
      case 'SUCCESS':
        return (
          <span className="px-1.5 py-0.2 rounded font-bold text-[9px] bg-emerald-950 text-emerald-400 border border-emerald-800">
            SUCCESS
          </span>
        );
      case 'INFO':
      default:
        return (
          <span className="px-1.5 py-0.2 rounded font-bold text-[9px] bg-blue-950 text-blue-400 border border-blue-800">
            INFO
          </span>
        );
    }
  };

  return (
    <div
      className={`rounded-md border border-zinc-800 bg-zinc-950 flex flex-col font-mono text-xs select-none overflow-hidden ${
        className || 'h-72'
      }`}
    >
      {/* Header with counter and actions */}
      <div className="h-9 px-3 border-b border-zinc-800 bg-zinc-900/60 flex items-center justify-between shrink-0">
        <div className="flex items-center gap-2">
          <Terminal className="w-3.5 h-3.5 text-zinc-400" />
          <span className="text-[11px] font-semibold text-zinc-200 uppercase tracking-wider">
            Audit Telemetry Stream
          </span>
          <span className="px-1.5 py-0.5 text-[10px] bg-zinc-800 text-zinc-400 border border-zinc-700 rounded">
            {logs.length} EVENTS
          </span>
          {simulationStatus === 'RUNNING' && (
            <span className="flex items-center gap-1 text-[10px] text-amber-400">
              <span className="w-1.5 h-1.5 rounded-full bg-amber-400 animate-ping" />
              STREAMING
            </span>
          )}
        </div>

        <div className="flex items-center gap-1.5">
          <button
            type="button"
            onClick={handleCopyLogs}
            className="p-1 hover:bg-zinc-800 text-zinc-400 hover:text-zinc-200 rounded transition-colors"
            title="Copy audit log"
          >
            {copied ? (
              <Check className="w-3.5 h-3.5 text-emerald-400" />
            ) : (
              <Copy className="w-3.5 h-3.5" />
            )}
          </button>
          <button
            type="button"
            onClick={clearLogs}
            className="p-1 hover:bg-zinc-800 text-zinc-400 hover:text-red-400 rounded transition-colors"
            title="Clear Terminal"
          >
            <Trash2 className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Auto-scrolling Log Stream */}
      <div
        ref={scrollRef}
        className="flex-1 p-3 overflow-y-auto space-y-1.5 bg-zinc-950 font-mono text-[11px] leading-relaxed scrollbar-thin scrollbar-thumb-zinc-800"
      >
        {logs.map((event) => (
          <div
            key={event.id}
            className="flex items-start gap-2 hover:bg-zinc-900/40 p-0.5 rounded transition-colors"
          >
            <span className="text-zinc-500 shrink-0 font-mono text-[10px]">
              {event.timestamp}
            </span>
            <div className="shrink-0">{getSeverityBadge(event.severity)}</div>
            <span className="text-zinc-300 break-all flex-1">{event.message}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
