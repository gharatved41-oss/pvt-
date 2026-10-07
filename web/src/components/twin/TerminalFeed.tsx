'use client';

import React, { useEffect, useRef, useState } from 'react';
import { Terminal, Copy, Check } from 'lucide-react';
import { useTwinEngine, LogEvent } from '@/store/useTwinEngine';

interface TerminalFeedProps {
  className?: string;
}

export function TerminalFeed({ className }: TerminalFeedProps) {
  const { logs, isSimulating } = useTwinEngine();
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
      .map((l) => `[${l.timestamp}] [${l.level}] ${l.message}`)
      .join('\n');
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const getLevelBadge = (level: LogEvent['level']) => {
    switch (level) {
      case 'CRIT':
        return (
          <span className="px-1.5 py-0.2 rounded-none font-bold text-[9px] bg-red-950 text-red-500 border border-red-800">
            CRIT
          </span>
        );
      case 'WARN':
        return (
          <span className="px-1.5 py-0.2 rounded-none font-bold text-[9px] bg-amber-950 text-amber-400 border border-amber-800">
            WARN
          </span>
        );
      case 'INFO':
      default:
        return (
          <span className="px-1.5 py-0.2 rounded-none font-bold text-[9px] bg-blue-950 text-blue-400 border border-blue-800">
            INFO
          </span>
        );
    }
  };

  return (
    <div
      className={`rounded-none border border-zinc-800 bg-zinc-950 flex flex-col font-mono text-xs select-none overflow-hidden ${
        className || 'h-72'
      }`}
    >
      {/* Terminal Title Bar */}
      <div className="h-9 px-3 border-b border-zinc-800 bg-zinc-900/60 flex items-center justify-between shrink-0">
        <div className="flex items-center gap-2">
          <Terminal className="w-3.5 h-3.5 text-zinc-400" />
          <span className="text-[11px] font-bold text-zinc-200 uppercase tracking-wider">
            AUDIT_TELEMETRY_FEED
          </span>
          <span className="px-1.5 py-0.5 text-[10px] bg-zinc-900 text-zinc-400 border border-zinc-800 rounded-none">
            {logs.length} EVENTS
          </span>
          {isSimulating && (
            <span className="flex items-center gap-1 text-[10px] text-amber-400">
              <span className="w-1.5 h-1.5 bg-amber-400 animate-ping" />
              TRAVERSING
            </span>
          )}
        </div>

        <button
          type="button"
          onClick={handleCopyLogs}
          className="p-1 hover:bg-zinc-800 text-zinc-400 hover:text-zinc-200 rounded-none transition-colors"
          title="Copy Audit Logs"
        >
          {copied ? (
            <Check className="w-3.5 h-3.5 text-emerald-400" />
          ) : (
            <Copy className="w-3.5 h-3.5" />
          )}
        </button>
      </div>

      {/* Auto-scrolling Monospaced Log Stream */}
      <div
        ref={scrollRef}
        className="flex-1 p-3 overflow-y-auto space-y-1.5 bg-zinc-950 font-mono text-[11px] leading-relaxed scrollbar-thin scrollbar-thumb-zinc-800"
      >
        {logs.map((event, idx) => (
          <div
            key={idx}
            className="flex items-start gap-2 hover:bg-zinc-900/40 p-0.5 rounded-none transition-colors"
          >
            <span className="text-zinc-500 shrink-0 font-mono text-[10px]">
              {event.timestamp}
            </span>
            <div className="shrink-0">{getLevelBadge(event.level)}</div>
            <span
              className={`break-all flex-1 ${
                event.level === 'CRIT'
                  ? 'text-red-400'
                  : event.level === 'WARN'
                  ? 'text-amber-400'
                  : 'text-zinc-300'
              }`}
            >
              {event.message}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
