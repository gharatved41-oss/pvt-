'use client';

import React, { useEffect, useRef } from 'react';
import { Terminal, Shield, Check, Copy } from 'lucide-react';
import { useTwinStore } from '@/store/useTwinStore';

export function CTEMTerminal() {
  const { eventLogs, simulationState } = useTwinStore();
  const bottomRef = useRef<HTMLDivElement>(null);

  // Auto-scroll to the bottom as new logs appear
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [eventLogs]);

  const getLogColor = (level: string) => {
    switch (level) {
      case 'crit':
        return 'text-red-400 font-semibold';
      case 'warn':
        return 'text-amber-400';
      case 'success':
        return 'text-emerald-400 font-semibold';
      default:
        return 'text-zinc-300';
    }
  };

  return (
    <div className="h-64 border-t border-zinc-800 bg-zinc-950 font-mono text-xs flex flex-col shrink-0">
      {/* Terminal Header Bar */}
      <div className="h-9 px-4 border-b border-zinc-800 bg-zinc-900/60 flex items-center justify-between shrink-0 select-none">
        <div className="flex items-center gap-2">
          <Terminal className="w-3.5 h-3.5 text-zinc-400" />
          <span className="text-[11px] font-semibold text-zinc-300 tracking-wider uppercase">
            Execution Console • Telemetry Feed
          </span>
          <span className="text-[10px] text-zinc-500">
            ({eventLogs.length} events)
          </span>
        </div>

        <div className="flex items-center gap-3 text-[10px] text-zinc-500">
          <div className="flex items-center gap-1.5">
            <span
              className={`w-1.5 h-1.5 rounded-full ${
                simulationState === 'RUNNING'
                  ? 'bg-amber-400 animate-ping'
                  : simulationState === 'COMPLETED'
                  ? 'bg-emerald-400'
                  : 'bg-zinc-600'
              }`}
            />
            <span className="uppercase text-zinc-400">
              {simulationState}
            </span>
          </div>
          <span>•</span>
          <span>AUTO-SCROLL: ON</span>
        </div>
      </div>

      {/* Terminal Log Stream Area */}
      <div className="flex-1 p-4 overflow-y-auto space-y-1.5 leading-relaxed bg-zinc-950/90">
        {eventLogs.map((log) => (
          <div key={log.id} className="flex items-start gap-2.5">
            <span className="text-zinc-500 shrink-0 select-none">
              [{log.timestamp}]
            </span>
            <span className={`${getLogColor(log.level)} break-all`}>
              {log.text}
            </span>
          </div>
        ))}
        <div ref={bottomRef} />
      </div>
    </div>
  );
}
