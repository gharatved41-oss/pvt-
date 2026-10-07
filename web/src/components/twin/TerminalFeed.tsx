'use client';

import React, { useState, useEffect, useRef } from 'react';
import { 
  Terminal, 
  Copy, 
  Check, 
  ArrowDown, 
  Pause, 
  Play, 
  Trash2, 
  ShieldAlert 
} from 'lucide-react';
import { useSimulationTelemetry } from '@/hooks/useSimulationTelemetry';
import { SimulationEvent } from '@/types';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';

export interface TerminalFeedProps {
  simId: string | null;
  events?: SimulationEvent[];
  className?: string;
  maxHeight?: string;
}

export function TerminalFeed({
  simId,
  events: propEvents,
  className,
  maxHeight = 'h-80',
}: TerminalFeedProps) {
  // Subscribe to real-time telemetry stream from Firestore
  const { events: liveEvents, loading } = useSimulationTelemetry(simId);
  const events = propEvents || liveEvents;

  const [autoScroll, setAutoScroll] = useState<boolean>(true);
  const [copied, setCopied] = useState<boolean>(false);
  const scrollRef = useRef<HTMLDivElement>(null);

  // Auto-scroll when new events arrive
  useEffect(() => {
    if (autoScroll && scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [events, autoScroll]);

  const handleCopyLogs = () => {
    const logText = events
      .map((e) => {
        const time = e.timestamp?.toDate
          ? e.timestamp.toDate().toISOString()
          : new Date().toISOString();
        return `[${time}] [${e.severity.toUpperCase()}] [${e.step}] ${e.message} (Target: ${e.targetNodeId})`;
      })
      .join('\n');

    navigator.clipboard.writeText(logText);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const formatTimestamp = (timestamp: any) => {
    if (!timestamp) return '00:00:00.000';
    if (timestamp.toDate) {
      const d = timestamp.toDate();
      return d.toTimeString().split(' ')[0] + '.' + d.getMilliseconds().toString().padStart(3, '0');
    }
    return new Date().toTimeString().split(' ')[0];
  };

  const getSeverityBadge = (severity: 'info' | 'warning' | 'critical') => {
    switch (severity) {
      case 'critical':
        return (
          <span className="font-mono text-[9px] px-1 py-0 rounded font-bold bg-red-950 text-red-400 border border-red-800/80">
            CRIT
          </span>
        );
      case 'warning':
        return (
          <span className="font-mono text-[9px] px-1 py-0 rounded font-bold bg-amber-950 text-amber-400 border border-amber-800/80">
            WARN
          </span>
        );
      case 'info':
      default:
        return (
          <span className="font-mono text-[9px] px-1 py-0 rounded font-bold bg-zinc-900 text-zinc-400 border border-zinc-700">
            INFO
          </span>
        );
    }
  };

  return (
    <div className={`rounded-md border border-zinc-800 bg-zinc-950 flex flex-col overflow-hidden ${className || ''}`}>
      
      {/* Terminal Top Bar */}
      <div className="h-9 px-3 border-b border-zinc-800 bg-zinc-900/50 flex items-center justify-between select-none shrink-0">
        <div className="flex items-center gap-2">
          <Terminal className="w-3.5 h-3.5 text-zinc-400" />
          <span className="font-mono text-xs font-semibold text-zinc-200">
            Live Telemetry Stream
          </span>
          <span className="text-[10px] font-mono text-zinc-500">
            ({events.length} events logged)
          </span>
        </div>

        <div className="flex items-center gap-2">
          {/* Auto Scroll Toggle */}
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setAutoScroll(!autoScroll)}
            className="h-6 text-[10px] font-mono px-2 text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800"
            title={autoScroll ? "Pause auto-scroll" : "Enable auto-scroll"}
          >
            {autoScroll ? (
              <>
                <Pause className="w-3 h-3 mr-1 text-zinc-400" />
                <span>Scroll: ON</span>
              </>
            ) : (
              <>
                <Play className="w-3 h-3 mr-1 text-zinc-400" />
                <span>Scroll: PAUSED</span>
              </>
            )}
          </Button>

          {/* Copy Logs */}
          <Button
            variant="ghost"
            size="sm"
            onClick={handleCopyLogs}
            disabled={events.length === 0}
            className="h-6 text-[10px] font-mono px-2 text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800"
          >
            {copied ? (
              <>
                <Check className="w-3 h-3 mr-1 text-emerald-400" />
                <span className="text-emerald-400">Copied</span>
              </>
            ) : (
              <>
                <Copy className="w-3 h-3 mr-1" />
                <span>Copy Logs</span>
              </>
            )}
          </Button>
        </div>
      </div>

      {/* Terminal Monospaced Viewport */}
      <div 
        ref={scrollRef}
        className={`${maxHeight} overflow-y-auto p-3 font-mono text-xs leading-relaxed space-y-1.5 selection:bg-zinc-800 selection:text-zinc-100`}
      >
        {events.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center text-zinc-600 text-[11px] py-12">
            <span className="animate-pulse">Waiting for execution telemetry from simulation runner...</span>
            <span className="text-[10px] text-zinc-700 mt-1">Events streamed to /simulations/{'{simId}'}/events</span>
          </div>
        ) : (
          events.map((event, index) => (
            <div 
              key={event.id || `${event.step}_${index}`}
              className="flex items-start gap-2 hover:bg-zinc-900/40 p-0.5 rounded transition-colors text-[11px]"
            >
              {/* Timestamp */}
              <span className="text-zinc-500 shrink-0 select-none">
                [{formatTimestamp(event.timestamp)}]
              </span>

              {/* Severity Pill */}
              <span className="shrink-0">
                {getSeverityBadge(event.severity)}
              </span>

              {/* Action Step */}
              <span className="font-semibold text-zinc-300 shrink-0">
                [{event.step}]
              </span>

              {/* Message with highlighted node IDs */}
              <span className="text-zinc-300 break-words flex-1">
                {event.message}
              </span>

              {/* Target Node Tag */}
              {event.targetNodeId && (
                <span className="text-[10px] text-zinc-500 font-mono shrink-0 hidden sm:inline-block">
                  @{event.targetNodeId}
                </span>
              )}
            </div>
          ))
        )}
      </div>

      {/* Terminal Footer Status Bar */}
      <div className="h-6 px-3 border-t border-zinc-800 bg-zinc-950 flex items-center justify-between text-[10px] font-mono text-zinc-500 select-none shrink-0">
        <span>Channel: Firestore Websocket Snapshot</span>
        <span className="flex items-center gap-1.5">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
          <span>Kernel Stream Active</span>
        </span>
      </div>

    </div>
  );
}
