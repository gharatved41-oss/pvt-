'use client';

import React, { useState } from 'react';
import { Crown, Plus, Trash2, ShieldAlert, ShieldCheck, Cpu, Sliders, ChevronDown, ChevronUp } from 'lucide-react';
import { useTwinStore } from '@/store/useTwinStore';
import { useAuthStore } from '@/store/useAuthStore';

export function AdminControls() {
  const { injectNode, clearLogs, forceAllStatus, nodes } = useTwinStore();
  const [isOpen, setIsOpen] = useState(true);

  return (
    <div className="border border-emerald-900/60 bg-emerald-950/20 rounded-md p-3 select-none text-xs font-mono">
      <div className="flex items-center justify-between pb-2 border-b border-emerald-900/40">
        <div className="flex items-center gap-2 text-emerald-400 font-semibold">
          <Crown className="w-4 h-4 text-emerald-400" />
          <span className="tracking-wider uppercase">Developer Admin Controls</span>
          <span className="text-[10px] px-1.5 py-0.2 rounded bg-emerald-950 border border-emerald-800 text-emerald-300">
            UNLIMITED QUOTA
          </span>
        </div>

        <button
          type="button"
          onClick={() => setIsOpen(!isOpen)}
          className="p-1 text-emerald-400/80 hover:text-emerald-300 hover:bg-emerald-950/50 rounded transition-colors"
        >
          {isOpen ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
        </button>
      </div>

      {isOpen && (
        <div className="pt-2.5 space-y-2.5">
          <div className="text-[11px] text-zinc-400 font-sans">
            You have full administrative clearance. You can inject custom nodes, manipulate topology states, and bypass simulation limits.
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {/* Inject Node */}
            <button
              type="button"
              onClick={() => injectNode()}
              className="px-2.5 py-1 bg-zinc-900 hover:bg-zinc-800 border border-zinc-700 text-zinc-200 rounded flex items-center gap-1.5 transition-colors"
            >
              <Plus className="w-3.5 h-3.5 text-emerald-400" />
              <span>Inject Node</span>
            </button>

            {/* Clear Logs */}
            <button
              type="button"
              onClick={clearLogs}
              className="px-2.5 py-1 bg-zinc-900 hover:bg-zinc-800 border border-zinc-700 text-zinc-200 rounded flex items-center gap-1.5 transition-colors"
            >
              <Trash2 className="w-3.5 h-3.5 text-zinc-400" />
              <span>Clear Console</span>
            </button>

            {/* Force Compromised */}
            <button
              type="button"
              onClick={() => forceAllStatus('compromised')}
              className="px-2.5 py-1 bg-red-950/50 hover:bg-red-950 border border-red-800/80 text-red-300 rounded flex items-center gap-1.5 transition-colors"
            >
              <ShieldAlert className="w-3.5 h-3.5 text-red-400" />
              <span>Force Compromised</span>
            </button>

            {/* Force Patched */}
            <button
              type="button"
              onClick={() => forceAllStatus('patched')}
              className="px-2.5 py-1 bg-emerald-950/50 hover:bg-emerald-950 border border-emerald-800/80 text-emerald-300 rounded flex items-center gap-1.5 transition-colors"
            >
              <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
              <span>Force Patched</span>
            </button>

            {/* Reset All to Idle */}
            <button
              type="button"
              onClick={() => forceAllStatus('healthy')}
              className="px-2.5 py-1 bg-zinc-900 hover:bg-zinc-800 border border-zinc-700 text-zinc-400 rounded transition-colors"
            >
              <span>Reset Statuses</span>
            </button>

            {/* Reset Quotas */}
            <button
              type="button"
              onClick={() => useAuthStore.getState().resetScans()}
              className="px-2.5 py-1 bg-blue-950/50 hover:bg-blue-950 border border-blue-800/80 text-blue-300 rounded transition-colors"
            >
              <span>Reset Quota (0/3)</span>
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
