"use client";

import React from 'react';
import { useTwinStore } from '@/store/useTwinStore';

export default function RemediationPanel() {
  const { simulationStatus, remediationPatch, applyRemediation } = useTwinStore();

  const renderContent = () => {
    if (simulationStatus === 'IDLE' || simulationStatus === 'PATCHED') {
      return (
        <div className="h-full w-full flex items-center justify-center text-center text-zinc-500">
          [REMEDIATION_PANEL_STANDBY]<br/>Awaiting adversarial validation...
        </div>
      );
    }

    if (simulationStatus === 'SCANNING' || (simulationStatus === 'COMPROMISED' && !remediationPatch)) {
      return (
        <div className="flex flex-col gap-2 p-3">
          <div className="animate-pulse bg-zinc-800 h-4 w-3/4 rounded-sm" />
          <div className="animate-pulse bg-zinc-800 h-4 w-1/2 rounded-sm" />
          <div className="animate-pulse bg-zinc-800 h-4 w-5/6 rounded-sm" />
        </div>
      );
    }

    if (simulationStatus === 'COMPROMISED' && remediationPatch) {
      return (
        <pre className="h-full overflow-x-auto overflow-y-auto p-3">
          <code className="font-mono text-[10px] text-emerald-400 whitespace-pre-wrap">
            {remediationPatch}
          </code>
        </pre>
      );
    }

    return null;
  };

  return (
    <div className="h-full w-full bg-zinc-950 p-4 font-mono text-xs flex flex-col">
      <div className="text-zinc-300 font-bold mb-2 uppercase border-b border-zinc-800 pb-2 shrink-0">
        // AI Remediation Synthesis
      </div>
      
      <div className="flex-1 bg-zinc-900 border border-zinc-700 overflow-hidden mb-4">
        {renderContent()}
      </div>

      <button
        onClick={() => applyRemediation()}
        disabled={simulationStatus !== 'COMPROMISED' || !remediationPatch}
        className="w-full shrink-0 bg-emerald-950 border border-emerald-800 text-emerald-400 font-bold py-2 hover:bg-emerald-900 hover:text-white disabled:opacity-50 disabled:cursor-not-allowed transition-colors uppercase rounded-none"
      >
        Apply Patch & Re-Test
      </button>
    </div>
  );
}
