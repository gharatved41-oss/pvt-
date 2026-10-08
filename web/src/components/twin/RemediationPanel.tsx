"use client";

import React, { useEffect, useState } from 'react';
import { useTwinStore } from '@/store/useTwinStore';
import { getAiRemediation } from '@/lib/apiClient';

export default function RemediationPanel() {
  const { simulationStatus, activePatch, applyRemediation, nodes } = useTwinStore();
  const [aiPatch, setAiPatch] = useState<string | null>(null);
  const [isSynthesizing, setIsSynthesizing] = useState(false);

  useEffect(() => {
    if (simulationStatus === 'COMPLETED' && activePatch) {
      const fetchPatch = async () => {
        setIsSynthesizing(true);
        const targetNode = nodes.find((n) => n.id === activePatch.targetNodeId);
        const patchData = await getAiRemediation(
          targetNode?.cve || 'Generic Vulnerability',
          `Node: ${targetNode?.label || 'Unknown'} IP: ${targetNode?.ipAddress || '0.0.0.0'}`
        );
        setAiPatch(patchData.patch);
        setIsSynthesizing(false);
      };
      fetchPatch();
    } else {
      setAiPatch(null);
    }
  }, [simulationStatus, activePatch, nodes]);

  if (simulationStatus !== 'COMPLETED' || !activePatch) {
    return (
      <div className="h-full w-full bg-zinc-950 p-4 font-mono text-xs text-zinc-500 flex items-center justify-center">
        [REMEDIATION_PANEL_OFFLINE] Awaiting simulation completion.
      </div>
    );
  }

  return (
    <div className="h-full w-full bg-zinc-950 p-4 font-mono text-xs flex flex-col">
      <div className="text-zinc-300 font-bold mb-2 uppercase border-b border-zinc-800 pb-2 shrink-0">
        // AI Remediation Synthesis
      </div>
      
      <div className="flex-1 bg-zinc-900 border border-zinc-700 text-emerald-400 p-3 overflow-x-auto overflow-y-auto mb-4 whitespace-pre-wrap">
        {isSynthesizing ? "> Synthesizing deterministic patch via Gemini Flash..." : aiPatch || "> Patch unavailable."}
      </div>

      <button
        onClick={() => applyRemediation()}
        disabled={isSynthesizing || !aiPatch}
        className="w-full shrink-0 bg-zinc-200 text-zinc-950 font-bold py-2 hover:bg-white disabled:opacity-50 transition-colors uppercase rounded-none"
      >
        Execute Remediation Protocol
      </button>
    </div>
  );
}
