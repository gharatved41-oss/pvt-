'use client';

import React, { useState } from 'react';
import { ShieldCheck, Check, Copy, Wrench, ShieldAlert, CheckCircle2 } from 'lucide-react';
import { useTwinStore } from '@/store/useTwinStore';

export function RemediationPanel() {
  const {
    activePatch,
    isPatchApplied,
    applyRemediation,
    simulationStatus,
    remediationStatus,
    nodes,
    riskScore,
  } = useTwinStore();
  const [copied, setCopied] = useState(false);

  if (simulationStatus !== 'COMPLETED' || !activePatch) {
    return null;
  }

  const compromisedNodes = nodes.filter((n) => n.status === 'compromised');
  const patchedNodes = nodes.filter((n) => n.status === 'patched');

  const handleCopyDiff = () => {
    navigator.clipboard.writeText(activePatch.diffSnippet);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="border border-zinc-800 bg-zinc-900/90 rounded-md p-4 font-mono select-none animate-in fade-in slide-in-from-top-2 duration-200">
      {/* Header Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-zinc-800">
        <div className="flex items-center gap-2.5">
          <div className="p-1.5 rounded bg-emerald-950 border border-emerald-800 text-emerald-400">
            <ShieldCheck className="w-4 h-4" />
          </div>
          <div>
            <div className="text-xs font-semibold text-zinc-100 flex items-center gap-2">
              <span>{activePatch.title}</span>
              <span className="px-1.5 py-0.5 text-[9px] bg-zinc-800 border border-zinc-700 text-zinc-300 rounded">
                {activePatch.cve}
              </span>
            </div>
            <div className="text-[11px] text-zinc-400 mt-0.5">
              Target Asset: <span className="text-zinc-200">{activePatch.targetNodeId}</span> • Risk Score:{' '}
              <span className="text-red-400 font-bold">{riskScore}/100</span>
            </div>
          </div>
        </div>

        {/* Action Triggers */}
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={handleCopyDiff}
            className="px-2.5 py-1 text-xs border border-zinc-700 hover:border-zinc-600 bg-zinc-800 hover:bg-zinc-750 text-zinc-200 rounded-md flex items-center gap-1.5 transition-colors"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copied ? 'Copied' : 'Copy Diff'}</span>
          </button>

          <button
            type="button"
            disabled={isPatchApplied}
            onClick={() => applyRemediation(activePatch.targetEdgeId)}
            className={`px-3 py-1 text-xs font-semibold rounded-md flex items-center gap-1.5 transition-all ${
              isPatchApplied
                ? 'bg-emerald-950 border border-emerald-800 text-emerald-400 cursor-default'
                : 'bg-emerald-500 hover:bg-emerald-400 text-zinc-950 shadow-sm cursor-pointer'
            }`}
          >
            {isPatchApplied ? (
              <>
                <CheckCircle2 className="w-3.5 h-3.5" />
                <span>Patch Verified on Twin</span>
              </>
            ) : (
              <>
                <Wrench className="w-3.5 h-3.5" />
                <span>Apply Patch to Twin</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Compromised Assets & Verification Status */}
      <div className="mt-3 grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
        {/* Validated Attack Path & Exposure Summary */}
        <div className="bg-zinc-950/70 border border-zinc-800 rounded p-3 space-y-2">
          <div className="text-[10px] uppercase tracking-wider text-zinc-400 flex items-center justify-between">
            <span>Validated Exposure Path</span>
            {remediationStatus === 'VERIFIED_SAFE' ? (
              <span className="text-emerald-400 font-bold flex items-center gap-1">
                <Check className="w-3 h-3" />
                VERIFIED_SAFE
              </span>
            ) : (
              <span className="text-red-400 font-bold flex items-center gap-1">
                <ShieldAlert className="w-3 h-3" />
                ACTIVE_BREACH
              </span>
            )}
          </div>

          <div className="text-[11px] text-zinc-300">
            {remediationStatus === 'VERIFIED_SAFE' ? (
              <p className="text-emerald-300">
                All lateral traversal paths have been severed. Re-test simulation confirmed 0 reachable high-value assets.
              </p>
            ) : (
              <p className="text-zinc-300">
                Identified reachable choke point into internal database tier ({compromisedNodes.length} assets compromised).
              </p>
            )}
          </div>

          <div className="text-[10px] text-zinc-500">
            Machine Action: <span className="text-emerald-400 break-all">{activePatch.machineAction}</span>
          </div>
        </div>

        {/* Patch Unified Diff */}
        <div className="bg-zinc-950 border border-zinc-800 rounded p-3 overflow-x-auto text-[11px]">
          <div className="text-[10px] uppercase tracking-wider text-zinc-500 mb-1 flex items-center justify-between">
            <span>Security Rule Diff</span>
            <span className="text-zinc-600">UNIFIED DIFF</span>
          </div>
          <pre className="text-zinc-300 whitespace-pre leading-snug">
            {activePatch.diffSnippet}
          </pre>
        </div>
      </div>
    </div>
  );
}
