'use client';

import React, { useState } from 'react';
import { ShieldCheck, Check, Copy, Wrench, AlertTriangle, FileCode } from 'lucide-react';
import { useTwinStore } from '@/store/useTwinStore';

export function CTEMPatchPanel() {
  const { activePatch, isPatchApplied, applyPatch, simulationState } = useTwinStore();
  const [copied, setCopied] = useState(false);

  if (simulationState !== 'COMPLETED' || !activePatch) {
    return null;
  }

  const handleCopy = () => {
    navigator.clipboard.writeText(activePatch.diffSnippet);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="border border-zinc-800 bg-zinc-900/90 rounded-md p-4 mb-4 select-none animate-in fade-in slide-in-from-top-2 duration-200">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-zinc-800">
        <div className="flex items-center gap-2.5">
          <div className="p-1.5 rounded bg-emerald-950/80 border border-emerald-800/80 text-emerald-400">
            <ShieldCheck className="w-4 h-4" />
          </div>
          <div>
            <div className="text-xs font-semibold text-zinc-100 flex items-center gap-2">
              <span>{activePatch.title}</span>
              <span className="px-1.5 py-0.5 text-[9px] font-mono bg-zinc-800 border border-zinc-700 text-zinc-300 rounded">
                {activePatch.cve}
              </span>
            </div>
            <div className="text-[11px] text-zinc-400 mt-0.5">
              Target Asset: <span className="font-mono text-zinc-200">{activePatch.targetNodeId}</span> • Action: <span className="font-mono text-emerald-400">{activePatch.machineAction}</span>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={handleCopy}
            className="px-2.5 py-1 text-xs border border-zinc-700 hover:border-zinc-600 bg-zinc-800 hover:bg-zinc-750 text-zinc-200 rounded-md flex items-center gap-1.5 transition-colors"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copied ? 'Copied' : 'Copy Diff'}</span>
          </button>

          <button
            type="button"
            disabled={isPatchApplied}
            onClick={applyPatch}
            className={`px-3 py-1 text-xs font-semibold rounded-md flex items-center gap-1.5 transition-all ${
              isPatchApplied
                ? 'bg-emerald-950 border border-emerald-800 text-emerald-400 cursor-default'
                : 'bg-emerald-500 hover:bg-emerald-400 text-zinc-950 shadow-sm cursor-pointer'
            }`}
          >
            {isPatchApplied ? (
              <>
                <Check className="w-3.5 h-3.5" />
                <span>Patch Verified on Twin</span>
              </>
            ) : (
              <>
                <Wrench className="w-3.5 h-3.5" />
                <span>Apply Patch to Sandbox</span>
              </>
            )}
          </button>
        </div>
      </div>

      <div className="mt-3 grid grid-cols-1 lg:grid-cols-2 gap-3">
        {/* Human Explanation */}
        <div className="bg-zinc-950/60 border border-zinc-800/80 rounded p-3">
          <div className="text-[10px] font-mono uppercase tracking-wider text-zinc-400 mb-1">
            AEV Security Remediation Rationale
          </div>
          <p className="text-xs text-zinc-300 leading-relaxed">
            {activePatch.humanExplanation}
          </p>
        </div>

        {/* Machine Action Code Diff */}
        <div className="bg-zinc-950 border border-zinc-800 rounded p-3 font-mono text-[11px] overflow-x-auto">
          <div className="text-[10px] uppercase tracking-wider text-zinc-500 mb-1 flex items-center justify-between">
            <span>Configuration Patch Preview</span>
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
