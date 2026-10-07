'use client';

import React from 'react';
import { ShieldCheck, ShieldAlert, Wrench, CheckCircle2 } from 'lucide-react';
import { useTwinEngine } from '@/store/useTwinEngine';

export function RemediationPanel() {
  const { nodes, edges, applyPatch, blastRadius } = useTwinEngine();

  // Check if any database node is currently compromised
  const compromisedDb = nodes.find(
    (node) => node.type === 'database' && node.status === 'compromised'
  );
  const isPatched = nodes.some(
    (node) => node.type === 'database' && node.status === 'patched'
  );

  // Database ingress edge (defaults to edge-app-db)
  const dbEdge = edges.find(
    (edge) => edge.target === (compromisedDb?.id || 'internal-db-1')
  );

  return (
    <div className="border border-zinc-800 bg-zinc-950 rounded-none p-4 font-mono text-xs select-none space-y-3">
      {/* Header */}
      <div className="flex items-center justify-between pb-2 border-b border-zinc-900">
        <div className="flex items-center gap-2 text-zinc-100 font-bold uppercase tracking-wider">
          <ShieldCheck className="w-4 h-4 text-emerald-400" />
          <span>REMEDIATION_ATTESTATION_PANEL</span>
        </div>
        <span className="text-[10px] text-zinc-500 uppercase">
          {isPatched ? 'STATUS: SECURED' : compromisedDb ? 'STATUS: AT_RISK' : 'STATUS: NOMINAL'}
        </span>
      </div>

      {/* Target Status Information */}
      <div className="text-[11px] text-zinc-400 space-y-1">
        <div className="flex justify-between">
          <span className="text-zinc-500">EXPOSURE ATTRIBUTION:</span>
          <span className={compromisedDb ? 'text-red-400 font-bold' : 'text-zinc-200'}>
            {compromisedDb ? 'CRITICAL_LATERAL_PATHWAY' : isPatched ? 'PATHWAY_SEVERED' : 'NO_BREACH_DETECTED'}
          </span>
        </div>
        <div className="flex justify-between">
          <span className="text-zinc-500">DATABASE TIER:</span>
          <span className="text-zinc-200">PostgreSQL (:5432)</span>
        </div>
        <div className="flex justify-between">
          <span className="text-zinc-500">CURRENT BLAST RADIUS:</span>
          <span className={blastRadius > 0 ? 'text-red-400 font-bold' : 'text-emerald-400'}>
            {blastRadius} / 100
          </span>
        </div>
      </div>

      {/* Conditional Patch Trigger: Revealed when database is compromised */}
      {compromisedDb && (
        <div className="pt-2 border-t border-zinc-900 space-y-2">
          <div className="p-2.5 border border-red-900/60 bg-red-950/20 text-red-300 text-[11px] flex items-start gap-2">
            <ShieldAlert className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
            <div>
              <div className="font-bold text-red-400 uppercase">CRITICAL_EXPOSURE_DETECTED</div>
              <div>Lateral pathway traversed into production customer database records.</div>
            </div>
          </div>

          <button
            type="button"
            onClick={() => applyPatch(dbEdge?.id)}
            className="w-full bg-emerald-500 hover:bg-emerald-400 text-zinc-950 font-bold text-xs py-2 px-3 rounded-none uppercase tracking-wider flex items-center justify-center gap-2 transition-colors cursor-pointer"
          >
            <Wrench className="w-3.5 h-3.5" />
            <span>Apply Network Segmentation (Block Port 5432)</span>
          </button>
        </div>
      )}

      {/* Success Notification after Patch Applied */}
      {isPatched && !compromisedDb && (
        <div className="pt-2 border-t border-zinc-900">
          <div className="p-2.5 border border-emerald-800 bg-emerald-950/20 text-emerald-300 text-[11px] flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            <span>Network segmentation enforced. Ingress to Port 5432 blocked.</span>
          </div>
        </div>
      )}
    </div>
  );
}
