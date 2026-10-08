"use client";

import React from 'react';
import { useTwinStore } from '@/store/useTwinStore';
import { ShieldAlert, ShieldCheck, XCircle, Shield } from 'lucide-react';

export function NodeDetailsPanel() {
  const { selectedNode, nodes, isolateNode, selectNode } = useTwinStore();

  const selectedNodeData = selectedNode ? nodes.find((n) => n.id === selectedNode) : null;

  if (!selectedNodeData) {
    return (
      <div className="h-full w-full bg-zinc-950 border-l border-zinc-800 flex items-center justify-center p-6 text-center select-none">
        <div className="flex flex-col items-center gap-3 text-zinc-500">
          <Shield className="w-8 h-8 opacity-20" />
          <p className="font-mono text-xs uppercase tracking-widest leading-relaxed">
            Select a node on the canvas<br/>to view real-time telemetry.
          </p>
        </div>
      </div>
    );
  }

  const { id, label, ipAddress, status, services = [], cve, cvss } = selectedNodeData;

  let StatusIcon = ShieldCheck;
  let statusColor = 'text-emerald-500';
  let badgeClass = 'bg-emerald-950 border-emerald-800 text-emerald-400';

  if (status === 'compromised') {
    StatusIcon = ShieldAlert;
    statusColor = 'text-red-500';
    badgeClass = 'bg-red-950 border-red-800 text-red-400';
  } else if (status === 'probing') {
    StatusIcon = ShieldAlert;
    statusColor = 'text-amber-500';
    badgeClass = 'bg-amber-950 border-amber-800 text-amber-400';
  }

  return (
    <div className="h-full w-full bg-zinc-950 border-l border-zinc-800 flex flex-col font-mono text-xs select-none">
      {/* Header */}
      <div className="p-4 border-b border-zinc-800 flex items-center justify-between bg-zinc-900/40">
        <div className="flex items-center gap-2">
          <StatusIcon className={`w-4 h-4 ${statusColor}`} />
          <span className="font-bold text-zinc-200 uppercase tracking-widest">{label}</span>
        </div>
        <button 
          onClick={() => selectNode(null)}
          className="text-zinc-500 hover:text-zinc-300 transition-colors"
          title="Deselect Node"
        >
          <XCircle className="w-4 h-4" />
        </button>
      </div>

      <div className="flex-1 overflow-y-auto p-4 space-y-6">
        
        {/* Node Identity */}
        <div>
          <div className="text-[10px] text-zinc-500 uppercase tracking-widest mb-2 font-bold">Network Identity</div>
          <div className="grid grid-cols-2 gap-2">
            <div className="bg-zinc-900 border border-zinc-800 p-2">
              <span className="text-zinc-500 text-[10px] block mb-1 uppercase">IP Address</span>
              <span className="text-zinc-200">{ipAddress || '0.0.0.0'}</span>
            </div>
            <div className="bg-zinc-900 border border-zinc-800 p-2">
              <span className="text-zinc-500 text-[10px] block mb-1 uppercase">Status</span>
              <span className={`px-1.5 py-0.5 border inline-block text-[10px] uppercase tracking-wider ${badgeClass}`}>
                {status}
              </span>
            </div>
          </div>
        </div>

        {/* Vulnerability Context */}
        {cve && (
          <div>
            <div className="text-[10px] text-zinc-500 uppercase tracking-widest mb-2 font-bold">Threat Intelligence</div>
            <div className="bg-zinc-900 border border-zinc-800 p-3 space-y-2">
              <div className="flex justify-between items-center border-b border-zinc-800 pb-2">
                <span className="text-zinc-400">CVE ID</span>
                <span className="text-red-400 font-bold">{cve}</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-zinc-400">CVSS Base Score</span>
                <span className="text-red-400 font-bold">{cvss || 'N/A'}</span>
              </div>
            </div>
          </div>
        )}

        {/* Active Services */}
        <div>
          <div className="text-[10px] text-zinc-500 uppercase tracking-widest mb-2 font-bold">Open Ports & Services</div>
          {services.length > 0 ? (
            <div className="border border-zinc-800 divide-y divide-zinc-800">
              {services.map((svc: { port: number; serviceName: string; vulnerable?: boolean }, idx: number) => (
                <div key={idx} className="flex justify-between items-center p-2 bg-zinc-900/50">
                  <div className="flex items-center gap-2">
                    <span className="text-blue-400 font-bold w-12">{svc.port}</span>
                    <span className="text-zinc-300 truncate">{svc.serviceName}</span>
                  </div>
                  {svc.vulnerable && (
                    <span className="text-[9px] px-1 bg-red-950 text-red-500 border border-red-900 uppercase">Vuln</span>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <div className="text-zinc-500 italic p-3 border border-zinc-800 bg-zinc-900/30 text-center">
              No externally exposed services
            </div>
          )}
        </div>
      </div>

      {/* Action Footer */}
      <div className="p-4 border-t border-zinc-800 bg-zinc-900/40 shrink-0">
        <button
          onClick={() => isolateNode(id)}
          disabled={status === 'patched' || status === 'healthy'}
          className="w-full py-2.5 px-4 flex items-center justify-center gap-2 font-bold uppercase tracking-widest transition-colors disabled:opacity-50 disabled:cursor-not-allowed bg-blue-600 hover:bg-blue-500 text-white"
        >
          <ShieldCheck className="w-4 h-4" />
          <span>Isolate Node</span>
        </button>
      </div>
    </div>
  );
}
