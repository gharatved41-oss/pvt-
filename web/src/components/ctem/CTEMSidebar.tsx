import React from 'react';
import { Layers, Shield, Database, Server, Cpu, CheckCircle2, AlertOctagon } from 'lucide-react';
import { useTwinStore } from '@/store/useTwinStore';
import { TEMPLATES } from '@/lib/mockData';

export function CTEMSidebar() {
  const { activeTemplate, loadTemplate, simulationState } = useTwinStore();

  const isRunning = simulationState === 'RUNNING';

  return (
    <aside className="w-64 border-r border-zinc-800 bg-zinc-950 flex flex-col h-full shrink-0 select-none">
      {/* Brand Header */}
      <div className="p-4 border-b border-zinc-800 flex items-center gap-2.5">
        <div className="p-1.5 bg-zinc-900 border border-zinc-700 rounded-md text-zinc-100">
          <Shield className="w-4 h-4 text-emerald-400" />
        </div>
        <div>
          <div className="text-xs font-bold tracking-tight text-zinc-100">VulnTwin AI</div>
          <div className="text-[10px] font-mono text-zinc-500">CTEM SIMULATOR • v3.0</div>
        </div>
      </div>

      {/* Preloaded Templates Section */}
      <div className="p-4 flex-1 overflow-y-auto space-y-4">
        <div>
          <div className="text-[11px] font-semibold uppercase tracking-wider text-zinc-400 mb-2 flex items-center justify-between">
            <span>Preloaded Environments</span>
            <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-zinc-900 border border-zinc-800 text-zinc-400">
              {Object.keys(TEMPLATES).length} Available
            </span>
          </div>

          <div className="space-y-2">
            {Object.values(TEMPLATES).map((template) => {
              const isSelected = activeTemplate.id === template.id;

              return (
                <button
                  key={template.id}
                  type="button"
                  disabled={isRunning}
                  onClick={() => loadTemplate(template.id)}
                  className={`w-full text-left p-3 rounded-md border transition-all ${
                    isSelected
                      ? 'border-zinc-400 bg-zinc-900/90 text-zinc-100 ring-1 ring-zinc-500/20'
                      : 'border-zinc-800/80 bg-zinc-900/30 text-zinc-400 hover:border-zinc-700 hover:bg-zinc-900/60'
                  } ${isRunning ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'}`}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs font-semibold text-zinc-200">
                      {template.name}
                    </span>
                    <span className={`w-1.5 h-1.5 rounded-full ${isSelected ? 'bg-emerald-400' : 'bg-zinc-600'}`} />
                  </div>

                  <p className="text-[11px] text-zinc-400 line-clamp-2 leading-relaxed mb-2">
                    {template.description}
                  </p>

                  <div className="flex items-center gap-2 text-[10px] font-mono text-zinc-500 border-t border-zinc-800/60 pt-2">
                    <span className="flex items-center gap-1">
                      <Server className="w-3 h-3" />
                      {template.initialNodes.length} nodes
                    </span>
                    <span>•</span>
                    <span className="flex items-center gap-1">
                      <Layers className="w-3 h-3" />
                      {template.edges.length} edges
                    </span>
                  </div>
                </button>
              );
            })}
          </div>
        </div>

        {/* Selected Environment Stats */}
        <div className="border border-zinc-800 rounded-md p-3 bg-zinc-900/20 space-y-2">
          <div className="text-[10px] uppercase font-bold tracking-wider text-zinc-400">
            Topology Metadata
          </div>
          <div className="space-y-1.5 text-xs font-mono">
            <div className="flex justify-between text-zinc-400">
              <span>Category:</span>
              <span className="text-zinc-200 truncate max-w-[120px] text-right" title={activeTemplate.category}>
                {activeTemplate.id === 'ecommerce' ? 'E-Commerce' : 'HIPAA PACS'}
              </span>
            </div>
            <div className="flex justify-between text-zinc-400">
              <span>Ingress Vector:</span>
              <span className="text-amber-400">{activeTemplate.initialNodes[0]?.name}</span>
            </div>
            <div className="flex justify-between text-zinc-400">
              <span>Primary Crown Jewel:</span>
              <span className="text-red-400">{activeTemplate.initialNodes[activeTemplate.initialNodes.length - 1]?.name}</span>
            </div>
          </div>
        </div>

        {/* System Attestation */}
        <div className="p-3 bg-zinc-900/50 border border-zinc-800/80 rounded-md text-[11px] text-zinc-400 space-y-1">
          <div className="font-semibold text-zinc-300 flex items-center gap-1">
            <CheckCircle2 className="w-3 h-3 text-emerald-400" />
            <span>Standalone CTEM Engine</span>
          </div>
          <p className="text-[10px] text-zinc-500 leading-normal">
            Zero cloud backend dependencies. Synthetic state managed locally via Zustand.
          </p>
        </div>
      </div>

      {/* Sidebar Footer */}
      <div className="p-3 border-t border-zinc-800 text-[10px] font-mono text-zinc-500 flex items-center justify-between">
        <span>STATE: CLIENT_ISOLATED</span>
        <span className="text-emerald-500">READY</span>
      </div>
    </aside>
  );
}
