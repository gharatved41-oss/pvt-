'use client';

import React from 'react';
import { Layers, Server, Shield, Database, ChevronDown } from 'lucide-react';
import { useTwinStore } from '@/store/useTwinStore';
import { TEMPLATES } from '@/lib/mockData';

export function TwinSelector() {
  const { activeTemplate, loadTemplate, simulationState } = useTwinStore();
  const isRunning = simulationState === 'RUNNING';

  return (
    <div className="w-64 border-r border-zinc-800 bg-zinc-950 flex flex-col h-full shrink-0 select-none">
      {/* Header */}
      <div className="p-4 border-b border-zinc-800">
        <div className="text-[11px] uppercase font-bold tracking-wider text-zinc-400 mb-1">
          Twin Architectures
        </div>
        <div className="text-xs text-zinc-500">
          Select cloud target for exposure analysis
        </div>
      </div>

      {/* Architectures Cards */}
      <div className="p-3 flex-1 overflow-y-auto space-y-2.5">
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
              <div className="flex items-center justify-between mb-1.5">
                <span className="text-xs font-semibold text-zinc-200">
                  {template.name}
                </span>
                <span
                  className={`w-2 h-2 rounded-full ${
                    isSelected ? 'bg-emerald-400' : 'bg-zinc-700'
                  }`}
                />
              </div>

              <p className="text-[11px] text-zinc-400 line-clamp-2 leading-relaxed mb-2.5">
                {template.description}
              </p>

              <div className="flex items-center justify-between text-[10px] font-mono text-zinc-500 border-t border-zinc-800/60 pt-2">
                <span className="flex items-center gap-1">
                  <Server className="w-3 h-3" />
                  {template.initialNodes.length} Assets
                </span>
                <span className="flex items-center gap-1 text-zinc-400">
                  <Layers className="w-3 h-3" />
                  {template.edges.length} Interconnects
                </span>
              </div>
            </button>
          );
        })}

        {/* Selected Architecture Forensics Metadata */}
        <div className="mt-4 border border-zinc-800 rounded-md p-3 bg-zinc-900/20 space-y-2 font-mono text-[11px]">
          <div className="text-[10px] uppercase font-bold tracking-wider text-zinc-500">
            Topology Forensics
          </div>
          <div className="space-y-1.5">
            <div className="flex justify-between text-zinc-400">
              <span>Perimeter:</span>
              <span className="text-amber-400">{activeTemplate.initialNodes[0]?.name}</span>
            </div>
            <div className="flex justify-between text-zinc-400">
              <span>Critical Target:</span>
              <span className="text-red-400">{activeTemplate.initialNodes[activeTemplate.initialNodes.length - 1]?.name}</span>
            </div>
            <div className="flex justify-between text-zinc-400">
              <span>Threat Spec:</span>
              <span className="text-zinc-300">{activeTemplate.patch.cve}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Footer Info */}
      <div className="p-3 border-t border-zinc-800 text-[10px] font-mono text-zinc-500 flex items-center justify-between">
        <span>ENGINE: CTEM_AEV</span>
        <span className="text-emerald-500">ISOLATED</span>
      </div>
    </div>
  );
}
