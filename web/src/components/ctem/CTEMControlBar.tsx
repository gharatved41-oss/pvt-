'use client';

import React from 'react';
import { Play, RotateCcw, ShieldAlert, CheckCircle2, RefreshCw, Activity } from 'lucide-react';
import { useTwinStore } from '@/store/useTwinStore';

export function CTEMControlBar() {
  const {
    activeTemplate,
    simulationState,
    simulationProgress,
    runSimulation,
    resetSimulation,
  } = useTwinStore();

  const isRunning = simulationState === 'RUNNING';

  return (
    <header className="h-14 border-b border-zinc-800 bg-zinc-950 px-4 sm:px-6 flex items-center justify-between shrink-0 select-none">
      {/* Left: Active Topology Name & Status Badge */}
      <div className="flex items-center gap-3">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-sm font-semibold text-zinc-100">
              {activeTemplate.name}
            </h1>
            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-zinc-900 border border-zinc-800 text-zinc-400">
              {activeTemplate.category}
            </span>
          </div>
        </div>

        {/* Status Badge */}
        <div className="hidden md:flex items-center gap-1.5 pl-3 border-l border-zinc-800 text-xs font-mono">
          <span
            className={`w-2 h-2 rounded-full ${
              simulationState === 'RUNNING'
                ? 'bg-amber-400 animate-ping'
                : simulationState === 'COMPLETED'
                ? 'bg-emerald-400'
                : 'bg-zinc-600'
            }`}
          />
          <span className="text-zinc-400">STATE:</span>
          <span
            className={`font-semibold ${
              simulationState === 'RUNNING'
                ? 'text-amber-400'
                : simulationState === 'COMPLETED'
                ? 'text-emerald-400'
                : 'text-zinc-400'
            }`}
          >
            {simulationState}
          </span>
        </div>
      </div>

      {/* Right: Actions */}
      <div className="flex items-center gap-2 sm:gap-3">
        {/* Reset Simulation Baseline */}
        <button
          type="button"
          disabled={isRunning}
          onClick={resetSimulation}
          className="px-3 py-1.5 text-xs font-medium border border-zinc-800 bg-zinc-900 hover:bg-zinc-850 hover:border-zinc-700 text-zinc-300 rounded-md flex items-center gap-1.5 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
          title="Reset topology to idle baseline"
        >
          <RotateCcw className="w-3.5 h-3.5" />
          <span className="hidden sm:inline">Reset</span>
        </button>

        {/* Primary Action: Run AI Validation */}
        <button
          type="button"
          disabled={isRunning}
          onClick={runSimulation}
          className={`px-4 py-1.5 text-xs font-semibold rounded-md flex items-center gap-2 transition-all shadow-none ${
            isRunning
              ? 'bg-zinc-800 text-zinc-400 cursor-not-allowed border border-zinc-700'
              : 'bg-zinc-100 hover:bg-white text-zinc-950 cursor-pointer active:scale-98'
          }`}
        >
          {isRunning ? (
            <>
              <RefreshCw className="w-3.5 h-3.5 animate-spin text-amber-400" />
              <span>Validating ({simulationProgress}%)...</span>
            </>
          ) : (
            <>
              <Play className="w-3.5 h-3.5 fill-current" />
              <span>Run AI Validation</span>
            </>
          )}
        </button>
      </div>
    </header>
  );
}
