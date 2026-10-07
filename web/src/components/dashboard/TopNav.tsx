'use client';

import React from 'react';
import { Shield, Play, RotateCcw, LogOut, User as UserIcon, RefreshCw } from 'lucide-react';
import { useAuthStore } from '@/store/useAuthStore';
import { useTwinStore } from '@/store/useTwinStore';

export function TopNav() {
  const { user, signOut: logout } = useAuthStore();
  const { 
    simulationState, 
    simulationProgress, 
    runSimulation, 
    resetSimulation 
  } = useTwinStore();

  const isRunning = simulationState === 'RUNNING';

  return (
    <header className="h-14 border-b border-zinc-800 bg-zinc-950 px-4 sm:px-6 flex items-center justify-between shrink-0 select-none">
      {/* Left: Brand Identity & Active Simulation Telemetry */}
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2.5">
          <div className="p-1.5 bg-zinc-900 border border-zinc-800 rounded-md text-emerald-400">
            <Shield className="w-4 h-4" />
          </div>
          <div>
            <h1 className="text-xs font-bold text-zinc-100 tracking-tight">
              VulnTwin AI
            </h1>
            <div className="text-[10px] font-mono text-zinc-500">
              ADVERSARIAL EXPOSURE VALIDATION
            </div>
          </div>
        </div>

        {/* Status Indicator */}
        <div className="hidden sm:flex items-center gap-2 pl-4 border-l border-zinc-800 text-xs font-mono">
          <span
            className={`w-2 h-2 rounded-full ${
              simulationState === 'RUNNING'
                ? 'bg-amber-400 animate-ping'
                : simulationState === 'COMPLETED'
                ? 'bg-emerald-400'
                : 'bg-zinc-600'
            }`}
          />
          <span className="text-zinc-500">ENGINE:</span>
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

      {/* Center / Right: Execution Controls & User Account */}
      <div className="flex items-center gap-3">
        {/* Reset Button */}
        <button
          type="button"
          disabled={isRunning}
          onClick={resetSimulation}
          className="px-2.5 py-1.5 text-xs font-mono border border-zinc-800 bg-zinc-900 hover:bg-zinc-850 hover:border-zinc-700 text-zinc-400 rounded-md flex items-center gap-1.5 transition-colors disabled:opacity-40"
          title="Reset digital twin state to baseline"
        >
          <RotateCcw className="w-3.5 h-3.5" />
          <span className="hidden md:inline">Reset</span>
        </button>

        {/* Primary Simulation Run Trigger */}
        <button
          type="button"
          disabled={isRunning}
          onClick={runSimulation}
          className={`px-3.5 py-1.5 text-xs font-semibold rounded-md flex items-center gap-2 transition-all shadow-none ${
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

        {/* User Identity & Logout Button */}
        <div className="flex items-center gap-2 pl-3 border-l border-zinc-800">
          <div className="hidden lg:flex flex-col text-right">
            <span className="text-xs font-mono text-zinc-200 truncate max-w-[180px]">
              {user?.email || 'analyst@corp-sec.com'}
            </span>
            <span className="text-[10px] text-zinc-500 font-mono">
              SECURITY ANALYST
            </span>
          </div>

          <button
            type="button"
            onClick={logout}
            className="p-1.5 text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900 border border-transparent hover:border-zinc-800 rounded-md transition-colors"
            title="Sign Out"
          >
            <LogOut className="w-4 h-4" />
          </button>
        </div>
      </div>
    </header>
  );
}
