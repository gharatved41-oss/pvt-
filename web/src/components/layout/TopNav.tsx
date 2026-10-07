'use client';

import React from 'react';
import { Shield, Play, RotateCcw, LogOut, RefreshCw, Crown, User, ShieldAlert } from 'lucide-react';
import { useAuthStore } from '@/store/useAuthStore';
import { useTwinStore } from '@/store/useTwinStore';

export function TopNav({ onTriggerRun }: { onTriggerRun?: () => void }) {
  const { user, role, signOut } = useAuthStore();
  const { 
    simulationState, 
    simulationProgress, 
    runSimulation, 
    resetSimulation 
  } = useTwinStore();

  const isRunning = simulationState === 'RUNNING';
  const isDeveloper = role === 'developer';
  const isQuotaReached = false;

  const handleRun = () => {
    if (onTriggerRun) {
      onTriggerRun();
    } else {
      runSimulation();
    }
  };

  return (
    <header className="h-14 border-b border-zinc-800 bg-zinc-950 px-4 sm:px-6 flex items-center justify-between shrink-0 select-none">
      {/* Left: Brand Identity & Telemetry Engine Status */}
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2.5">
          <div className="p-1.5 bg-zinc-900 border border-zinc-800 rounded-md text-emerald-400">
            <Shield className="w-4 h-4" />
          </div>
          <div>
            <h1 className="text-xs font-bold text-zinc-100 tracking-tight flex items-center gap-2">
              <span>VulnTwin AI</span>
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
          <span className="text-zinc-500">STATE:</span>
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

      {/* Right: Simulation Controls, Quota, Role Badge & User Account */}
      <div className="flex items-center gap-3">
        {/* Reset Trigger */}
        <button
          type="button"
          disabled={isRunning}
          onClick={resetSimulation}
          className="px-2.5 py-1.5 text-xs font-mono border border-zinc-800 bg-zinc-900 hover:bg-zinc-850 hover:border-zinc-700 text-zinc-400 rounded-md flex items-center gap-1.5 transition-colors disabled:opacity-40"
          title="Reset digital twin to idle baseline"
        >
          <RotateCcw className="w-3.5 h-3.5" />
          <span className="hidden md:inline">Reset</span>
        </button>

        {/* Primary Action Button */}
        <button
          type="button"
          disabled={isRunning || isQuotaReached}
          onClick={handleRun}
          className={`px-3.5 py-1.5 text-xs font-semibold rounded-md flex items-center gap-2 transition-all shadow-none ${
            isQuotaReached
              ? 'bg-zinc-900 text-red-400 border border-red-900/60 cursor-not-allowed'
              : isRunning
              ? 'bg-zinc-800 text-zinc-400 cursor-not-allowed border border-zinc-700'
              : 'bg-zinc-100 hover:bg-white text-zinc-950 cursor-pointer active:scale-98'
          }`}
          title={isQuotaReached ? 'Standard Tier daily scan quota reached (3/3)' : 'Trigger AI security validation traversal'}
        >
          {isRunning ? (
            <>
              <RefreshCw className="w-3.5 h-3.5 animate-spin text-amber-400" />
              <span>Validating ({simulationProgress}%)...</span>
            </>
          ) : isQuotaReached ? (
            <>
              <ShieldAlert className="w-3.5 h-3.5 text-red-400" />
              <span>Quota Exceeded</span>
            </>
          ) : (
            <>
              <Play className="w-3.5 h-3.5 fill-current" />
              <span>Run AI Validation</span>
            </>
          )}
        </button>

        {/* User Quota & Role Badge */}
        <div className="flex items-center gap-3 pl-3 border-l border-zinc-800">
          <div className="hidden md:flex flex-col text-right">
            <span className="text-xs font-mono text-zinc-200 truncate max-w-[160px]" title={user?.email || ''}>
              {user?.email || 'analyst@enterprise.com'}
            </span>
            <div className="flex items-center justify-end gap-1.5 text-[10px] font-mono mt-0.5">
              <span className="text-zinc-500">
                {isDeveloper ? 'Access: Full Admin' : 'Access: Standard Tier'}
              </span>
            </div>
          </div>

          {/* Role Badge */}
          {isDeveloper ? (
            <span className="px-2 py-0.5 text-[10px] font-mono font-bold bg-emerald-950/90 text-emerald-400 border border-emerald-800/80 rounded tracking-wider flex items-center gap-1 shadow-2xs">
              <Crown className="w-3 h-3 text-emerald-400" />
              DEVELOPER
            </span>
          ) : (
            <span className="px-2 py-0.5 text-[10px] font-mono font-bold bg-zinc-900 text-zinc-400 border border-zinc-800 rounded tracking-wider flex items-center gap-1">
              <User className="w-3 h-3 text-zinc-500" />
              STANDARD
            </span>
          )}

          {/* Sign Out Button */}
          <button
            type="button"
            onClick={signOut}
            className="p-1.5 text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900 border border-transparent hover:border-zinc-800 rounded-md transition-colors"
            title="Sign Out of Session"
          >
            <LogOut className="w-4 h-4" />
          </button>
        </div>
      </div>
    </header>
  );
}
