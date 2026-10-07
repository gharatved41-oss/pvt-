'use client';

import React from 'react';
import { Shield, Play, RotateCcw, LogOut, RefreshCw, Crown, User, ShieldAlert } from 'lucide-react';
import { useAuthStore } from '@/store/useAuthStore';
import { useTwinStore } from '@/store/useTwinStore';

export function TopNav() {
  const { user, role, scansUsed, maxScans, signOut } = useAuthStore();
  const {
    simulationStatus,
    simulationProgress,
    runValidation,
    resetSimulation,
  } = useTwinStore();

  const isRunning = simulationStatus === 'RUNNING';
  const isDeveloper = role === 'developer';
  const isQuotaReached = !isDeveloper && scansUsed >= maxScans;

  return (
    <header className="h-14 border-b border-zinc-800 bg-zinc-950 px-4 sm:px-6 flex items-center justify-between shrink-0 select-none">
      {/* Brand Identity & Subsystem Header */}
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2.5">
          <div className="p-1.5 bg-zinc-900 border border-zinc-800 rounded-md text-emerald-400">
            <Shield className="w-4 h-4" />
          </div>
          <div>
            <h1 className="text-xs font-bold text-zinc-100 tracking-tight flex items-center gap-2 font-mono">
              <span>VulnTwin AI // Exposure Validation</span>
            </h1>
            <div className="text-[10px] font-mono text-zinc-500">
              ADVERSARIAL DIGITAL TWIN PLATFORM
            </div>
          </div>
        </div>

        {/* Live Simulation State Indicator */}
        <div className="hidden sm:flex items-center gap-2 pl-4 border-l border-zinc-800 text-xs font-mono">
          <span
            className={`w-2 h-2 rounded-full ${
              isRunning
                ? 'bg-amber-400 animate-ping'
                : simulationStatus === 'COMPLETED'
                ? 'bg-emerald-400'
                : 'bg-zinc-600'
            }`}
          />
          <span className="text-zinc-500">STATE:</span>
          <span
            className={`font-semibold ${
              isRunning
                ? 'text-amber-400'
                : simulationStatus === 'COMPLETED'
                ? 'text-emerald-400'
                : 'text-zinc-400'
            }`}
          >
            {simulationStatus}
          </span>
        </div>
      </div>

      {/* Control Triggers & User RBAC Indicators */}
      <div className="flex items-center gap-3">
        {/* Reset Button */}
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

        {/* Run Validation Action */}
        <button
          type="button"
          disabled={isRunning || isQuotaReached}
          onClick={() => runValidation()}
          className={`px-3.5 py-1.5 text-xs font-semibold rounded-md flex items-center gap-2 transition-all font-mono ${
            isQuotaReached
              ? 'bg-zinc-900 text-red-400 border border-red-900/60 cursor-not-allowed'
              : isRunning
              ? 'bg-zinc-800 text-zinc-400 cursor-not-allowed border border-zinc-700'
              : 'bg-zinc-100 hover:bg-white text-zinc-950 cursor-pointer active:scale-98'
          }`}
          title={
            isQuotaReached
              ? 'Standard Tier daily scan quota reached (3/3)'
              : 'Trigger AI security validation traversal'
          }
        >
          {isRunning ? (
            <>
              <RefreshCw className="w-3.5 h-3.5 animate-spin text-amber-400" />
              <span>Validating ({simulationProgress}%)...</span>
            </>
          ) : isQuotaReached ? (
            <>
              <ShieldAlert className="w-3.5 h-3.5 text-red-400" />
              <span>Limit Reached</span>
            </>
          ) : (
            <>
              <Play className="w-3.5 h-3.5 fill-current" />
              <span>Run AI Validation</span>
            </>
          )}
        </button>

        {/* Quota Meter & User Information */}
        <div className="flex items-center gap-3 pl-3 border-l border-zinc-800">
          <div className="hidden md:flex flex-col text-right">
            <span
              className="text-xs font-mono text-zinc-200 truncate max-w-[170px]"
              title={user?.email || ''}
            >
              {user?.email || 'analyst@enterprise.com'}
            </span>
            <div className="flex items-center justify-end gap-1.5 text-[10px] font-mono mt-0.5">
              <span className="text-zinc-500">
                {isDeveloper
                  ? 'Scans: UNLIMITED'
                  : `Scans: ${scansUsed} / ${maxScans}`}
              </span>
            </div>
          </div>

          {/* Role Badge */}
          {isDeveloper ? (
            <span className="px-2 py-0.5 text-[10px] font-mono font-bold bg-emerald-950 text-emerald-400 border border-emerald-800 rounded tracking-wider flex items-center gap-1">
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
            title="Sign Out"
          >
            <LogOut className="w-4 h-4" />
          </button>
        </div>
      </div>
    </header>
  );
}
