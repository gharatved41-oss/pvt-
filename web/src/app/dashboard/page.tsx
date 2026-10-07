'use client';

import React from 'react';
import { Shield, Play, RotateCcw, LogOut, RefreshCw, Crown, User, ShieldAlert } from 'lucide-react';
import { useAuthStore } from '@/store/useAuthStore';
import { useTwinEngine } from '@/store/useTwinEngine';
import { AuthModal } from '@/components/auth/AuthModal';
import { GraphCanvas } from '@/components/twin/GraphCanvas';
import { TerminalFeed } from '@/components/twin/TerminalFeed';
import { RemediationPanel } from '@/components/twin/RemediationPanel';

export default function DashboardPage() {
  const { user, role, scansUsed, maxScans, signOut } = useAuthStore();
  const { isSimulating, blastRadius, startSimulation, resetSimulation } = useTwinEngine();
  const [authModalOpen, setAuthModalOpen] = React.useState(false);

  const isDeveloper = role === 'developer';
  const isQuotaReached = !isDeveloper && scansUsed >= maxScans;

  // Unauthenticated Guard
  if (!user) {
    return (
      <div className="min-h-screen bg-zinc-950 text-zinc-100 flex flex-col items-center justify-center font-mono text-xs select-none p-4">
        <div className="max-w-md w-full border border-zinc-800 bg-zinc-950 p-6 space-y-4 text-center">
          <div className="flex items-center justify-center">
            <div className="w-8 h-8 bg-zinc-900 border border-zinc-800 flex items-center justify-center text-red-400">
              <ShieldAlert className="w-4 h-4" />
            </div>
          </div>
          <div>
            <div className="font-bold uppercase tracking-wider text-zinc-100">
              ACCESS_RESTRICTED // AUTH_REQUIRED
            </div>
            <p className="text-[11px] text-zinc-400 mt-1">
              You must authenticate with corporate credentials or developer clearance to mount the digital twin dashboard.
            </p>
          </div>
          <button
            type="button"
            onClick={() => setAuthModalOpen(true)}
            className="w-full bg-zinc-100 hover:bg-white text-zinc-950 font-bold py-2 uppercase tracking-wider transition-colors"
          >
            AUTHENTICATE NOW
          </button>
        </div>

        <AuthModal
          isOpen={authModalOpen}
          onClose={() => setAuthModalOpen(false)}
          targetAction="Access Digital Twin Dashboard"
        />
      </div>
    );
  }

  return (
    <div className="flex flex-col h-screen w-full bg-zinc-950 text-zinc-100 overflow-hidden font-mono select-none">
      {/* Top Nav (Email, Role Badge, Quota) */}
      <header className="h-14 border-b border-zinc-800 bg-zinc-950 px-6 flex items-center justify-between shrink-0">
        {/* Brand & Subsystem */}
        <div className="flex items-center gap-3">
          <div className="w-7 h-7 bg-zinc-900 border border-zinc-800 flex items-center justify-center text-emerald-400">
            <Shield className="w-4 h-4" />
          </div>
          <div>
            <div className="text-xs font-bold uppercase tracking-wider text-zinc-100">
              VULNTWIN AI // EXPOSURE VALIDATION
            </div>
            <div className="text-[10px] text-zinc-500 uppercase tracking-widest">
              ADVERSARIAL DIGITAL TWIN PLATFORM
            </div>
          </div>
        </div>

        {/* Controls & User Information */}
        <div className="flex items-center gap-3 text-xs">
          {/* Reset Twin Button */}
          <button
            type="button"
            disabled={isSimulating}
            onClick={resetSimulation}
            className="px-2.5 py-1.5 border border-zinc-800 bg-zinc-900 hover:bg-zinc-850 text-zinc-400 hover:text-zinc-200 flex items-center gap-1.5 transition-colors uppercase disabled:opacity-50"
            title="Reset Graph State"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">RESET</span>
          </button>

          {/* Run Validation Action */}
          <button
            type="button"
            disabled={isSimulating || isQuotaReached}
            onClick={() => startSimulation()}
            className={`px-3.5 py-1.5 font-bold uppercase flex items-center gap-1.5 transition-colors ${
              isQuotaReached
                ? 'bg-zinc-900 text-red-400 border border-red-900 cursor-not-allowed'
                : isSimulating
                ? 'bg-zinc-800 text-zinc-400 border border-zinc-700 cursor-not-allowed'
                : 'bg-zinc-100 hover:bg-white text-zinc-950 cursor-pointer'
            }`}
          >
            {isSimulating ? (
              <>
                <RefreshCw className="w-3.5 h-3.5 animate-spin text-amber-400" />
                <span>TRAVERSING...</span>
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5 fill-current" />
                <span>RUN VALIDATION</span>
              </>
            )}
          </button>

          {/* User Details & Quota */}
          <div className="flex items-center gap-3 pl-3 border-l border-zinc-800">
            <div className="hidden md:flex flex-col text-right">
              <span className="text-zinc-200 truncate max-w-[170px]" title={user.email || ''}>
                {user.email || 'analyst@enterprise.com'}
              </span>
              <span className="text-[10px] text-zinc-500">
                {isDeveloper ? 'QUOTA: UNLIMITED' : `SCANS: ${scansUsed} / ${maxScans}`}
              </span>
            </div>

            {/* Role Badge */}
            {isDeveloper ? (
              <span className="px-2 py-0.5 text-[10px] font-bold bg-emerald-950 text-emerald-400 border border-emerald-800 tracking-wider flex items-center gap-1">
                <Crown className="w-3 h-3 text-emerald-400" />
                DEVELOPER
              </span>
            ) : (
              <span className="px-2 py-0.5 text-[10px] font-bold bg-zinc-900 text-zinc-400 border border-zinc-800 tracking-wider flex items-center gap-1">
                <User className="w-3 h-3 text-zinc-500" />
                STANDARD
              </span>
            )}

            {/* Sign Out */}
            <button
              type="button"
              onClick={signOut}
              className="p-1.5 text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900 border border-transparent hover:border-zinc-800 transition-colors"
              title="Sign Out"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        </div>
      </header>

      {/* Main Grid: 70% width for <GraphCanvas />, 30% width for <TerminalFeed /> stacked on <RemediationPanel /> */}
      <main className="flex-1 flex flex-col lg:flex-row min-h-0 overflow-hidden">
        {/* LEFT (70%): Interactive Attack Graph Canvas */}
        <section className="lg:w-[70%] w-full flex flex-col h-full border-r border-zinc-800 min-h-0 relative bg-zinc-950">
          {/* Canvas Sub-Header */}
          <div className="h-10 border-b border-zinc-800 bg-zinc-900/40 px-4 flex items-center justify-between shrink-0 text-xs text-zinc-400">
            <div className="flex items-center gap-2">
              <span className="text-zinc-600">ACTIVE_TOPOLOGY:</span>
              <span className="text-zinc-200 font-bold">AWS_3TIER_PRODUCTION_TWIN</span>
            </div>
            {blastRadius > 0 && (
              <div className="flex items-center gap-1.5">
                <span className="text-zinc-500 uppercase">BLAST_RADIUS:</span>
                <span className="font-bold px-1.5 py-0.2 border bg-red-950 text-red-400 border-red-800">
                  {blastRadius} / 100
                </span>
              </div>
            )}
          </div>

          <div className="flex-1 relative min-h-0 bg-zinc-950">
            <GraphCanvas />
          </div>
        </section>

        {/* RIGHT (30%): TelemetryFeed stacked on RemediationPanel */}
        <aside className="lg:w-[30%] w-full flex flex-col h-full bg-zinc-950 min-h-0 border-t lg:border-t-0 border-zinc-800 overflow-y-auto">
          {/* Top: Terminal Telemetry Stream */}
          <div className="p-3 border-b border-zinc-800 shrink-0">
            <TerminalFeed className="h-72" />
          </div>

          {/* Bottom: Remediation Panel */}
          <div className="p-3 flex-1 overflow-y-auto">
            <RemediationPanel />
          </div>
        </aside>
      </main>
    </div>
  );
}
