'use client';

import React from 'react';
import { AuthGuard } from '@/components/layout/AuthGuard';
import { TopNav } from '@/components/layout/TopNav';
import { AdminControls } from '@/components/dashboard/AdminControls';
import { TwinSelector } from '@/components/dashboard/TwinSelector';
import { GraphCanvas } from '@/components/dashboard/GraphCanvas';
import { AuditTerminal } from '@/components/dashboard/AuditTerminal';
import { CTEMPatchPanel } from '@/components/ctem/CTEMPatchPanel';
import { useAuthStore } from '@/store/useAuthStore';
import { useTwinStore } from '@/store/useTwinStore';

function DashboardView() {
  const { role } = useAuthStore();
  const { simulationState, activePatch } = useTwinStore();
  const isDeveloper = role === 'developer';

  return (
    <div className="flex h-screen w-full bg-zinc-950 text-zinc-100 overflow-hidden font-sans select-none">
      {/* 1. Left Sidebar: Architecture Selector */}
      <TwinSelector />

      {/* 2. Main Content Viewport */}
      <div className="flex-1 flex flex-col h-full min-w-0 overflow-hidden">
        {/* Top Navigation Bar: User Email, Role Badge, Sign Out & Run Validation */}
        <TopNav />

        {/* Dynamic Canvas & Telemetry Area */}
        <div className="flex-1 relative min-h-0 bg-zinc-950 flex flex-col overflow-hidden">
          {/* Conditional Developer View: Admin Controls Panel */}
          {isDeveloper && (
            <div className="p-3 border-b border-zinc-800/80 bg-zinc-950/90 z-20 shrink-0">
              <AdminControls />
            </div>
          )}

          {/* Remediation Patch Reveal when Simulation Completes */}
          {simulationState === 'COMPLETED' && activePatch && (
            <div className="p-4 bg-zinc-950/95 border-b border-zinc-800 shrink-0 z-10 max-h-72 overflow-y-auto">
              <CTEMPatchPanel />
            </div>
          )}

          {/* Network Topology Graph Canvas */}
          <div className="flex-1 min-h-0 relative">
            <GraphCanvas />
          </div>
        </div>

        {/* Bottom Audit Terminal Feed */}
        <AuditTerminal />
      </div>
    </div>
  );
}

export default function MainPage() {
  return (
    <AuthGuard>
      <DashboardView />
    </AuthGuard>
  );
}
