"use client";

import React, { useEffect } from 'react';
import TopNav from '@/components/layout/TopNav';
import dynamic from "next/dynamic";
const GraphCanvas = dynamic(
  () => import("@/components/twin/GraphCanvas"),
  { ssr: false, loading: () => <div className="h-full w-full bg-zinc-950 font-mono text-xs text-zinc-500 p-4">Loading topology engine...</div> }
);
const TerminalFeed = dynamic(
  () => import("@/components/twin/TerminalFeed"),
  { ssr: false }
);
const RemediationPanel = dynamic(
  () => import("@/components/twin/RemediationPanel"),
  { ssr: false }
);
import { useTwinStore } from '@/store/useTwinStore';
import { useAuthStore } from '@/store/useAuthStore';
import { useRouter } from 'next/navigation';

export default function DashboardPage() {
  const { runValidation, simulationStatus } = useTwinStore();
  const { user, isInitialized } = useAuthStore();
  const router = useRouter();

  useEffect(() => {
    if (isInitialized && !user) {
      router.push('/');
    }
  }, [user, isInitialized, router]);

  if (!isInitialized || !user) {
    return (
      <div className="min-h-screen bg-zinc-950 text-zinc-500 font-mono text-xs p-4 flex items-center justify-center">
        [SYSTEM] Initializing Authentication...
      </div>
    );
  }

  return (
    <div className="h-screen w-full flex flex-col bg-zinc-950 overflow-hidden text-zinc-200">
      <TopNav />
      
      <div className="flex-1 grid grid-cols-12 gap-0 h-[calc(100vh-3rem)]">
        {/* Left Workspace */}
        <div className="col-span-8 border-r border-zinc-800 flex flex-col h-full bg-zinc-950">
          <div className="h-12 border-b border-zinc-800 flex items-center px-4 justify-between bg-zinc-900/30 shrink-0">
            <span className="font-mono text-xs text-zinc-400 uppercase">Target Topology: E-Commerce Sandbox</span>
            <button
              onClick={() => runValidation()}
              disabled={simulationStatus === 'RUNNING'}
              className="bg-red-950/40 text-red-400 border border-red-900/50 px-4 py-1.5 font-mono text-xs uppercase hover:bg-red-900/60 disabled:opacity-50 transition-all rounded-none"
            >
              {simulationStatus === 'RUNNING' ? 'Scanning...' : 'Run Adversarial Simulation'}
            </button>
          </div>
          <div className="flex-1 overflow-hidden">
            <GraphCanvas />
          </div>
        </div>

        {/* Right Workspace */}
        <div className="col-span-4 flex flex-col h-full bg-zinc-950">
          <div className="h-[60%] border-b border-zinc-800 overflow-hidden">
            <TerminalFeed />
          </div>
          <div className="h-[40%] overflow-hidden">
            <RemediationPanel />
          </div>
        </div>
      </div>
    </div>
  );
}
