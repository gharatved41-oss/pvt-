'use client';

import React, { useState, useEffect } from 'react';
import { IntroSplash } from '@/components/layout/IntroSplash';
import { LandingHero } from '@/components/home/LandingHero';
import { AuthModal } from '@/components/auth/AuthModal';
import { TopNav } from '@/components/layout/TopNav';
import { AdminControls } from '@/components/dashboard/AdminControls';
import { GraphCanvas } from '@/components/twin/GraphCanvas';
import { TerminalFeed } from '@/components/twin/TerminalFeed';
import { RemediationPanel } from '@/components/twin/RemediationPanel';
import { useAuthStore } from '@/store/useAuthStore';
import { useTwinStore } from '@/store/useTwinStore';
import { Play, RefreshCw, ShieldAlert, Layers, Home, Eye } from 'lucide-react';

export default function MainPage() {
  const { user, role, scansUsed, maxScans } = useAuthStore();
  const {
    simulationStatus,
    simulationProgress,
    runValidation,
    selectedTemplate,
    loadTemplate,
    riskScore,
  } = useTwinStore();

  const [showSplash, setShowSplash] = useState<boolean>(false);
  const [authModalOpen, setAuthModalOpen] = useState<boolean>(false);
  const [targetAction, setTargetAction] = useState<string>('');
  const [viewMode, setViewMode] = useState<'landing' | 'sandbox'>('landing');
  const [verificationError, setVerificationError] = useState<string | null>(null);

  // 1. Session Intro Splash Check
  useEffect(() => {
    if (typeof window !== 'undefined') {
      const seen = sessionStorage.getItem('hasSeenIntro');
      if (!seen) {
        setShowSplash(true);
      }
    }
  }, []);

  const isDeveloper = role === 'developer';
  const isRunning = simulationStatus === 'RUNNING';
  const isQuotaReached = !isDeveloper && scansUsed >= maxScans;

  // 2. Action Gating Interceptor
  const handleActionClick = (actionName: string) => {
    setTargetAction(actionName);
    setVerificationError(null);

    // If not logged in, trigger AuthModal
    if (!user) {
      setAuthModalOpen(true);
      return;
    }

    // If logged in but email not verified (and not developer), display verification alert
    if (!isDeveloper && !user.emailVerified) {
      setVerificationError(
        'Access Restricted: Please verify your email address to launch the Digital Twin simulation.'
      );
      return;
    }

    // Route template selection if applicable
    if (actionName.includes('Healthcare')) {
      loadTemplate('healthcare');
    } else if (actionName.includes('Enterprise')) {
      loadTemplate('ecommerce');
    }

    setViewMode('sandbox');
  };

  const handleAuthSuccess = () => {
    setVerificationError(null);
    setViewMode('sandbox');
  };

  return (
    <>
      {/* Module 1: Brand Intro Splash Animation */}
      {showSplash && (
        <IntroSplash
          onComplete={() => {
            setShowSplash(false);
          }}
        />
      )}

      {/* Email Verification Required Banner */}
      {verificationError && (
        <div className="fixed top-4 left-1/2 -translate-x-1/2 z-50 max-w-xl w-[90%] bg-zinc-950 border border-red-500 text-red-400 font-mono text-xs p-3 flex items-center justify-between shadow-2xl">
          <div className="flex items-center gap-2">
            <span className="font-bold text-red-500">[VERIFICATION_REQUIRED]:</span>
            <span>{verificationError}</span>
          </div>
          <button
            type="button"
            onClick={() => setVerificationError(null)}
            className="ml-3 text-zinc-500 hover:text-zinc-300 font-bold uppercase"
          >
            [DISMISS]
          </button>
        </div>
      )}

      {/* Module 3: Authentication Modal */}
      <AuthModal
        isOpen={authModalOpen}
        onClose={() => setAuthModalOpen(false)}
        onSuccess={handleAuthSuccess}
        targetAction={targetAction}
      />

      {/* View Switcher: Public Showcase vs. Interactive Twin Sandbox */}
      {viewMode === 'landing' ? (
        <LandingHero
          onActionClick={handleActionClick}
          onReplayIntro={() => {
            sessionStorage.removeItem('hasSeenIntro');
            setShowSplash(true);
          }}
        />
      ) : (
        <div className="flex flex-col h-screen w-full bg-zinc-950 text-zinc-100 overflow-hidden font-sans select-none">
          {/* Header Navigation with Showcase Return Option */}
          <div className="relative">
            <TopNav />
            {/* Quick Switch to Showcase View */}
            <button
              type="button"
              onClick={() => setViewMode('landing')}
              className="absolute left-[360px] top-3 hidden xl:flex items-center gap-1.5 px-2.5 py-1 rounded bg-zinc-900 border border-zinc-800 text-[11px] font-mono text-zinc-400 hover:text-zinc-200 transition-colors z-20"
              title="Return to Public Architectural Showcase"
            >
              <Home className="w-3 h-3 text-zinc-500" />
              <span>Showcase View</span>
            </button>
          </div>

          {/* Developer Admin Override Panel */}
          {isDeveloper && (
            <div className="px-4 py-2 border-b border-zinc-800 bg-zinc-950 shrink-0">
              <AdminControls />
            </div>
          )}

          {/* Main 70/30 Split Viewport */}
          <div className="flex-1 flex flex-col lg:flex-row min-h-0 overflow-hidden">
            {/* LEFT COLUMN (70%): Template selector & Interactive Graph Canvas */}
            <div className="lg:w-[70%] w-full flex flex-col h-full border-r border-zinc-800 min-h-0">
              {/* Top Control Bar */}
              <div className="h-12 border-b border-zinc-800 bg-zinc-900/40 px-4 flex items-center justify-between shrink-0 font-mono text-xs">
                {/* Template Selector Tabs */}
                <div className="flex items-center gap-2">
                  <span className="text-zinc-500 uppercase text-[10px] tracking-wider flex items-center gap-1">
                    <Layers className="w-3.5 h-3.5 text-zinc-400" />
                    Template:
                  </span>
                  <button
                    type="button"
                    onClick={() => loadTemplate('ecommerce')}
                    className={`px-2.5 py-1 rounded text-xs transition-colors ${
                      selectedTemplate === 'ecommerce'
                        ? 'bg-zinc-800 text-zinc-100 border border-zinc-700 font-semibold'
                        : 'text-zinc-400 hover:text-zinc-200'
                    }`}
                  >
                    E-Commerce Cloud
                  </button>
                  <button
                    type="button"
                    onClick={() => loadTemplate('healthcare')}
                    className={`px-2.5 py-1 rounded text-xs transition-colors ${
                      selectedTemplate === 'healthcare'
                        ? 'bg-zinc-800 text-zinc-100 border border-zinc-700 font-semibold'
                        : 'text-zinc-400 hover:text-zinc-200'
                    }`}
                  >
                    Healthcare PACS
                  </button>
                </div>

                {/* Compound Risk & Run Button */}
                <div className="flex items-center gap-3">
                  {riskScore > 0 && (
                    <div className="flex items-center gap-1.5 text-[11px]">
                      <span className="text-zinc-500">Compound Risk:</span>
                      <span
                        className={`font-bold px-1.5 py-0.5 rounded border ${
                          riskScore >= 80
                            ? 'bg-red-950 text-red-400 border-red-800'
                            : riskScore >= 50
                            ? 'bg-amber-950 text-amber-400 border-amber-800'
                            : 'bg-emerald-950 text-emerald-400 border-emerald-800'
                        }`}
                      >
                        {riskScore} / 100
                      </span>
                    </div>
                  )}

                  <button
                    type="button"
                    disabled={isRunning || isQuotaReached}
                    onClick={() => runValidation()}
                    className={`px-3 py-1 rounded font-semibold text-xs flex items-center gap-1.5 transition-all ${
                      isQuotaReached
                        ? 'bg-zinc-900 text-red-400 border border-red-900 cursor-not-allowed'
                        : isRunning
                        ? 'bg-zinc-800 text-zinc-400 border border-zinc-700 cursor-not-allowed'
                        : 'bg-zinc-100 hover:bg-white text-zinc-950 cursor-pointer active:scale-98'
                    }`}
                  >
                    {isRunning ? (
                      <>
                        <RefreshCw className="w-3.5 h-3.5 animate-spin text-amber-400" />
                        <span>Validating ({simulationProgress}%)...</span>
                      </>
                    ) : isQuotaReached ? (
                      <>
                        <ShieldAlert className="w-3.5 h-3.5 text-red-400" />
                        <span>Quota Limit (3/3)</span>
                      </>
                    ) : (
                      <>
                        <Play className="w-3.5 h-3.5 fill-current" />
                        <span>Run AI Validation</span>
                      </>
                    )}
                  </button>
                </div>
              </div>

              {/* Digital Twin Graph Canvas */}
              <div className="flex-1 relative min-h-0 bg-zinc-950">
                <GraphCanvas />
              </div>
            </div>

            {/* RIGHT COLUMN (30%): Telemetry Stream & Remediation Panel */}
            <div className="lg:w-[30%] w-full flex flex-col h-full bg-zinc-950 min-h-0 overflow-y-auto">
              {/* Telemetry Stream */}
              <div className="p-3 border-b border-zinc-800 shrink-0">
                <TerminalFeed className="h-80" />
              </div>

              {/* Remediation Panel */}
              <div className="p-3 flex-1 overflow-y-auto">
                <RemediationPanel />
              </div>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
