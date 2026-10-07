'use client';

import React from 'react';
import {
  Shield,
  ArrowRight,
  Play,
  RotateCcw,
  Sparkles,
} from 'lucide-react';
import { useAuthStore } from '@/store/useAuthStore';

interface LandingHeroProps {
  onActionClick: (actionName: string) => void;
  onReplayIntro?: () => void;
}

export function LandingHero({ onActionClick, onReplayIntro }: LandingHeroProps) {
  const { user } = useAuthStore();

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100 flex flex-col font-mono select-none">
      {/* Top Header */}
      <header className="h-14 border-b border-zinc-800 bg-zinc-950 px-6 flex items-center justify-between sticky top-0 z-30">
        <div className="flex items-center gap-3">
          <div className="w-7 h-7 bg-zinc-900 border border-zinc-800 flex items-center justify-center text-emerald-400">
            <Shield className="w-4 h-4" />
          </div>
          <div>
            <span className="text-xs font-bold text-zinc-100 uppercase tracking-wider">
              VULNTWIN AI
            </span>
            <span className="text-[10px] text-zinc-500 ml-2 hidden sm:inline">
              // ADVERSARIAL DIGITAL TWIN PLATFORM
            </span>
          </div>
        </div>

        <div className="flex items-center gap-3 text-xs">
          {onReplayIntro && (
            <button
              type="button"
              onClick={onReplayIntro}
              className="px-2.5 py-1 text-[11px] border border-zinc-800 bg-zinc-900 hover:bg-zinc-800 text-zinc-400 hover:text-zinc-200 flex items-center gap-1 transition-colors"
              title="Replay Brand Intro Animation"
            >
              <RotateCcw className="w-3 h-3 text-emerald-400" />
              <span>REPLAY_INTRO</span>
            </button>
          )}

          {user ? (
            <button
              type="button"
              onClick={() => onActionClick('Launch Digital Twin')}
              className="px-3.5 py-1.5 bg-emerald-500 hover:bg-emerald-400 text-zinc-950 font-bold uppercase transition-colors flex items-center gap-1.5"
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              <span>ENTER WORKSPACE</span>
            </button>
          ) : (
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => onActionClick('Sign In')}
                className="px-3 py-1.5 bg-zinc-100 hover:bg-white text-zinc-950 font-bold uppercase transition-colors"
              >
                SIGN IN
              </button>
            </div>
          )}
        </div>
      </header>

      {/* Hero Section */}
      <section className="px-6 py-16 md:py-20 max-w-5xl mx-auto flex flex-col items-center text-center space-y-6">
        <div className="inline-flex items-center gap-2 px-3 py-1 border border-zinc-800 bg-zinc-900 text-emerald-400 text-xs">
          <Sparkles className="w-3 h-3" />
          <span>CONTINUOUS THREAT EXPOSURE MANAGEMENT (CTEM)</span>
        </div>

        <h1 className="text-2xl sm:text-4xl lg:text-5xl font-bold tracking-tight text-zinc-100 uppercase leading-snug">
          MATHEMATICAL BREACH SIMULATION ON DIGITAL TWINS.{' '}
          <span className="text-zinc-500">ZERO PRODUCTION RISK.</span>
        </h1>

        <p className="text-xs sm:text-sm text-zinc-400 max-w-2xl leading-relaxed">
          Safely validate multi-hop attack reachability, compound blast radius, and automated security rule remediation in the browser runtime using deterministic graph mathematics.
        </p>

        {/* Primary Action Triggers */}
        <div className="flex flex-wrap items-center justify-center gap-3 pt-4">
          <button
            type="button"
            onClick={() => onActionClick('Launch Digital Twin')}
            className="px-5 py-2.5 bg-zinc-100 hover:bg-white text-zinc-950 font-bold text-xs uppercase flex items-center gap-2 transition-colors"
          >
            <span>LAUNCH DIGITAL TWIN</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>

          <button
            type="button"
            onClick={() => onActionClick('Run AI Validation')}
            className="px-5 py-2.5 bg-zinc-900 hover:bg-zinc-800 border border-zinc-800 text-zinc-200 text-xs uppercase flex items-center gap-2 transition-colors"
          >
            <Play className="w-3.5 h-3.5 fill-current text-emerald-400" />
            <span>RUN AI VALIDATION</span>
          </button>
        </div>

        {/* Metrics Grid */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 w-full pt-10 border-t border-zinc-800 text-left text-xs">
          <div className="p-3 bg-zinc-900 border border-zinc-800">
            <div className="text-[10px] text-zinc-500 uppercase">BREACH MODEL</div>
            <div className="font-bold text-zinc-100 mt-1">DIRECTED GRAPH G(V,E)</div>
            <div className="text-[10px] text-emerald-400 mt-0.5">DETERMINISTIC TRAVERSAL</div>
          </div>
          <div className="p-3 bg-zinc-900 border border-zinc-800">
            <div className="text-[10px] text-zinc-500 uppercase">PACKET OVERHEAD</div>
            <div className="font-bold text-zinc-100 mt-1">0 LIVE PACKETS</div>
            <div className="text-[10px] text-emerald-400 mt-0.5">ISOLATED SIMULATOR</div>
          </div>
          <div className="p-3 bg-zinc-900 border border-zinc-800">
            <div className="text-[10px] text-zinc-500 uppercase">COMPOUND RISK</div>
            <div className="font-bold text-zinc-100 mt-1">BLAST RADIUS R(C,D)</div>
            <div className="text-[10px] text-amber-400 mt-0.5">LOGARITHMIC SCALING</div>
          </div>
          <div className="p-3 bg-zinc-900 border border-zinc-800">
            <div className="text-[10px] text-zinc-500 uppercase">REMEDIATION LOOP</div>
            <div className="font-bold text-zinc-100 mt-1">CLOSED-LOOP ATTESTATION</div>
            <div className="text-[10px] text-emerald-400 mt-0.5">AUTONOMOUS RE-TEST</div>
          </div>
        </div>
      </section>

      {/* Architecture Showcase Cards */}
      <section className="px-6 py-10 max-w-5xl mx-auto w-full space-y-4">
        <div className="flex items-center justify-between border-b border-zinc-800 pb-2">
          <span className="text-xs font-bold text-zinc-100 uppercase">
            TARGET ENVIRONMENT TOPOLOGIES
          </span>
          <span className="text-[10px] text-zinc-500">2 TEMPLATES READY</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 text-xs">
          {/* Card 1: Enterprise Cloud VPC */}
          <div className="bg-zinc-900 border border-zinc-800 p-4 flex flex-col justify-between space-y-3">
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="px-1.5 py-0.5 text-[10px] bg-zinc-800 text-zinc-300 border border-zinc-700">
                  AWS MULTI-TIER
                </span>
                <span className="text-red-400 font-bold">CVSS 9.8</span>
              </div>
              <h3 className="text-xs font-bold text-zinc-100">
                Enterprise Cloud VPC (E-Commerce)
              </h3>
              <p className="text-[11px] text-zinc-400 leading-relaxed">
                Public ALB routing into Node.js gateway with permissive internal access directly to customer PostgreSQL database.
              </p>
            </div>
            <button
              type="button"
              onClick={() => onActionClick('Enterprise Cloud VPC')}
              className="w-full bg-zinc-950 hover:bg-zinc-800 border border-zinc-800 text-zinc-200 py-2 px-3 text-xs flex items-center justify-center gap-1.5 uppercase transition-colors"
            >
              <span>INSPECT & VALIDATE</span>
              <ArrowRight className="w-3.5 h-3.5 text-zinc-400" />
            </button>
          </div>

          {/* Card 2: Healthcare PACS Network */}
          <div className="bg-zinc-900 border border-zinc-800 p-4 flex flex-col justify-between space-y-3">
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="px-1.5 py-0.5 text-[10px] bg-zinc-800 text-zinc-300 border border-zinc-700">
                  HIPAA REGULATED
                </span>
                <span className="text-red-400 font-bold">CVSS 9.4</span>
              </div>
              <h3 className="text-xs font-bold text-zinc-100">
                Healthcare PACS Network (PHI Vault)
              </h3>
              <p className="text-[11px] text-zinc-400 leading-relaxed">
                VPN gateway routing tele-radiology traffic into Orthanc DICOM Web with unsegmented communication to patient records.
              </p>
            </div>
            <button
              type="button"
              onClick={() => onActionClick('Healthcare PACS Network')}
              className="w-full bg-zinc-950 hover:bg-zinc-800 border border-zinc-800 text-zinc-200 py-2 px-3 text-xs flex items-center justify-center gap-1.5 uppercase transition-colors"
            >
              <span>INSPECT & VALIDATE</span>
              <ArrowRight className="w-3.5 h-3.5 text-zinc-400" />
            </button>
          </div>

          {/* Card 3: Active Threat Engine */}
          <div className="bg-zinc-900 border border-zinc-800 p-4 flex flex-col justify-between space-y-3">
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="px-1.5 py-0.5 text-[10px] bg-emerald-950 text-emerald-400 border border-emerald-800">
                  CLOSED-LOOP AEV
                </span>
                <span className="text-emerald-400 font-bold">VERIFIED_SAFE</span>
              </div>
              <h3 className="text-xs font-bold text-zinc-100">
                Automated Remediation Loop
              </h3>
              <p className="text-[11px] text-zinc-400 leading-relaxed">
                When breach vector succeeds, generate atomic isolation rules (Terraform/iptables), apply to twin, and autonomously re-test.
              </p>
            </div>
            <button
              type="button"
              onClick={() => onActionClick('Automated Remediation')}
              className="w-full bg-zinc-950 hover:bg-zinc-800 border border-zinc-800 text-zinc-200 py-2 px-3 text-xs flex items-center justify-center gap-1.5 uppercase transition-colors"
            >
              <span>INSPECT REMEDIATION</span>
              <ArrowRight className="w-3.5 h-3.5 text-zinc-400" />
            </button>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="mt-auto border-t border-zinc-800 bg-zinc-950 px-6 py-4 text-[10px] text-zinc-500 flex flex-col sm:flex-row items-center justify-between gap-2">
        <span>VULNTWIN AI // ENTERPRISE EXPOSURE VALIDATION PLATFORM</span>
        <span>ZERO PRODUCTION IMPACT • DETERMINISTIC GRAPH MATHEMATICS</span>
      </footer>
    </div>
  );
}
