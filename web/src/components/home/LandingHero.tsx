'use client';

import React from 'react';
import {
  Shield,
  Server,
  Database,
  ArrowRight,
  Lock,
  Cpu,
  Layers,
  Activity,
  CheckCircle2,
  AlertTriangle,
  Play,
  KeyRound,
  FileText,
  Workflow,
  Sparkles,
} from 'lucide-react';
import { useAuthStore } from '@/store/useAuthStore';

interface LandingHeroProps {
  onActionClick: (actionName: string) => void;
}

export function LandingHero({ onActionClick }: LandingHeroProps) {
  const { user, role, loginAsDeveloper } = useAuthStore();

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100 flex flex-col font-sans select-none">
      {/* Top Navigation Banner */}
      <header className="h-14 border-b border-zinc-800 bg-zinc-950/80 backdrop-blur-md px-6 flex items-center justify-between sticky top-0 z-30">
        <div className="flex items-center gap-3">
          <div className="p-1.5 rounded bg-zinc-900 border border-zinc-800 text-emerald-400">
            <Shield className="w-4 h-4" />
          </div>
          <div>
            <span className="text-xs font-bold font-mono text-zinc-100 tracking-wider uppercase">
              VulnTwin AI
            </span>
            <span className="text-[10px] font-mono text-zinc-500 ml-2 hidden sm:inline">
              // Continuous Threat Exposure Management
            </span>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <div className="hidden md:flex items-center gap-2 text-xs font-mono text-zinc-400 border-r border-zinc-800 pr-4">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            <span className="text-zinc-500">RUNTIME:</span>
            <span className="text-zinc-300">BROWSER_ISOLATED</span>
          </div>

          {user ? (
            <button
              type="button"
              onClick={() => onActionClick('Launch Digital Twin')}
              className="px-3.5 py-1.5 bg-emerald-500 hover:bg-emerald-400 text-zinc-950 font-semibold font-mono text-xs rounded-md transition-colors flex items-center gap-1.5"
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              <span>Enter Sandbox</span>
            </button>
          ) : (
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => loginAsDeveloper('sara.dongare@corp-sec.com')}
                className="px-2.5 py-1.5 border border-emerald-800/80 bg-emerald-950/40 hover:bg-emerald-900/60 text-emerald-300 font-mono text-xs rounded-md transition-colors flex items-center gap-1.5"
                title="Direct Administrator Clearance"
              >
                <KeyRound className="w-3.5 h-3.5" />
                <span className="hidden sm:inline">Dev Clearance</span>
              </button>

              <button
                type="button"
                onClick={() => onActionClick('Sign In')}
                className="px-3 py-1.5 bg-zinc-100 hover:bg-white text-zinc-950 font-semibold font-mono text-xs rounded-md transition-colors"
              >
                Sign In
              </button>
            </div>
          )}
        </div>
      </header>

      {/* Hero Section */}
      <section className="px-6 py-16 md:py-24 max-w-6xl mx-auto flex flex-col items-center text-center space-y-6">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-emerald-900/60 bg-emerald-950/30 text-emerald-400 text-xs font-mono">
          <Sparkles className="w-3.5 h-3.5" />
          <span>Next-Gen Adversarial Exposure Validation (AEV)</span>
        </div>

        <h1 className="text-3xl sm:text-5xl lg:text-6xl font-bold tracking-tight text-zinc-100 max-w-4xl font-mono leading-tight">
          Mathematical Breach Simulation On Digital Twins.{' '}
          <span className="text-zinc-500 font-normal">Zero Production Risk.</span>
        </h1>

        <p className="text-sm sm:text-base text-zinc-400 max-w-2xl font-sans leading-relaxed">
          Safely validate multi-hop attack reachability, compound blast radius, and automated security rule remediation in the browser runtime using deterministic graph mathematics.
        </p>

        {/* Primary Action Buttons */}
        <div className="flex flex-wrap items-center justify-center gap-3 pt-4">
          <button
            type="button"
            onClick={() => onActionClick('Launch Digital Twin')}
            className="px-5 py-2.5 bg-zinc-100 hover:bg-white text-zinc-950 font-semibold font-mono text-xs rounded-md transition-colors flex items-center gap-2"
          >
            <span>Launch Digital Twin</span>
            <ArrowRight className="w-4 h-4" />
          </button>

          <button
            type="button"
            onClick={() => onActionClick('Run AI Validation')}
            className="px-5 py-2.5 bg-zinc-900 hover:bg-zinc-800 border border-zinc-800 text-zinc-200 font-mono text-xs rounded-md transition-colors flex items-center gap-2"
          >
            <Play className="w-3.5 h-3.5 fill-current text-emerald-400" />
            <span>Run AI Validation Demo</span>
          </button>
        </div>

        {/* Metrics Grid */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 w-full pt-12 border-t border-zinc-800/80 font-mono text-left">
          <div className="p-4 bg-zinc-900/40 border border-zinc-800/80 rounded-md">
            <div className="text-[10px] text-zinc-500 uppercase tracking-wider">Breach Model</div>
            <div className="text-lg font-bold text-zinc-100 mt-1">Directed Graph G(V,E)</div>
            <div className="text-[11px] text-emerald-400 mt-0.5">Deterministic Traversal</div>
          </div>
          <div className="p-4 bg-zinc-900/40 border border-zinc-800/80 rounded-md">
            <div className="text-[10px] text-zinc-500 uppercase tracking-wider">Production Cost</div>
            <div className="text-lg font-bold text-zinc-100 mt-1">$0.00 / Zero Packets</div>
            <div className="text-[11px] text-emerald-400 mt-0.5">Isolated Twin Runtime</div>
          </div>
          <div className="p-4 bg-zinc-900/40 border border-zinc-800/80 rounded-md">
            <div className="text-[10px] text-zinc-500 uppercase tracking-wider">Compound Risk</div>
            <div className="text-lg font-bold text-zinc-100 mt-1">Blast Radius R(C,D)</div>
            <div className="text-[11px] text-amber-400 mt-0.5">Logarithmic Scaling</div>
          </div>
          <div className="p-4 bg-zinc-900/40 border border-zinc-800/80 rounded-md">
            <div className="text-[10px] text-zinc-500 uppercase tracking-wider">Remediation Loop</div>
            <div className="text-lg font-bold text-zinc-100 mt-1">Closed-Loop Verification</div>
            <div className="text-[11px] text-emerald-400 mt-0.5">Automated Re-Test</div>
          </div>
        </div>
      </section>

      {/* Interactive Topology Showcase Cards */}
      <section className="px-6 py-12 max-w-6xl mx-auto w-full space-y-6">
        <div className="flex items-center justify-between border-b border-zinc-800 pb-3">
          <div>
            <h2 className="text-sm font-bold font-mono text-zinc-100 uppercase tracking-wider">
              Pre-Configured Architecture Topologies
            </h2>
            <p className="text-xs text-zinc-400 font-sans mt-0.5">
              Click any environment template below to inspect choke points and simulate reachability.
            </p>
          </div>
          <span className="text-[10px] font-mono text-zinc-500">2 TEMPLATES READY</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 font-mono">
          {/* Card 1: Enterprise Cloud VPC */}
          <div className="bg-zinc-900/60 border border-zinc-800 hover:border-zinc-700 rounded-md p-5 flex flex-col justify-between transition-all group">
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="px-2 py-0.5 text-[10px] bg-zinc-800 text-zinc-300 border border-zinc-700 rounded">
                  AWS MULTI-TIER
                </span>
                <span className="text-red-400 text-xs font-semibold">CVSS 9.8</span>
              </div>
              <h3 className="text-sm font-bold text-zinc-100 group-hover:text-emerald-400 transition-colors">
                Enterprise Cloud VPC (E-Commerce)
              </h3>
              <p className="text-xs text-zinc-400 font-sans leading-relaxed">
                Public AWS ALB ingress routing into a Node.js reverse-proxy gateway with permissive internal routing directly into customer PostgreSQL records.
              </p>

              <div className="pt-2 border-t border-zinc-800/80 text-[11px] text-zinc-500 space-y-1">
                <div className="flex justify-between">
                  <span>Assets:</span>
                  <span className="text-zinc-300">4 Nodes • 3 Interconnects</span>
                </div>
                <div className="flex justify-between">
                  <span>Exposed Target:</span>
                  <span className="text-red-400">PostgreSQL (:5432)</span>
                </div>
                <div className="flex justify-between">
                  <span>Synthetic Records:</span>
                  <span className="text-amber-400">50,000 PII</span>
                </div>
              </div>
            </div>

            <button
              type="button"
              onClick={() => onActionClick('Enterprise Cloud VPC')}
              className="mt-5 w-full bg-zinc-950 hover:bg-zinc-800 border border-zinc-800 hover:border-zinc-700 text-zinc-200 py-2 px-3 rounded text-xs flex items-center justify-center gap-1.5 transition-colors"
            >
              <span>Inspect & Validate</span>
              <ArrowRight className="w-3.5 h-3.5 text-zinc-400" />
            </button>
          </div>

          {/* Card 2: Healthcare PACS Network */}
          <div className="bg-zinc-900/60 border border-zinc-800 hover:border-zinc-700 rounded-md p-5 flex flex-col justify-between transition-all group">
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="px-2 py-0.5 text-[10px] bg-zinc-800 text-zinc-300 border border-zinc-700 rounded">
                  HIPAA REGULATED
                </span>
                <span className="text-red-400 text-xs font-semibold">CVSS 9.4</span>
              </div>
              <h3 className="text-sm font-bold text-zinc-100 group-hover:text-emerald-400 transition-colors">
                Healthcare PACS Network (PHI Vault)
              </h3>
              <p className="text-xs text-zinc-400 font-sans leading-relaxed">
                External VPN Gateway routing tele-radiology traffic into an Orthanc DICOM Web API with unsegmented communication to the patient records archive.
              </p>

              <div className="pt-2 border-t border-zinc-800/80 text-[11px] text-zinc-500 space-y-1">
                <div className="flex justify-between">
                  <span>Assets:</span>
                  <span className="text-zinc-300">3 Nodes • 2 Interconnects</span>
                </div>
                <div className="flex justify-between">
                  <span>Exposed Target:</span>
                  <span className="text-red-400">Patient PHI Vault (:27017)</span>
                </div>
                <div className="flex justify-between">
                  <span>Synthetic Records:</span>
                  <span className="text-amber-400">120,000 PHI</span>
                </div>
              </div>
            </div>

            <button
              type="button"
              onClick={() => onActionClick('Healthcare PACS Network')}
              className="mt-5 w-full bg-zinc-950 hover:bg-zinc-800 border border-zinc-800 hover:border-zinc-700 text-zinc-200 py-2 px-3 rounded text-xs flex items-center justify-center gap-1.5 transition-colors"
            >
              <span>Inspect & Validate</span>
              <ArrowRight className="w-3.5 h-3.5 text-zinc-400" />
            </button>
          </div>

          {/* Card 3: Active Threat Engine */}
          <div className="bg-zinc-900/60 border border-zinc-800 hover:border-zinc-700 rounded-md p-5 flex flex-col justify-between transition-all group">
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="px-2 py-0.5 text-[10px] bg-emerald-950 text-emerald-400 border border-emerald-800 rounded">
                  CLOSED-LOOP AEV
                </span>
                <span className="text-emerald-400 text-xs font-semibold">VERIFIED_SAFE</span>
              </div>
              <h3 className="text-sm font-bold text-zinc-100 group-hover:text-emerald-400 transition-colors">
                Automated Remediation Loop
              </h3>
              <p className="text-xs text-zinc-400 font-sans leading-relaxed">
                When an exploit vector succeeds, VulnTwin generates precise isolation rules (Terraform / iptables), applies them to the digital twin, and autonomously re-tests the attack.
              </p>

              <div className="pt-2 border-t border-zinc-800/80 text-[11px] text-zinc-500 space-y-1">
                <div className="flex justify-between">
                  <span>Isolation Logic:</span>
                  <span className="text-zinc-300">Atomic Edge Block</span>
                </div>
                <div className="flex justify-between">
                  <span>Verification:</span>
                  <span className="text-emerald-400">Autonomous Re-Test</span>
                </div>
                <div className="flex justify-between">
                  <span>Rollback Protection:</span>
                  <span className="text-zinc-300">Zero-Downtime Attestation</span>
                </div>
              </div>
            </div>

            <button
              type="button"
              onClick={() => onActionClick('Automated Remediation')}
              className="mt-5 w-full bg-zinc-950 hover:bg-zinc-800 border border-zinc-800 hover:border-zinc-700 text-zinc-200 py-2 px-3 rounded text-xs flex items-center justify-center gap-1.5 transition-colors"
            >
              <span>Inspect Remediation</span>
              <ArrowRight className="w-3.5 h-3.5 text-zinc-400" />
            </button>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="mt-auto border-t border-zinc-800 bg-zinc-950 px-6 py-6 font-mono text-[11px] text-zinc-500 flex flex-col sm:flex-row items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <Shield className="w-3.5 h-3.5 text-emerald-400" />
          <span>VulnTwin AI — Enterprise Adversarial Exposure Validation</span>
        </div>
        <div className="flex items-center gap-4">
          <span>Client-Side CTEM Simulator</span>
          <span>•</span>
          <span>RBAC Firestore Protected</span>
        </div>
      </footer>
    </div>
  );
}
