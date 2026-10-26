import React from 'react';
import { Link } from 'react-router-dom';
import { Shield, Cpu, RefreshCw, BarChart3, CheckCircle2, ArrowRight, Lock, Eye } from 'lucide-react';

export const LandingPage: React.FC = () => {
  return (
    <div className="min-h-screen bg-[#070b14] text-slate-100 flex flex-col selection:bg-cyan-500 selection:text-slate-900">
      {/* Top Navbar */}
      <header className="h-20 border-b border-slate-800/80 px-8 flex items-center justify-between max-w-7xl mx-auto w-full">
        <div className="flex items-center space-x-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center shadow-lg shadow-cyan-500/20">
            <Shield className="w-6 h-6 text-slate-950 font-bold" />
          </div>
          <div>
            <span className="font-extrabold text-xl tracking-wider text-slate-100">
              VULN <span className="text-cyan-400">TWIN</span>
            </span>
            <span className="hidden sm:inline-block ml-2 px-2 py-0.5 rounded text-[10px] font-mono bg-cyan-950/60 border border-cyan-700/50 text-cyan-400">
              ACADEMIC CAPSTONE
            </span>
          </div>
        </div>

        <div className="flex items-center space-x-4">
          <Link
            to="/login"
            className="text-sm font-medium text-slate-300 hover:text-cyan-400 transition-colors px-3 py-1.5"
          >
            Sign In
          </Link>
          <Link
            to="/register"
            className="px-4 py-2 rounded-lg text-sm font-semibold bg-cyan-500 hover:bg-cyan-400 text-slate-950 transition-all shadow-md shadow-cyan-500/20"
          >
            Register
          </Link>
        </div>
      </header>

      {/* Hero Section */}
      <section className="flex-1 max-w-6xl mx-auto px-8 py-20 flex flex-col items-center text-center">
        <div className="inline-flex items-center px-3 py-1 rounded-full text-xs font-mono bg-slate-900/90 border border-cyan-500/30 text-cyan-400 mb-8">
          <span className="w-2 h-2 rounded-full bg-cyan-400 mr-2 animate-ping" />
          AI/ML-Driven Cyber Digital Twin Validation & Remediation
        </div>

        <h1 className="text-4xl sm:text-6xl font-extrabold tracking-tight text-slate-100 max-w-4xl leading-tight sm:leading-none">
          Verify Vulnerabilities in <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-sky-300 to-blue-500">Isolated Digital Twins</span> Without Production Risk
        </h1>

        <p className="mt-6 text-lg text-slate-400 max-w-2xl leading-relaxed">
          Traditional vulnerability scanners produce high volumes of theoretical alerts without confirming true exploitability.
          <strong> Vuln TWin</strong> couples machine-learning risk prioritization with isolated digital twin sandboxes to safely validate findings, simulate vendor remediation, and mathematically verify resolution.
        </p>

        <div className="mt-10 flex flex-col sm:flex-row gap-4">
          <Link
            to="/dashboard"
            className="px-6 py-3.5 rounded-xl font-bold text-sm bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 flex items-center justify-center space-x-2 shadow-xl shadow-cyan-500/25 transition-all"
          >
            <span>Launch Security Console</span>
            <ArrowRight className="w-4 h-4" />
          </Link>
          <Link
            to="/login"
            className="px-6 py-3.5 rounded-xl font-semibold text-sm bg-slate-900/80 hover:bg-slate-800 text-slate-200 border border-slate-700 flex items-center justify-center space-x-2 transition-all"
          >
            <Lock className="w-4 h-4 text-cyan-400" />
            <span>Sign In with Demo Credentials</span>
          </Link>
        </div>

        {/* Feature Cards Grid */}
        <div className="mt-24 grid grid-cols-1 md:grid-cols-3 gap-6 text-left w-full">
          <div className="cyber-card p-6 bg-slate-900/40 border border-slate-800 rounded-xl">
            <div className="w-12 h-12 rounded-lg bg-cyan-950/80 border border-cyan-800 flex items-center justify-center text-cyan-400 mb-4">
              <Cpu className="w-6 h-6" />
            </div>
            <h3 className="text-base font-bold text-slate-200">1. Isolated Digital Twins</h3>
            <p className="text-xs text-slate-400 mt-2 leading-relaxed">
              Instantiate accurate software replicas on air-gapped sandboxes. Validate vulnerabilities safely without disruption or damage to production systems.
            </p>
          </div>

          <div className="cyber-card p-6 bg-slate-900/40 border border-slate-800 rounded-xl">
            <div className="w-12 h-12 rounded-lg bg-blue-950/80 border border-blue-800 flex items-center justify-center text-blue-400 mb-4">
              <BarChart3 className="w-6 h-6" />
            </div>
            <h3 className="text-base font-bold text-slate-200">2. ML Risk Prioritization</h3>
            <p className="text-xs text-slate-400 mt-2 leading-relaxed">
              GradientBoosting model separates intrinsic CVSS severity from composite realized risk, incorporating asset criticality, exploit maturity, and evidence depth.
            </p>
          </div>

          <div className="cyber-card p-6 bg-slate-900/40 border border-slate-800 rounded-xl">
            <div className="w-12 h-12 rounded-lg bg-emerald-950/80 border border-emerald-800 flex items-center justify-center text-emerald-400 mb-4">
              <RefreshCw className="w-6 h-6" />
            </div>
            <h3 className="text-base font-bold text-slate-200">3. Retest & Verify</h3>
            <p className="text-xs text-slate-400 mt-2 leading-relaxed">
              Require explicit human sign-off before applying patches inside the twin. Re-inspect package manifests and re-run non-destructive probes to prove remediation.
            </p>
          </div>
        </div>

        {/* How It Works Diagram Steps */}
        <div className="mt-20 w-full max-w-4xl p-8 rounded-2xl bg-[#0b101e] border border-slate-800/80 text-left">
          <h2 className="text-lg font-bold text-slate-200 mb-6 flex items-center">
            <Eye className="w-5 h-5 text-cyan-400 mr-2" />
            End-to-End Cyber Digital Twin Lifecycle
          </h2>

          <div className="grid grid-cols-1 sm:grid-cols-4 gap-4 text-xs">
            <div className="p-4 rounded-lg bg-slate-900 border border-slate-800">
              <span className="font-mono text-cyan-400 font-bold">PHASE 1</span>
              <h4 className="font-semibold text-slate-200 mt-1">Inventory & Match</h4>
              <p className="text-slate-400 mt-1">Parse Linux/Windows packages; match against deterministic CVE catalog.</p>
            </div>
            <div className="p-4 rounded-lg bg-slate-900 border border-slate-800">
              <span className="font-mono text-blue-400 font-bold">PHASE 2</span>
              <h4 className="font-semibold text-slate-200 mt-1">Replicate in Twin</h4>
              <p className="text-slate-400 mt-1">Spin up an airgapped sandbox replica with matching OS & packages.</p>
            </div>
            <div className="p-4 rounded-lg bg-slate-900 border border-slate-800">
              <span className="font-mono text-purple-400 font-bold">PHASE 3</span>
              <h4 className="font-semibold text-slate-200 mt-1">Safe Validation</h4>
              <p className="text-slate-400 mt-1">Run non-destructive test procedures to confirm genuine exploitability.</p>
            </div>
            <div className="p-4 rounded-lg bg-slate-900 border border-slate-800">
              <span className="font-mono text-emerald-400 font-bold">PHASE 4</span>
              <h4 className="font-semibold text-slate-200 mt-1">Remediate & Verify</h4>
              <p className="text-slate-400 mt-1">Human-approved fix execution, retesting, and PDF assessment report.</p>
            </div>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-slate-800/80 py-8 px-8 text-center text-xs text-slate-500 font-mono">
        Vuln TWin Platform &copy; 2026 | Built for Final-Year Cybersecurity Capstone Demonstration
      </footer>
    </div>
  );
};
