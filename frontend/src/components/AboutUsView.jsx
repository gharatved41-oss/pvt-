import React from 'react';
import { Shield, Cpu, Database, Terminal, Users, CheckCircle2, ArrowRight } from 'lucide-react';

export default function AboutUsView({ onNavigateToAnalyze }) {
  const teamMembers = [
    {
      name: 'Sara Dongare',
      role: 'Digital Twin & Safe Verification Lead',
      icon: Cpu,
      description:
        'Sara leads the Digital Twin simulation and non-destructive verification workflow. Her subsystem models target web servers, databases, and authentication controls in an isolated test environment, safely verifying vulnerabilities and measuring before/after security regression without ever touching production systems.',
      specialties: [
        'Digital Twin Architecture',
        'Controlled Verification',
        'Automated Re-Test Workflow',
        'Before / After Security Comparison',
      ],
    },
    {
      name: 'Shubra Gharat',
      role: 'AI & Risk Intelligence Lead',
      icon: Database,
      description:
        'Shubra leads the deterministic risk engine, exploitability evaluation, and explainable AI layer. Her engine calculates exact risk scores (0–100), performs root-cause analysis, and translates raw security telemetry into actionable remediation playbooks.',
      specialties: [
        'Deterministic Risk Scoring (0–100)',
        'Contextual Exploitability',
        'AI Root-Cause Identification',
        'Remediation Playbook Generation',
      ],
    },
    {
      name: 'Ved Gharat',
      role: 'Frontend & User Experience Lead',
      icon: Shield,
      description:
        'Ved architects the clean enterprise visual experience, validation topology diagrams, and interactive security memory tables. His work delivers a professional, minimal cybersecurity workflow adhering to enterprise standards.',
      specialties: [
        'Enterprise Design System',
        'Digital Twin Architecture UI',
        'Security Memory Evolution Graph',
        'User-Centric SOC Workflow',
      ],
    },
    {
      name: 'Mayank Patil',
      role: 'Backend & Integration Lead',
      icon: Terminal,
      description:
        'Mayank builds the core platform architecture, high-performance FastAPI backend, daily scan rate limiting, SSRF defense shields, relational persistence, and compliance audit exports. His work unifies the risk engine and digital twin simulator into a reliable product.',
      specialties: [
        'FastAPI Backend Architecture',
        'Daily Rate Limiting & Quotas',
        'SSRF Defense & URL Normalization',
        'Compliance Audit Exporter',
      ],
    },
  ];

  return (
    <div className="space-y-8 max-w-6xl mx-auto pb-14">
      
      {/* 1. Header & Project Mission */}
      <div className="bg-white border border-[#E2E8F0] rounded-xl p-8 shadow-sm text-center max-w-4xl mx-auto space-y-4">
        <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl overflow-hidden border border-blue-400/30 shadow-md bg-slate-900 mx-auto">
          <img src="/vulntwin-logo.jpg" alt="VulnTwin AI" className="w-full h-full object-cover" />
        </div>
        <span className="text-xs font-bold text-[#2563EB] uppercase tracking-wider bg-blue-50 px-3 py-1 rounded-full border border-blue-200">
          Core Engineering Team
        </span>
        <h1 className="text-2xl font-bold text-[#0B1F44]">
          VulnTwin AI Engineering Squad
        </h1>
        <p className="text-sm text-slate-500 leading-relaxed font-sans max-w-2xl mx-auto">
          Detect • Validate • Remediate • Secure. Our 4-member squad combines deterministic vulnerability scoring, controlled Digital Twin verification, and AI-grounded remediation.
        </p>
      </div>

      {/* 2. Team Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {teamMembers.map((member, idx) => {
          const Icon = member.icon;
          return (
            <div
              key={idx}
              className="bg-white border border-[#E2E8F0] rounded-xl p-6 shadow-sm hover:border-slate-300 transition-all flex flex-col justify-between space-y-4"
            >
              <div>
                <div className="flex items-center gap-3 mb-3">
                  <div className="w-10 h-10 rounded-lg bg-[#EFF6FF] border border-[#BFDBFE] text-[#2563EB] flex items-center justify-center shrink-0">
                    <Icon className="w-5 h-5" />
                  </div>
                  <div>
                    <h3 className="text-base font-bold text-[#0B1F44]">{member.name}</h3>
                    <div className="text-xs text-[#2563EB] font-semibold">{member.role}</div>
                  </div>
                </div>

                <p className="text-xs text-slate-600 leading-relaxed font-sans">
                  {member.description}
                </p>
              </div>

              <div>
                <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider mb-2">
                  Key Technical Ownership:
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {member.specialties.map((spec, sIdx) => (
                    <span
                      key={sIdx}
                      className="px-2 py-0.5 rounded text-[11px] bg-slate-50 border border-slate-200 text-slate-600 font-medium"
                    >
                      {spec}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* 3. Bottom Banner */}
      <div className="bg-[#0B1F44] rounded-xl p-8 text-white shadow-sm flex flex-col sm:flex-row items-center justify-between gap-6">
        <div className="space-y-1 text-center sm:text-left">
          <h3 className="text-lg font-bold">Ready to evaluate a security indicator?</h3>
          <p className="text-xs text-slate-300">
            Test the threat safely in an isolated Digital Twin without risking production stability.
          </p>
        </div>
        <button
          onClick={() => onNavigateToAnalyze && onNavigateToAnalyze()}
          className="px-5 py-2.5 bg-[#2563EB] hover:bg-blue-600 text-white font-semibold text-xs rounded-lg transition-colors flex items-center gap-2 shrink-0 shadow-sm"
        >
          <span>Open Analysis Scanner</span>
          <ArrowRight className="w-4 h-4" />
        </button>
      </div>

    </div>
  );
}
