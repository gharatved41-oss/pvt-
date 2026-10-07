import React, { useState } from 'react';
import { CheckCircle2, AlertTriangle, ShieldAlert, Cpu, ArrowRight, Play, RefreshCw } from 'lucide-react';

export default function ValidationView({ onNavigateToTwin }) {
  const [activeTest, setActiveTest] = useState(null);
  const [testingIndex, setTestingIndex] = useState(null);

  const validationTests = [
    {
      id: 'VAL-01',
      name: 'Simulated Drive-by Dropper Ingress Probe',
      component: 'Web Server / Gateway',
      testType: 'Controlled Binary GET Probe',
      safetyConstraint: 'Zero execution on host; twin HTTP envelope inspection only',
      impactAssessment: 'High — Remote code delivery vector confirmed',
      result: 'CONFIRMED_VULNERABLE',
      details: 'Twin observed unauthenticated executable header delivery without client validation.'
    },
    {
      id: 'VAL-02',
      name: 'SSL Stripping & Security Header Verification',
      component: 'Transport / Reverse Proxy',
      testType: 'Passive Header Directives Probe',
      safetyConstraint: 'Synthetic handshake simulation in isolated twin network',
      impactAssessment: 'Medium — AiTM credential interception possible',
      result: 'CONFIRMED_VULNERABLE',
      details: 'Twin recorded 0 HSTS and CSP directives in the response envelope.'
    },
    {
      id: 'VAL-03',
      name: 'SQL Injection & Parameter Tampering Probe',
      component: 'API Layer / Database Gateway',
      testType: 'Synthetic Input Fuzzing against Virtual DB',
      safetyConstraint: 'Fuzzing targeted against ephemeral SQLite replica, not production DB',
      impactAssessment: 'Low — Parameterized queries blocked injection',
      result: 'RESILIENT_SECURE',
      details: 'Digital Twin database successfully rejected malicious query strings without error leakage.'
    },
    {
      id: 'VAL-04',
      name: 'Open Redirection Phishing Relay Probe',
      component: 'Application Routing Handler',
      testType: 'Synthetic Redirect Traversal',
      safetyConstraint: 'Loopback sandbox; external redirection blocked by twin guard',
      impactAssessment: 'Medium — Phishing relay exploitation feasible',
      result: 'CONFIRMED_VULNERABLE',
      details: 'Twin permitted navigation to unverified query parameters without hostname checking.'
    }
  ];

  const handleRunSingleTest = (idx) => {
    setTestingIndex(idx);
    setTimeout(() => {
      setTestingIndex(null);
    }, 900);
  };

  return (
    <div className="space-y-6 max-w-6xl mx-auto pb-12">
      
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-[#0B1F44]">
            Controlled Security Validation
          </h1>
          <p className="text-sm text-slate-500 mt-1">
            Testing exploitability on virtual replicas — distinguishing theoretical weaknesses from real threats.
          </p>
        </div>

        <button
          onClick={() => onNavigateToTwin && onNavigateToTwin()}
          className="px-4 py-2 bg-[#2563EB] hover:bg-blue-700 text-white font-semibold text-xs rounded-lg transition-colors shadow-sm flex items-center gap-1.5"
        >
          <Cpu className="w-3.5 h-3.5" />
          <span>Go to Digital Twin</span>
        </button>
      </div>

      {/* Safety Callout Box */}
      <div className="bg-white border border-[#E2E8F0] rounded-xl p-5 shadow-sm space-y-2">
        <div className="flex items-center gap-2 text-xs font-bold text-[#2563EB] uppercase tracking-wider">
          <CheckCircle2 className="w-4 h-4 text-emerald-600" />
          <span>Zero-Risk Validation Principle</span>
        </div>
        <p className="text-sm text-slate-600 leading-relaxed font-sans">
          Unlike traditional security scanners that merely report theoretical CVEs, VulnTwin AI performs <strong>controlled validation probes</strong> exclusively inside the isolated Digital Twin. If a probe fails, only the virtual copy is affected — your live production systems, databases, and customer traffic remain completely untouched.
        </p>
      </div>

      {/* Validation Test List */}
      <div className="bg-white border border-[#E2E8F0] rounded-xl shadow-sm overflow-hidden">
        <div className="px-6 py-4 border-b border-[#E2E8F0] flex items-center justify-between">
          <h3 className="text-sm font-bold text-[#0B1F44]">Automated Validation Test Suites</h3>
          <span className="text-xs text-slate-500">4 Suites Configured</span>
        </div>

        <div className="divide-y divide-[#E2E8F0]">
          {validationTests.map((test, idx) => (
            <div key={test.id} className="p-5 hover:bg-slate-50/80 transition-colors space-y-3">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <div className="flex items-center gap-2.5">
                  <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-100 text-slate-700 font-semibold border border-slate-200">
                    {test.id}
                  </span>
                  <h4 className="text-sm font-bold text-slate-900">{test.name}</h4>
                  <span className="text-xs text-slate-500">({test.component})</span>
                </div>

                <div className="flex items-center gap-3">
                  <span className={`text-xs font-bold px-2.5 py-0.5 rounded-full border ${
                    test.result === 'CONFIRMED_VULNERABLE'
                      ? 'bg-rose-50 text-rose-700 border-rose-200'
                      : 'bg-emerald-50 text-emerald-700 border-emerald-200'
                  }`}>
                    {test.result === 'CONFIRMED_VULNERABLE' ? '● Confirmed Exploitable' : '● Resilient / Blocked'}
                  </span>

                  <button
                    onClick={() => handleRunSingleTest(idx)}
                    disabled={testingIndex === idx}
                    className="px-3 py-1 bg-white border border-slate-300 hover:bg-[#EFF6FF] hover:border-[#BFDBFE] text-xs font-semibold text-[#2563EB] rounded-lg transition-colors flex items-center gap-1.5 shadow-2xs"
                  >
                    {testingIndex === idx ? (
                      <>
                        <RefreshCw className="w-3 h-3 animate-spin" />
                        <span>Validating...</span>
                      </>
                    ) : (
                      <>
                        <Play className="w-3 h-3" />
                        <span>Run Probe</span>
                      </>
                    )}
                  </button>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs pt-1">
                <div className="p-2.5 bg-[#F8FAFC] border border-[#E2E8F0] rounded-lg">
                  <span className="font-semibold text-slate-700 block">Safety Guard:</span>
                  <span className="text-slate-500">{test.safetyConstraint}</span>
                </div>
                <div className="p-2.5 bg-[#F8FAFC] border border-[#E2E8F0] rounded-lg">
                  <span className="font-semibold text-slate-700 block">Impact Assessment:</span>
                  <span className="text-slate-500">{test.impactAssessment}</span>
                </div>
              </div>

              <p className="text-xs text-slate-600 font-mono">
                Verification Result: {test.details}
              </p>
            </div>
          ))}
        </div>
      </div>

    </div>
  );
}
