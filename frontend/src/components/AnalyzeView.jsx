import React, { useState, useEffect } from 'react';
import { 
  Search, ShieldAlert, ShieldCheck, AlertTriangle, HelpCircle, 
  ArrowRight, RefreshCw, ExternalLink, Cpu, CheckCircle2, 
  Layers, Lock, AlertOctagon, Terminal, FileCode2, Copy, Check,
  GitBranch, Globe, Key, Shield, Printer, Sparkles, UserCheck, Wrench
} from 'lucide-react';
import { API_BASE } from '../config/api';

export default function AnalyzeView({ onSelectAnalysis, onNavigateToTwin, currentUser, onOpenAuth }) {
  const [inputValue, setInputValue] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');
  const [result, setResult] = useState(null);
  const [copied, setCopied] = useState(false);
  const [quotaInfo, setQuotaInfo] = useState(null);

  // Fetch quota
  useEffect(() => {
    const fetchQuota = async () => {
      try {
        const headers = {
          'x-user-identifier': currentUser?.email || currentUser?.username || 'anonymous',
          'x-user-role': currentUser?.role || 'user'
        };
        const res = await fetch(`${API_BASE}/api/v1/user/quota`, { headers });
        if (res.ok) {
          const data = await res.json();
          setQuotaInfo(data);
        }
      } catch (err) {
        console.warn('Quota check fallback:', err);
      }
    };
    fetchQuota();
  }, [currentUser]);

  // Realistic Target System & Vulnerability Presets
  const presets = [
    {
      title: 'E-Commerce App (SQL Injection Probe)',
      value: "https://shop.acme-corp.internal/products?id=1' UNION SELECT username,password FROM users--",
      badge: 'SQLi (Critical)',
      badgeClass: 'bg-rose-50 text-rose-700 border-rose-200'
    },
    {
      title: 'Customer Portal (Reflected XSS)',
      value: 'https://portal.enterprise.internal/search?query=<script>alert(document.cookie)</script>',
      badge: 'XSS Vector',
      badgeClass: 'bg-rose-50 text-rose-700 border-rose-200'
    },
    {
      title: 'API Gateway (Spring Actuator Env Leak)',
      value: 'https://api.internal-cloud.corp/actuator/env',
      badge: 'Env Exposure',
      badgeClass: 'bg-amber-50 text-amber-700 border-amber-200'
    },
    {
      title: 'Storage Service (Path Traversal LFI)',
      value: 'https://files.backup-storage.corp/view?file=../../../../etc/passwd',
      badge: 'LFI / Traversal',
      badgeClass: 'bg-rose-50 text-rose-700 border-rose-200'
    },
    {
      title: 'Verified Production Asset (Clean Baseline)',
      value: 'https://auth.company.org/health',
      badge: 'Safe Baseline',
      badgeClass: 'bg-emerald-50 text-emerald-700 border-emerald-200'
    }
  ];

  const handleRunAnalysis = async (customValue) => {
    if (!currentUser) {
      setErrorMsg('Authentication Required: Please sign in to perform vulnerability analysis.');
      if (onOpenAuth) onOpenAuth();
      return;
    }

    if (currentUser.role === 'user' && quotaInfo && quotaInfo.can_analyze === false) {
      setErrorMsg('Daily evaluation limit reached (3/3 evaluations used today). Quota resets at 00:00 UTC.');
      return;
    }

    const val = (customValue !== undefined ? customValue : inputValue).trim();
    if (!val) {
      setErrorMsg('Please specify a valid URL, domain, IP address or CVE/hash indicator.');
      return;
    }

    setErrorMsg('');
    setIsLoading(true);
    setResult(null);

    const isHash = /^[a-fA-F0-9]{32,64}$/.test(val);

    try {
      const endpoint = isHash 
        ? `${API_BASE}/api/v1/analyze/hash`
        : `${API_BASE}/api/v1/analyze/url`;

      const payload = isHash ? { hash: val } : { url: val, force_refresh: true };

      const response = await fetch(endpoint, {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'x-user-identifier': currentUser.email || currentUser.username || 'anonymous',
          'x-user-role': currentUser.role || 'user'
        },
        body: JSON.stringify(payload),
      });

      if (!response.ok) {
        const errorData = await response.json();
        if (response.status === 429) {
          setQuotaInfo((prev) => ({ ...prev, remaining: 0, can_analyze: false, used_today: 3 }));
        }
        throw new Error(errorData.detail || 'Analysis service returned an error.');
      }

      const data = await response.json();
      setResult(data);
      if (onSelectAnalysis) {
        onSelectAnalysis(data);
      }
      if (data.quota) {
        setQuotaInfo(data.quota);
      }
    } catch (err) {
      setErrorMsg(err.message || 'Unable to connect to backend server on port 8001.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleCopy = (text) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const isQuotaExhausted = currentUser?.role === 'user' && quotaInfo && quotaInfo.can_analyze === false;

  return (
    <div className="space-y-6 max-w-5xl mx-auto pb-12">
      
      {/* 1. Header Information */}
      <div>
        <h1 className="text-2xl font-bold text-[#0B1F44]">
          Security Analysis
        </h1>
        <p className="text-sm text-slate-500 mt-1">
          Safely analyze a URL, domain, IP address, or security indicator without executing untrusted code on production.
        </p>
      </div>

      {/* 2. Clean Enterprise Input Box */}
      <div className="bg-white border border-[#E2E8F0] rounded-xl p-6 shadow-sm space-y-4">
        
        {/* Quota Status Notice for Users */}
        {isQuotaExhausted && (
          <div className="p-3 bg-slate-50 border border-slate-200 rounded-lg text-xs text-slate-700 flex items-center gap-2">
            <AlertOctagon className="w-4 h-4 text-slate-500 shrink-0" />
            <span>Daily evaluation quota reached (3/3 used today). Reset at 00:00 UTC.</span>
          </div>
        )}

        <div>
          <label className="block text-xs font-semibold text-slate-700 mb-2 uppercase tracking-wider">
            Target URL / Domain / IP / Indicator
          </label>
          <div className="flex flex-col sm:flex-row gap-3">
            <input
              type="text"
              value={inputValue}
              onChange={(e) => setInputValue(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleRunAnalysis()}
              disabled={isQuotaExhausted || isLoading}
              placeholder="e.g. http://vlc-fast-updater.xyz/vlc_setup.exe or https://example.com"
              className="flex-1 px-4 py-2.5 bg-slate-50 border border-[#E2E8F0] rounded-lg text-sm text-slate-900 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-[#2563EB] focus:border-transparent transition-all disabled:opacity-50"
            />

            <button
              onClick={() => handleRunAnalysis()}
              disabled={isLoading || isQuotaExhausted}
              className="px-6 py-2.5 bg-[#2563EB] hover:bg-blue-700 text-white font-semibold text-sm rounded-lg transition-colors shadow-sm flex items-center justify-center gap-2 shrink-0 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {isLoading ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin text-white" />
                  <span>Analyzing...</span>
                </>
              ) : (
                <span>Analyze Target</span>
              )}
            </button>
          </div>
        </div>

        {errorMsg && (
          <div className="p-3 bg-red-50 border border-red-200 rounded-lg text-xs text-red-700 flex items-center gap-2">
            <AlertOctagon className="w-4 h-4 text-red-600 shrink-0" />
            <span>{errorMsg}</span>
          </div>
        )}

        {/* Target Presets */}
        <div className="pt-3 border-t border-[#F1F5F9]">
          <span className="text-xs font-medium text-slate-400 block mb-2">
            Preset Test Indicators:
          </span>
          <div className="flex flex-wrap gap-2">
            {presets.map((preset, idx) => (
              <button
                key={idx}
                type="button"
                onClick={() => {
                  setInputValue(preset.value);
                  handleRunAnalysis(preset.value);
                }}
                className="px-3 py-1.5 bg-white border border-[#E2E8F0] hover:border-slate-400 rounded-lg text-xs text-slate-700 flex items-center gap-2 transition-colors shadow-2xs"
              >
                <span>{preset.title}</span>
                <span className={`text-[10px] px-1.5 py-0.2 rounded font-semibold border ${preset.badgeClass}`}>
                  {preset.badge}
                </span>
              </button>
            ))}
          </div>
        </div>

      </div>

      {/* 3. Analysis Results Section */}
      {result && (
        <div className="space-y-6">
          
          {/* Main Assessment Card */}
          <div className="bg-white border border-[#E2E8F0] rounded-xl p-6 shadow-sm space-y-6">
            
            {/* Top row: Target, Risk Badge, Exploitability */}
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-6 pb-6 border-b border-[#E2E8F0]">
              
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-semibold px-2 py-0.5 rounded bg-slate-100 text-slate-700 border border-slate-200">
                    {result.analysis_id}
                  </span>
                  <span className="text-xs text-slate-500 font-medium">
                    Type: {result.indicator_type}
                  </span>
                </div>
                <div className="flex items-center gap-2 pt-1">
                  <h2 className="text-lg font-bold text-slate-900 break-all font-mono">
                    {result.submitted_url}
                  </h2>
                  <button
                    onClick={() => handleCopy(result.submitted_url)}
                    className="text-slate-400 hover:text-slate-600 p-1"
                    title="Copy URL"
                  >
                    {copied ? <Check className="w-4 h-4 text-emerald-600" /> : <Copy className="w-4 h-4" />}
                  </button>
                </div>
                {result.domain && (
                  <p className="text-xs text-slate-500">
                    Host: <span className="text-slate-700 font-semibold">{result.domain}</span>
                  </p>
                )}
              </div>

              {/* Security Scores */}
              <div className="flex items-center gap-6 shrink-0">
                
                {/* Risk Score */}
                <div className="text-center px-4 py-2 bg-slate-50 border border-slate-200 rounded-lg">
                  <div className="text-2xl font-bold leading-tight" style={{
                    color: result.risk_score >= 70 ? '#EF4444' : result.risk_score >= 40 ? '#F59E0B' : '#10B981'
                  }}>
                    {result.risk_score}<span className="text-xs font-normal text-slate-400">/100</span>
                  </div>
                  <div className="text-[10px] font-semibold uppercase text-slate-500">Risk Score</div>
                </div>

                {/* Verdict Badge */}
                <div className="space-y-1 text-center">
                  <div className={`px-3 py-1 rounded-full text-xs font-bold border ${
                    result.verdict === 'MALICIOUS'
                      ? 'bg-rose-50 text-rose-700 border-rose-200'
                      : result.verdict === 'SUSPICIOUS'
                      ? 'bg-amber-50 text-amber-700 border-amber-200'
                      : 'bg-emerald-50 text-emerald-700 border-emerald-200'
                  }`}>
                    {result.verdict === 'MALICIOUS' ? '● High Threat' : result.verdict === 'SUSPICIOUS' ? '● Suspicious' : '● Safe'}
                  </div>
                  <div className="text-[11px] text-slate-500">
                    Confidence: <strong>{Math.round(result.confidence * 100)}%</strong>
                  </div>
                </div>

                {/* Exploitability Level */}
                <div className="text-center px-4 py-2 bg-slate-50 border border-slate-200 rounded-lg">
                  <div className="text-sm font-bold text-[#2563EB]">
                    {result.exploitability?.level || 'MEDIUM'}
                  </div>
                  <div className="text-[10px] font-semibold uppercase text-slate-500">Exploitability</div>
                </div>

              </div>

            </div>

            {/* Grounded Explanation with discreet AI Badge */}
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-slate-700 uppercase tracking-wider">
                  Analysis Explanation
                </span>
                <span className="text-[11px] px-2 py-0.5 rounded bg-blue-50 text-[#2563EB] border border-blue-200 font-medium">
                  AI-assisted explanation
                </span>
              </div>
              <p className="text-sm text-slate-600 leading-relaxed bg-[#F8FAFC] p-4 rounded-lg border border-[#E2E8F0]">
                {result.summary}
              </p>
            </div>

            {/* Action Bar: Verify on Digital Twin CTA */}
            <div className="pt-2 flex flex-wrap items-center justify-between gap-4 border-t border-[#E2E8F0]">
              <div className="flex items-center gap-3">
                <button
                  onClick={() => onNavigateToTwin && onNavigateToTwin(result)}
                  className="px-5 py-2.5 bg-[#2563EB] hover:bg-blue-700 text-white font-semibold text-xs rounded-lg transition-colors shadow-sm flex items-center gap-2"
                >
                  <Cpu className="w-4 h-4" />
                  <span>Verify on Digital Twin &amp; Run Re-test</span>
                  <ArrowRight className="w-4 h-4" />
                </button>
                <a
                  href={`${API_BASE}/api/v1/analysis/${result.analysis_id}/export/markdown`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="px-4 py-2.5 bg-white border border-[#E2E8F0] hover:bg-slate-50 text-slate-700 font-semibold text-xs rounded-lg transition-colors flex items-center gap-2"
                >
                  <Printer className="w-4 h-4 text-slate-500" />
                  <span>Export Report (.md)</span>
                </a>
              </div>
              <span className="text-xs text-slate-500">
                Safe testing in virtual twin with zero production risk
              </span>
            </div>

          </div>

          {/* Evidence List Card */}
          <div className="bg-white border border-[#E2E8F0] rounded-xl p-6 shadow-sm space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-[#E2E8F0]">
              <div className="flex items-center gap-2">
                <Layers className="w-4 h-4 text-[#2563EB]" />
                <h3 className="text-sm font-bold text-slate-900">
                  Supporting Evidence &amp; Signals ({result.evidence?.length || 0})
                </h3>
              </div>
              <span className="text-xs text-slate-500">Corroborated Telemetry</span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {result.evidence?.map((ev, i) => (
                <div key={i} className="p-3 bg-[#F8FAFC] border border-[#E2E8F0] rounded-lg space-y-1">
                  <div className="flex items-start justify-between gap-2">
                    <span className="text-xs font-semibold text-slate-800">{ev.title}</span>
                    <span className={`text-[10px] px-2 py-0.5 rounded font-semibold shrink-0 ${
                      ev.severity === 'HIGH' || ev.severity === 'CRITICAL'
                        ? 'bg-rose-50 text-rose-700 border border-rose-200'
                        : ev.severity === 'MEDIUM'
                        ? 'bg-amber-50 text-amber-700 border border-amber-200'
                        : 'bg-slate-100 text-slate-600 border border-slate-200'
                    }`}>
                      {ev.severity}
                    </span>
                  </div>
                  <p className="text-xs text-slate-500 leading-snug">{ev.description}</p>
                  <div className="text-[10px] text-slate-400 pt-1">
                    Source: {ev.source}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* SafePath Verified Alternative (If available) */}
          {result.safepath && (
            <div className="bg-white border border-blue-200 bg-blue-50/20 rounded-xl p-6 shadow-sm space-y-4">
              <div className="flex items-center gap-2 text-xs font-bold text-[#2563EB] uppercase tracking-wider">
                <ShieldCheck className="w-4 h-4" />
                <span>SafePath™ Verified Software Alternative</span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="p-4 bg-white border border-red-200 rounded-lg space-y-1.5">
                  <span className="text-[11px] font-semibold text-red-700 uppercase">Unverified Source Detected</span>
                  <div className="text-xs font-mono text-slate-800 break-all">{result.safepath.original_url}</div>
                  <div className="text-xs text-slate-500">
                    Risk: <strong className="text-red-600">{result.safepath.original_risk}/100</strong> (Potential trojan bundle)
                  </div>
                </div>

                <div className="p-4 bg-white border border-emerald-300 rounded-lg space-y-1.5">
                  <span className="text-[11px] font-semibold text-emerald-700 uppercase">Official Vendor Repository</span>
                  <div className="text-xs font-bold text-slate-900">{result.safepath.recommended_name}</div>
                  <div className="text-xs font-mono text-slate-600 break-all">{result.safepath.recommended_url}</div>
                  <div className="text-xs text-slate-500">
                    Risk: <strong className="text-emerald-600">{result.safepath.recommended_risk}/100</strong> ({result.safepath.trust_level})
                  </div>
                  <div className="pt-1">
                    <a
                      href={result.safepath.recommended_url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1.5 text-xs text-[#2563EB] font-semibold hover:underline"
                    >
                      <span>Visit Authentic Vendor Download</span>
                      <ExternalLink className="w-3.5 h-3.5" />
                    </a>
                  </div>
                </div>
              </div>
            </div>
          )}

        </div>
      )}

    </div>
  );
}
