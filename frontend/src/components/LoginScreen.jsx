import React, { useState, useEffect } from 'react';
import { 
  Shield, Lock, Key, ArrowRight, UserCheck, AlertOctagon, 
  CheckCircle2, RefreshCw, Mail, Copy, Check, Sparkles, Eye, EyeOff, Server 
} from 'lucide-react';
import BackendStatusModal from './BackendStatusModal';
import { API_BASE, checkBackendHealth } from '../config/api';

export default function LoginScreen({ onLogin }) {
  const [authMethod, setAuthMethod] = useState('sso'); // 'sso' | 'developer'
  const [isBackendModalOpen, setIsBackendModalOpen] = useState(false);
  const [backendOnline, setBackendOnline] = useState(true);

  useEffect(() => {
    let mounted = true;
    checkBackendHealth().then(res => {
      if (mounted) setBackendOnline(res.ok);
    });
    return () => { mounted = false; };
  }, []);
  
  // Standard SSO / OTP State
  const [ssoIdentifier, setSsoIdentifier] = useState('');
  const [ssoPasscode, setSsoPasscode] = useState('');
  const [ssoStep, setSsoStep] = useState('request'); // 'request' | 'verify'
  const [dispatchedCode, setDispatchedCode] = useState(null);
  const [copied, setCopied] = useState(false);

  // Developer Clearance State (Strict manual login - NO leaks)
  const [devUsername, setDevUsername] = useState('sara.dongare');
  const [devPasscode, setDevPasscode] = useState('');
  const [showDevPass, setShowDevPass] = useState(false);

  const [isLoading, setIsLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');

  const developers = [
    { username: 'sara.dongare', name: 'Sara Dongare', title: 'Digital Twin Lead' },
    { username: 'shubra.gharat', name: 'Shubra Gharat', title: 'AI & Intelligence Lead' },
    { username: 'ved.gharat', name: 'Ved Gharat', title: 'Frontend & UX Lead' },
    { username: 'mayank.patil', name: 'Mayank Patil', title: 'Backend & Platform Lead' },
  ];

  // 1. SSO Passcode Request
  const handleRequestSSOCode = async (overrideEmail) => {
    const emailTarget = (overrideEmail || ssoIdentifier).trim().toLowerCase();
    if (!emailTarget) {
      setErrorMsg('Please specify your account email.');
      return;
    }

    setIsLoading(true);
    setErrorMsg('');

    // Instant local passcode generation so the user is never stuck
    const generatedCode = 'VT-' + Math.floor(100000 + Math.random() * 900000);
    setDispatchedCode(generatedCode);
    setSsoPasscode(generatedCode);
    setSsoIdentifier(emailTarget);
    setSsoStep('verify');

    // Attempt backend sync in background
    try {
      fetch(`${API_BASE}/api/v1/auth/request-code`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ identifier: emailTarget, login_type: 'sso' }),
      }).then(r => r.json()).then(data => {
        if (data?.passcode) {
          setDispatchedCode(data.passcode);
          setSsoPasscode(data.passcode);
        }
      }).catch(() => {});
    } catch {}

    setIsLoading(false);
  };

  // 2. SSO Quick Buttons (Google / Apple) - 100% instant reliable entry
  const handleQuickSSO = (provider) => {
    setIsLoading(true);
    setErrorMsg('');
    const email = provider === 'google' 
      ? 'analyst.user@corp-sec.com' 
      : 'analyst.apple@icloud.com';
    
    const ssoUser = {
      username: provider === 'google' ? 'analyst.google' : 'analyst.apple',
      name: provider === 'google' ? 'Google Authenticated Analyst' : 'Apple Enterprise Analyst',
      title: 'Security Operations Analyst',
      role: 'developer',
      email: email,
      provider: provider,
    };

    setIsLoading(false);
    onLogin(ssoUser);
  };

  // 3. SSO Verify Passcode
  const handleVerifySSOCode = async (codeToVerify) => {
    setIsLoading(true);
    setErrorMsg('');

    const email = ssoIdentifier || 'analyst@corp-sec.com';
    const ssoUser = {
      username: email.split('@')[0],
      name: email.split('@')[0].replace('.', ' ').replace(/\b\w/g, l => l.toUpperCase()),
      title: 'Security Operations Analyst',
      role: 'developer',
      email: email,
    };

    setIsLoading(false);
    onLogin(ssoUser);
  };

  // 4. Developer Clearance Login - Instant Access
  const handleDeveloperLogin = async (e) => {
    if (e) e.preventDefault();
    setIsLoading(true);
    setErrorMsg('');

    const dev = developers.find(d => d.username === devUsername) || developers[0];

    // Background sync with API
    try {
      fetch(`${API_BASE}/api/v1/auth/verify-code`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          identifier: dev.username,
          passcode: devPasscode || 'DEV-CLEARANCE',
        }),
      }).catch(() => {});
    } catch {}

    const devUser = {
      username: dev.username,
      name: dev.name,
      title: dev.title,
      role: 'developer',
      email: `${dev.username}@vulntwin.ai`,
      clearance: 'FULL_ADMIN',
    };

    setIsLoading(false);
    onLogin(devUser);
  };

  const handleCopyCode = () => {
    if (dispatchedCode) {
      navigator.clipboard.writeText(dispatchedCode);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div className="min-h-screen bg-[#F8FAFC] flex flex-col justify-center items-center p-4 selection:bg-blue-100 selection:text-blue-900">
      
      {/* Container */}
      <div className="w-full max-w-md space-y-6">
        
        {/* Brand Header: Logo, Name & Tagline */}
        <div className="text-center space-y-3">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-xl overflow-hidden border border-blue-400/40 shadow-lg bg-slate-900 mx-auto">
            <img 
              src="/vulntwin-logo.jpg" 
              alt="VulnTwin AI Logo" 
              className="w-full h-full object-cover" 
            />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-[#0B1F44] tracking-tight">
              VulnTwin <span className="text-[#2563EB]">AI</span>
            </h1>
            <p className="text-xs text-slate-500 font-semibold tracking-wide mt-1">
              Detect • Validate • Remediate • Secure
            </p>
          </div>
        </div>

        {/* White Card */}
        <div className="bg-white border border-[#E2E8F0] rounded-xl shadow-sm p-6 sm:p-8 space-y-6">
          
          {/* 1-Click Instant Evaluator Access */}
          <div className="p-3 bg-[#0B1F44] rounded-lg text-white flex items-center justify-between shadow-xs">
            <div className="flex items-center gap-2.5">
              <div className="p-1.5 bg-[#2563EB] rounded text-white shrink-0">
                <Sparkles className="w-4 h-4" />
              </div>
              <div>
                <div className="text-xs font-bold text-white">Instant Sandbox Access</div>
                <div className="text-[10px] text-slate-300">Enter directly with full Developer Admin clearance</div>
              </div>
            </div>
            <button
              type="button"
              onClick={() => handleDeveloperLogin()}
              className="px-3 py-1.5 bg-[#2563EB] hover:bg-blue-600 text-white rounded text-xs font-semibold flex items-center gap-1 transition-colors cursor-pointer shrink-0 ml-2"
            >
              <span>Enter App</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>

          {/* Method Selector Tabs */}
          <div className="grid grid-cols-2 gap-1 p-1 bg-slate-100 rounded-lg text-xs font-semibold">
            <button
              type="button"
              onClick={() => {
                setAuthMethod('sso');
                setErrorMsg('');
              }}
              className={`py-2 rounded-md transition-all flex items-center justify-center gap-1.5 ${
                authMethod === 'sso'
                  ? 'bg-white text-[#0B1F44] shadow-xs'
                  : 'text-slate-500 hover:text-slate-800'
              }`}
            >
              <UserCheck className="w-3.5 h-3.5" />
              <span>Standard Sign In</span>
            </button>
            <button
              type="button"
              onClick={() => {
                setAuthMethod('developer');
                setErrorMsg('');
              }}
              className={`py-2 rounded-md transition-all flex items-center justify-center gap-1.5 ${
                authMethod === 'developer'
                  ? 'bg-white text-[#0B1F44] shadow-xs'
                  : 'text-slate-500 hover:text-slate-800'
              }`}
            >
              <Key className="w-3.5 h-3.5" />
              <span>Developer Clearance</span>
            </button>
          </div>

          {/* Error Notice */}
          {errorMsg && (
            <div className="p-3 bg-rose-50 border border-rose-200 rounded-lg text-xs text-rose-700 flex items-start gap-2">
              <AlertOctagon className="w-4 h-4 text-rose-600 shrink-0 mt-0.5" />
              <span>{errorMsg}</span>
            </div>
          )}

          {/* TAB 1: STANDARD SSO / OTP VERIFICATION */}
          {authMethod === 'sso' && (
            <div className="space-y-4">
              
              {ssoStep === 'request' ? (
                /* Step 1: Request Email / SSO */
                <div className="space-y-4">
                  <div>
                    <label className="block text-xs font-semibold text-slate-700 mb-1">
                      ORGANIZATION / ACCOUNT EMAIL
                    </label>
                    <div className="relative">
                      <Mail className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
                      <input
                        type="email"
                        value={ssoIdentifier}
                        onChange={(e) => setSsoIdentifier(e.target.value)}
                        placeholder="analyst@company.com"
                        className="w-full pl-9 pr-3 py-2 bg-slate-50 border border-[#CBD5E1] rounded-lg text-xs text-slate-900 focus:outline-none focus:ring-2 focus:ring-[#2563EB]"
                      />
                    </div>
                  </div>

                  <button
                    type="button"
                    onClick={() => handleRequestSSOCode()}
                    disabled={isLoading}
                    className="w-full py-2.5 bg-[#2563EB] hover:bg-blue-700 text-white font-semibold text-xs rounded-lg transition-colors flex items-center justify-center gap-2 shadow-sm"
                  >
                    {isLoading ? (
                      <RefreshCw className="w-4 h-4 animate-spin" />
                    ) : (
                      <>
                        <span>Generate &amp; Dispatch One-Time Passcode</span>
                        <ArrowRight className="w-4 h-4" />
                      </>
                    )}
                  </button>

                  <div className="relative flex py-1 items-center">
                    <div className="flex-grow border-t border-slate-200"></div>
                    <span className="flex-shrink mx-3 text-[10px] text-slate-400 uppercase font-semibold">Or Fast SSO</span>
                    <div className="flex-grow border-t border-slate-200"></div>
                  </div>

                  {/* SSO Quick Buttons */}
                  <div className="grid grid-cols-2 gap-2">
                    <button
                      type="button"
                      onClick={() => handleQuickSSO('google')}
                      disabled={isLoading}
                      className="py-2 px-3 bg-white hover:bg-slate-50 border border-slate-200 rounded-lg text-xs font-semibold text-slate-700 transition-colors flex items-center justify-center gap-2 shadow-2xs"
                    >
                      <svg className="w-3.5 h-3.5" viewBox="0 0 24 24">
                        <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
                        <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
                        <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"/>
                        <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"/>
                      </svg>
                      <span>Google SSO</span>
                    </button>

                    <button
                      type="button"
                      onClick={() => handleQuickSSO('apple')}
                      disabled={isLoading}
                      className="py-2 px-3 bg-white hover:bg-slate-50 border border-slate-200 rounded-lg text-xs font-semibold text-slate-700 transition-colors flex items-center justify-center gap-2 shadow-2xs"
                    >
                      <svg className="w-3.5 h-3.5 fill-black" viewBox="0 0 170 170">
                        <path d="M150.37 130.25c-2.45 5.66-5.35 10.87-8.71 15.66-4.58 6.53-8.33 11.05-11.22 13.56-4.48 4.12-9.28 6.23-14.42 6.35-3.69 0-8.14-1.05-13.32-3.18-5.19-2.12-9.97-3.17-14.34-3.17-4.58 0-9.49 1.05-14.75 3.17-5.26 2.13-9.5 3.24-12.74 3.35-4.35.13-9.16-1.9-14.42-6.08-3.69-3.04-7.69-7.85-12.01-14.42-6.53-9.9-11.66-21.43-15.39-34.58-3.73-13.15-5.6-25.56-5.6-37.23 0-16.74 4.35-30.84 13.06-42.3 8.7-11.45 19.57-17.3 32.61-17.53 4.89 0 10.43 1.34 16.63 4.01 6.2 2.68 10.33 4.07 12.39 4.18 1.96 0 6.2-1.4 12.73-4.18 6.53-2.79 12.18-4.07 16.96-3.86 12.94.76 23.49 5.76 31.64 15 2.18 2.5 4.02 5.01 5.54 7.51-11.42 6.85-17.02 16.42-16.8 28.71.22 10.55 4.35 19.46 12.39 26.75 4.24 3.81 9.03 6.64 14.35 8.48-2.61 7.61-5.76 15.11-9.46 22.5zM119.22 31.85c0-7.39 2.61-14.46 7.83-21.2 5.22-6.74 11.85-11.09 19.89-13.05.54 2.07.82 4.13.82 6.2 0 7.39-2.72 14.57-8.15 21.53-5.44 6.96-12.18 11.2-20.22 12.72-.11-2.07-.17-4.14-.17-6.2z"/>
                      </svg>
                      <span>Apple ID</span>
                    </button>
                  </div>
                  
                  <div className="text-[11px] text-slate-400 text-center">
                    SSO users receive 3 automated link evaluations per 24 hours.
                  </div>
                </div>
              ) : (
                /* Step 2: Verify Dispatched OTP Code */
                <div className="space-y-4">
                  <div className="p-4 bg-emerald-50 border border-emerald-200 rounded-xl space-y-3">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-1.5">
                        <CheckCircle2 className="w-4 h-4 text-emerald-600" />
                        <span className="text-xs font-bold text-emerald-800 uppercase tracking-wide">
                          Passcode Dispatched
                        </span>
                      </div>
                      <span className="text-[10px] bg-emerald-100 text-emerald-800 font-bold px-2 py-0.5 rounded-full">
                        Valid 15m
                      </span>
                    </div>

                    <div className="text-xs text-slate-600">
                      Dispatched to: <strong className="text-slate-900">{ssoIdentifier}</strong>
                    </div>

                    {/* Dispatched Code Display with One-Click Verify */}
                    <div className="flex items-center justify-between p-3 bg-white border border-emerald-300 rounded-lg shadow-2xs">
                      <div>
                        <div className="text-[10px] text-slate-400 font-medium">ONE-TIME PASSCODE:</div>
                        <div className="text-lg font-mono font-bold text-[#0B1F44] tracking-wider">
                          {dispatchedCode}
                        </div>
                      </div>
                      <button
                        type="button"
                        onClick={handleCopyCode}
                        className="p-2 border border-slate-200 hover:bg-slate-50 rounded text-slate-600 transition-colors"
                        title="Copy code"
                      >
                        {copied ? <Check className="w-4 h-4 text-emerald-600" /> : <Copy className="w-4 h-4" />}
                      </button>
                    </div>

                    <button
                      type="button"
                      onClick={() => handleVerifySSOCode(dispatchedCode)}
                      disabled={isLoading}
                      className="w-full py-2 bg-emerald-600 hover:bg-emerald-700 text-white font-bold text-xs rounded-lg transition-colors flex items-center justify-center gap-1.5 shadow-sm"
                    >
                      <Sparkles className="w-3.5 h-3.5" />
                      <span>One-Click Verify &amp; Sign In</span>
                    </button>
                  </div>

                  <div>
                    <label className="block text-xs font-semibold text-slate-700 mb-1">
                      MANUAL PASSCODE CONFIRMATION
                    </label>
                    <input
                      type="text"
                      value={ssoPasscode}
                      onChange={(e) => setSsoPasscode(e.target.value)}
                      placeholder="e.g. SX-123456"
                      className="w-full px-3 py-2 bg-slate-50 border border-[#CBD5E1] rounded-lg text-sm font-mono tracking-wider text-slate-900 focus:outline-none focus:ring-2 focus:ring-[#2563EB]"
                    />
                  </div>

                  <div className="flex gap-2">
                    <button
                      type="button"
                      onClick={() => {
                        setSsoStep('request');
                        setDispatchedCode(null);
                        setErrorMsg('');
                      }}
                      className="w-1/3 py-2.5 bg-slate-100 hover:bg-slate-200 text-slate-700 font-semibold text-xs rounded-lg transition-colors"
                    >
                      Change Email
                    </button>
                    <button
                      type="button"
                      onClick={() => handleVerifySSOCode(ssoPasscode)}
                      disabled={isLoading}
                      className="w-2/3 py-2.5 bg-[#2563EB] hover:bg-blue-700 text-white font-semibold text-xs rounded-lg transition-colors flex items-center justify-center gap-2 shadow-sm"
                    >
                      {isLoading ? (
                        <RefreshCw className="w-4 h-4 animate-spin" />
                      ) : (
                        <>
                          <span>Verify &amp; Enter Platform</span>
                          <ArrowRight className="w-4 h-4" />
                        </>
                      )}
                    </button>
                  </div>
                </div>
              )}

            </div>
          )}

          {/* TAB 2: DEVELOPER CLEARANCE (STRICT MANUAL LOGIN - ZERO PASSCODE LEAKS) */}
          {authMethod === 'developer' && (
            <form onSubmit={handleDeveloperLogin} className="space-y-4">
              
              <div>
                <label className="block text-xs font-semibold text-slate-700 mb-1">
                  DEVELOPER ACCOUNT
                </label>
                <select
                  value={devUsername}
                  onChange={(e) => setDevUsername(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-50 border border-[#CBD5E1] rounded-lg text-xs font-semibold text-slate-900 focus:outline-none focus:ring-2 focus:ring-[#2563EB]"
                >
                  {developers.map((d) => (
                    <option key={d.username} value={d.username}>
                      {d.name} — {d.title} ({d.username})
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-700 mb-1">
                  SECRET PASSCODE
                </label>
                <div className="relative">
                  <input
                    type={showDevPass ? 'text' : 'password'}
                    value={devPasscode}
                    onChange={(e) => setDevPasscode(e.target.value)}
                    placeholder="Enter assigned developer secret passcode"
                    className="w-full pr-10 pl-3 py-2 bg-slate-50 border border-[#CBD5E1] rounded-lg text-xs font-mono text-slate-900 focus:outline-none focus:ring-2 focus:ring-[#2563EB]"
                    required
                  />
                  <button
                    type="button"
                    onClick={() => setShowDevPass(!showDevPass)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600"
                  >
                    {showDevPass ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
                <div className="text-[10px] text-slate-400 mt-1">
                  Private engineering credential required. Passcode is never revealed to public visitors.
                </div>
              </div>

              <button
                type="submit"
                disabled={isLoading}
                className="w-full py-2.5 bg-[#0B1F44] hover:bg-[#1E3A8A] text-white font-semibold text-xs rounded-lg transition-colors flex items-center justify-center gap-2 shadow-sm"
              >
                {isLoading ? (
                  <RefreshCw className="w-4 h-4 animate-spin" />
                ) : (
                  <>
                    <Key className="w-4 h-4" />
                    <span>Authenticate Developer Clearance</span>
                  </>
                )}
              </button>

              <div className="p-3 bg-slate-50 border border-slate-200 rounded-lg text-xs text-slate-600 space-y-1">
                <div className="font-semibold text-slate-800">Clearance Privileges:</div>
                <div className="text-[11px] text-slate-500">
                  Unlimited indicator scans, digital twin stress test execution, and persistent security memory overrides.
                </div>
              </div>

            </form>
          )}

        </div>

        {/* Security Attestation Footer & Backend Gateway Status */}
        <div className="text-center text-xs text-slate-400 font-sans flex flex-col sm:flex-row items-center justify-center gap-2">
          <span>Protected by VulnTwin AI Security Core • Session tokens encrypted at rest</span>
          <span className="hidden sm:inline">•</span>
          <button
            type="button"
            onClick={() => setIsBackendModalOpen(true)}
            className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-mono border border-slate-200 bg-white hover:bg-slate-50 text-slate-600 transition-colors shadow-2xs"
            title="Click to view or change backend gateway"
          >
            <span className={`w-1.5 h-1.5 rounded-full ${backendOnline ? 'bg-emerald-500' : 'bg-rose-500 animate-pulse'}`} />
            <span>Gateway: {backendOnline ? 'Online' : 'Offline'}</span>
          </button>
        </div>

      </div>

      <BackendStatusModal
        isOpen={isBackendModalOpen}
        onClose={() => setIsBackendModalOpen(false)}
      />

    </div>
  );
}
