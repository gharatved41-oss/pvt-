import React, { useState, useEffect } from 'react';
import { 
  Shield, Key, ArrowRight, UserCheck, AlertOctagon, 
  RefreshCw, Eye, EyeOff 
} from 'lucide-react';
import BackendStatusModal from './BackendStatusModal';
import { API_BASE, checkBackendHealth } from '../config/api';

const EMAIL_REGEX = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;

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
  
  // Standard User State
  const [ssoIdentifier, setSsoIdentifier] = useState('');
  const [ssoPasscode, setSsoPasscode] = useState('');
  const [ssoStep, setSsoStep] = useState('request'); // 'request' | 'verify'
  const [codeDispatchedMessage, setCodeDispatchedMessage] = useState('');

  // Developer Clearance State
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

  // 1. Standard Passcode Request (Via Backend Only)
  const handleRequestSSOCode = async (e) => {
    if (e) e.preventDefault();
    const emailTarget = ssoIdentifier.trim().toLowerCase();
    
    if (!emailTarget || !EMAIL_REGEX.test(emailTarget)) {
      setErrorMsg('Please specify a valid corporate email address (e.g. analyst@company.com). Bare digits or invalid identifiers are rejected.');
      return;
    }

    setIsLoading(true);
    setErrorMsg('');

    try {
      const res = await fetch(`${API_BASE}/api/v1/auth/request-code`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ identifier: emailTarget, login_type: 'sso' }),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail || 'Failed to request security passcode.');
      }

      setCodeDispatchedMessage(`Passcode dispatched for ${emailTarget}. Please enter your code below.`);
      setSsoStep('verify');
      setSsoPasscode('');
    } catch (err) {
      setErrorMsg(err.message || 'Error communicating with security gateway.');
    } finally {
      setIsLoading(false);
    }
  };

  // 2. Standard Passcode Verification (Strict Backend Validation)
  const handleVerifySSOCode = async (e) => {
    if (e) e.preventDefault();
    const cleanCode = ssoPasscode.trim();
    if (!cleanCode) {
      setErrorMsg('Please enter the security passcode received.');
      return;
    }

    setIsLoading(true);
    setErrorMsg('');

    try {
      const res = await fetch(`${API_BASE}/api/v1/auth/verify-code`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          identifier: ssoIdentifier.trim().toLowerCase(),
          passcode: cleanCode,
        }),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail || 'Invalid passcode. Access denied.');
      }

      if (data.status === 'authenticated' && data.user) {
        onLogin(data.user);
      } else {
        throw new Error('Authentication failed.');
      }
    } catch (err) {
      setErrorMsg(err.message || 'Authentication error.');
    } finally {
      setIsLoading(false);
    }
  };

  // 3. Developer Clearance Login (STRICT Backend Verification - NO SHORTCUTS)
  const handleDeveloperLogin = async (e) => {
    if (e) e.preventDefault();
    const cleanPass = devPasscode.trim();

    if (!cleanPass) {
      setErrorMsg('Developer secret passcode is required.');
      return;
    }

    setIsLoading(true);
    setErrorMsg('');

    try {
      const res = await fetch(`${API_BASE}/api/v1/auth/verify-code`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          identifier: devUsername.trim().toLowerCase(),
          passcode: cleanPass,
        }),
      });

      const data = await res.json();
      if (!res.ok) {
        // Backend returns HTTP 401 if passcode is incorrect
        throw new Error(data.detail || 'Invalid developer credentials. Access denied.');
      }

      if (data.status === 'authenticated' && data.user) {
        onLogin(data.user);
      } else {
        throw new Error('Developer authentication failed.');
      }
    } catch (err) {
      setErrorMsg(err.message || 'Authentication failed. Please verify your credentials.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#F8FAFC] flex flex-col justify-center items-center p-4 selection:bg-blue-100 selection:text-blue-900 font-sans">
      
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
              Continuous Threat Exposure Management (CTEM)
            </p>
          </div>
        </div>

        {/* White Card */}
        <div className="bg-white border border-[#E2E8F0] rounded-xl shadow-sm p-6 sm:p-8 space-y-6">
          
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

          {/* TAB 1: STANDARD USER AUTH */}
          {authMethod === 'sso' && (
            <div className="space-y-4">
              {ssoStep === 'request' ? (
                <form onSubmit={handleRequestSSOCode} className="space-y-4">
                  <div>
                    <label className="block text-xs font-semibold text-slate-700 mb-1">
                      CORPORATE EMAIL
                    </label>
                    <input
                      type="email"
                      value={ssoIdentifier}
                      onChange={(e) => setSsoIdentifier(e.target.value)}
                      placeholder="analyst@enterprise.com"
                      className="w-full px-3 py-2 bg-slate-50 border border-[#CBD5E1] rounded-lg text-xs text-slate-900 focus:outline-none focus:ring-2 focus:ring-[#2563EB]"
                      required
                    />
                  </div>

                  <button
                    type="submit"
                    disabled={isLoading}
                    className="w-full py-2.5 bg-[#0B1F44] hover:bg-[#1E3A8A] text-white font-semibold text-xs rounded-lg transition-colors flex items-center justify-center gap-2 shadow-sm disabled:opacity-50"
                  >
                    {isLoading ? (
                      <RefreshCw className="w-4 h-4 animate-spin" />
                    ) : (
                      <>
                        <span>Request Access Code</span>
                        <ArrowRight className="w-4 h-4" />
                      </>
                    )}
                  </button>
                </form>
              ) : (
                <form onSubmit={handleVerifySSOCode} className="space-y-4">
                  {codeDispatchedMessage && (
                    <div className="p-2.5 bg-blue-50 border border-blue-200 text-blue-700 text-xs rounded-lg">
                      {codeDispatchedMessage}
                    </div>
                  )}

                  <div>
                    <label className="block text-xs font-semibold text-slate-700 mb-1">
                      ENTER ACCESS PASSCODE
                    </label>
                    <input
                      type="text"
                      value={ssoPasscode}
                      onChange={(e) => setSsoPasscode(e.target.value)}
                      placeholder="e.g. SX-123456"
                      className="w-full px-3 py-2 bg-slate-50 border border-[#CBD5E1] rounded-lg text-sm font-mono tracking-wider text-slate-900 focus:outline-none focus:ring-2 focus:ring-[#2563EB]"
                      required
                    />
                  </div>

                  <div className="flex gap-2">
                    <button
                      type="button"
                      onClick={() => {
                        setSsoStep('request');
                        setErrorMsg('');
                      }}
                      className="w-1/3 py-2.5 bg-slate-100 hover:bg-slate-200 text-slate-700 font-semibold text-xs rounded-lg transition-colors"
                    >
                      Change Email
                    </button>
                    <button
                      type="submit"
                      disabled={isLoading}
                      className="w-2/3 py-2.5 bg-[#2563EB] hover:bg-blue-700 text-white font-semibold text-xs rounded-lg transition-colors flex items-center justify-center gap-2 shadow-sm disabled:opacity-50"
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
                </form>
              )}
            </div>
          )}

          {/* TAB 2: DEVELOPER CLEARANCE (STRICT BACKEND VERIFICATION) */}
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
                  Verified with backend RBAC security engine. Passcode is never bypassed.
                </div>
              </div>

              <button
                type="submit"
                disabled={isLoading}
                className="w-full py-2.5 bg-[#0B1F44] hover:bg-[#1E3A8A] text-white font-semibold text-xs rounded-lg transition-colors flex items-center justify-center gap-2 shadow-sm disabled:opacity-50"
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
