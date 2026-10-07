import React, { useState } from 'react';
import { X, Lock, Key, CheckCircle2, AlertOctagon, ArrowRight, UserCheck, Shield } from 'lucide-react';

export const DEVELOPER_ACCOUNTS = [
  {
    username: 'sara.dongare',
    passcode: 'SX-DEV-SARA-9021',
    name: 'Sara Dongare',
    role: 'Digital Twin & Safe Verification Lead',
    badge: 'LEAD // TWIN_VERIFY',
  },
  {
    username: 'shubra.gharat',
    passcode: 'SX-DEV-SHUBRA-4418',
    name: 'Shubra Gharat',
    role: 'AI & Risk Intelligence Lead',
    badge: 'LEAD // AI_EXPLOIT',
  },
  {
    username: 'ved.gharat',
    passcode: 'SX-DEV-VED-7732',
    name: 'Ved Gharat',
    role: 'Frontend & User Experience Lead',
    badge: 'LEAD // FRONTEND',
  },
  {
    username: 'mayank.patil',
    passcode: 'SX-DEV-MAYANK-1337',
    name: 'Mayank Patil',
    role: 'Backend & Integration Lead',
    badge: 'LEAD // PLATFORM',
  },
];

export default function AuthModal({ isOpen, onClose, onLogin, currentUser }) {
  const [authMethod, setAuthMethod] = useState('dev_credentials'); // 'dev_credentials' or 'oauth'
  const [usernameInput, setUsernameInput] = useState('');
  const [passcodeInput, setPasscodeInput] = useState('');
  const [loginError, setLoginError] = useState('');

  if (!isOpen) return null;

  const handleDevSubmit = (e) => {
    if (e) e.preventDefault();
    setLoginError('');

    const cleanUser = usernameInput.trim().toLowerCase();
    const cleanPass = passcodeInput.trim();

    const matched = DEVELOPER_ACCOUNTS.find(
      (acc) =>
        (acc.username.toLowerCase() === cleanUser || acc.name.toLowerCase() === cleanUser) &&
        acc.passcode === cleanPass
    );

    if (matched) {
      onLogin({
        name: matched.name,
        username: matched.username,
        role: 'developer',
        title: matched.role,
        badge: matched.badge,
        email: `${matched.username}@vulntwin.internal`,
      });
      onClose();
    } else {
      setLoginError('Invalid Developer Username or Passcode. Contact platform admin for credentials.');
    }
  };

  const handleOAuthLogin = (provider) => {
    const dummyUser = {
      name: provider === 'google' ? 'Alex Rivera' : 'Jordan Vance',
      email: provider === 'google' ? 'alex.rivera@corp-security.com' : 'jordan.vance@icloud.com',
      provider: provider,
      role: 'user',
      title: 'Security Analyst',
    };
    onLogin(dummyUser);
    onClose();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-xs">
      <div className="relative w-full max-w-md p-6 bg-white border border-[#E2E8F0] rounded-xl shadow-xl space-y-5">
        
        {/* Close Button */}
        <button
          onClick={onClose}
          className="absolute top-4 right-4 text-slate-400 hover:text-slate-600 transition-colors"
        >
          <X className="w-5 h-5" />
        </button>

        {/* Header */}
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <Shield className="w-5 h-5 text-[#2563EB]" />
            <h2 className="text-lg font-bold text-[#0B1F44]">
              VulnTwin AI Access &amp; Clearance
            </h2>
          </div>
          <p className="text-xs text-slate-500 font-sans">
            Authenticate to evaluate security vulnerabilities and manage Digital Twin testing.
          </p>
        </div>

        {/* Tab Switcher */}
        <div className="grid grid-cols-2 gap-1 p-1 bg-slate-100 rounded-lg text-xs font-semibold">
          <button
            onClick={() => setAuthMethod('dev_credentials')}
            className={`py-2 rounded-md transition-all flex items-center justify-center gap-1.5 ${
              authMethod === 'dev_credentials'
                ? 'bg-white text-[#0B1F44] shadow-xs'
                : 'text-slate-500 hover:text-slate-800'
            }`}
          >
            <Key className="w-3.5 h-3.5" />
            <span>Developer Clearance</span>
          </button>
          <button
            onClick={() => setAuthMethod('oauth')}
            className={`py-2 rounded-md transition-all flex items-center justify-center gap-1.5 ${
              authMethod === 'oauth'
                ? 'bg-white text-[#0B1F44] shadow-xs'
                : 'text-slate-500 hover:text-slate-800'
            }`}
          >
            <UserCheck className="w-3.5 h-3.5" />
            <span>Google / Apple SSO</span>
          </button>
        </div>

        {authMethod === 'dev_credentials' ? (
          /* Developer Login Form */
          <div className="space-y-4">
            <form onSubmit={handleDevSubmit} className="space-y-3">
              <div>
                <label className="block text-xs font-semibold text-slate-700 mb-1">
                  DEVELOPER USERNAME
                </label>
                <input
                  type="text"
                  value={usernameInput}
                  onChange={(e) => setUsernameInput(e.target.value)}
                  placeholder="e.g. sara.dongare, mayank.patil"
                  className="w-full px-3 py-2 bg-slate-50 border border-[#CBD5E1] rounded-lg text-xs text-slate-900 focus:outline-none focus:ring-2 focus:ring-[#2563EB]"
                  required
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-700 mb-1">
                  SECURITY PASSCODE
                </label>
                <input
                  type="password"
                  value={passcodeInput}
                  onChange={(e) => setPasscodeInput(e.target.value)}
                  placeholder="Enter assigned secret passcode"
                  className="w-full px-3 py-2 bg-slate-50 border border-[#CBD5E1] rounded-lg text-xs text-slate-900 focus:outline-none focus:ring-2 focus:ring-[#2563EB]"
                  required
                />
              </div>

              {loginError && (
                <div className="p-2.5 bg-rose-50 border border-rose-200 rounded-lg text-rose-700 text-xs flex items-center gap-2">
                  <AlertOctagon className="w-4 h-4 text-rose-600 shrink-0" />
                  <span>{loginError}</span>
                </div>
              )}

              <button
                type="submit"
                className="w-full py-2.5 bg-[#2563EB] hover:bg-blue-700 text-white font-semibold text-xs rounded-lg transition-colors flex items-center justify-center gap-2 shadow-sm"
              >
                <span>Verify Clearance &amp; Unlock Platform</span>
                <ArrowRight className="w-4 h-4" />
              </button>
            </form>

            <div className="pt-2 border-t border-[#E2E8F0] text-xs text-slate-500 font-sans leading-relaxed">
              Developer clearance credentials grant unlimited daily evaluations and access to the Threat Memory Vault.
            </div>
          </div>
        ) : (
          /* OAuth SSO Buttons */
          <div className="space-y-3 pt-2">
            <button
              onClick={() => handleOAuthLogin('google')}
              className="w-full py-2.5 px-4 bg-white hover:bg-slate-50 border border-slate-300 rounded-lg text-xs font-semibold text-slate-700 transition-colors flex items-center justify-center gap-3 shadow-2xs"
            >
              <svg className="w-4 h-4" viewBox="0 0 24 24">
                <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
                <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
                <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"/>
                <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"/>
              </svg>
              <span>Continue with Google</span>
            </button>

            <button
              onClick={() => handleOAuthLogin('apple')}
              className="w-full py-2.5 px-4 bg-white hover:bg-slate-50 border border-slate-300 rounded-lg text-xs font-semibold text-slate-700 transition-colors flex items-center justify-center gap-3 shadow-2xs"
            >
              <svg className="w-4 h-4 fill-black" viewBox="0 0 170 170">
                <path d="M150.37 130.25c-2.45 5.66-5.35 10.87-8.71 15.66-4.58 6.53-8.33 11.05-11.22 13.56-4.48 4.12-9.28 6.23-14.42 6.35-3.69 0-8.14-1.05-13.32-3.18-5.19-2.12-9.97-3.17-14.34-3.17-4.58 0-9.49 1.05-14.75 3.17-5.26 2.13-9.5 3.24-12.74 3.35-4.35.13-9.16-1.9-14.42-6.08-3.69-3.04-7.69-7.85-12.01-14.42-6.53-9.9-11.66-21.43-15.39-34.58-3.73-13.15-5.6-25.56-5.6-37.23 0-16.74 4.35-30.84 13.06-42.3 8.7-11.45 19.57-17.3 32.61-17.53 4.89 0 10.43 1.34 16.63 4.01 6.2 2.68 10.33 4.07 12.39 4.18 1.96 0 6.2-1.4 12.73-4.18 6.53-2.79 12.18-4.07 16.96-3.86 12.94.76 23.49 5.76 31.64 15 2.18 2.5 4.02 5.01 5.54 7.51-11.42 6.85-17.02 16.42-16.8 28.71.22 10.55 4.35 19.46 12.39 26.75 4.24 3.81 9.03 6.64 14.35 8.48-2.61 7.61-5.76 15.11-9.46 22.5zM119.22 31.85c0-7.39 2.61-14.46 7.83-21.2 5.22-6.74 11.85-11.09 19.89-13.05.54 2.07.82 4.13.82 6.2 0 7.39-2.72 14.57-8.15 21.53-5.44 6.96-12.18 11.2-20.22 12.72-.11-2.07-.17-4.14-.17-6.2z"/>
              </svg>
              <span>Continue with Apple</span>
            </button>

            <div className="p-3 bg-blue-50/70 border border-blue-200 rounded-lg text-xs space-y-1">
              <div className="flex items-center gap-1.5 text-[#2563EB] font-bold">
                <CheckCircle2 className="w-3.5 h-3.5" />
                <span>Standard Account Policy</span>
              </div>
              <p className="text-slate-600 font-sans leading-snug">
                Google &amp; Apple SSO grants <strong className="text-slate-900">3 link evaluations per 24 hours</strong> with full evidence extraction and SafePath alternative matching.
              </p>
            </div>
          </div>
        )}

      </div>
    </div>
  );
}
