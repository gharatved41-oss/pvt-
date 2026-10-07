import React, { useState } from 'react';
import { X, Lock, Key, AlertOctagon, ArrowRight, Shield } from 'lucide-react';
import { API_BASE } from '../config/api';

export default function AuthModal({ isOpen, onClose, onLogin, currentUser }) {
  const [usernameInput, setUsernameInput] = useState('');
  const [passcodeInput, setPasscodeInput] = useState('');
  const [loginError, setLoginError] = useState('');
  const [loading, setLoading] = useState(false);

  if (!isOpen) return null;

  const handleDevSubmit = async (e) => {
    if (e) e.preventDefault();
    setLoginError('');

    const cleanUser = usernameInput.trim().toLowerCase();
    const cleanPass = passcodeInput.trim();

    if (!cleanUser || !cleanPass) {
      setLoginError('Both username and secret passcode are required.');
      return;
    }

    setLoading(true);

    try {
      const res = await fetch(`${API_BASE}/api/v1/auth/verify-code`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          identifier: cleanUser,
          passcode: cleanPass,
        }),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail || 'Invalid Developer Username or Passcode. Access denied.');
      }

      if (data.status === 'authenticated' && data.user) {
        onLogin(data.user);
        onClose();
      } else {
        throw new Error('Authentication failed.');
      }
    } catch (err) {
      setLoginError(err.message || 'Developer verification failed.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-xs font-sans">
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
              Developer Clearance Authentication
            </h2>
          </div>
          <p className="text-xs text-slate-500">
            Enter assigned private developer credentials to obtain administrative clearances.
          </p>
        </div>

        {/* Error Notification */}
        {loginError && (
          <div className="p-3 bg-rose-50 border border-rose-200 rounded-lg text-xs text-rose-700 flex items-start gap-2">
            <AlertOctagon className="w-4 h-4 text-rose-600 shrink-0 mt-0.5" />
            <span>{loginError}</span>
          </div>
        )}

        <form onSubmit={handleDevSubmit} className="space-y-4">
          <div>
            <label className="block text-xs font-semibold text-slate-700 mb-1">
              DEVELOPER USERNAME
            </label>
            <input
              type="text"
              required
              value={usernameInput}
              onChange={(e) => setUsernameInput(e.target.value)}
              placeholder="e.g. sara.dongare, mayank.patil"
              className="w-full px-3 py-2 bg-slate-50 border border-[#CBD5E1] rounded-lg text-xs font-mono text-slate-900 focus:outline-none focus:ring-2 focus:ring-[#2563EB]"
            />
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-700 mb-1">
              ASSIGNED SECRET PASSCODE
            </label>
            <input
              type="password"
              required
              value={passcodeInput}
              onChange={(e) => setPasscodeInput(e.target.value)}
              placeholder="••••••••••••"
              className="w-full px-3 py-2 bg-slate-50 border border-[#CBD5E1] rounded-lg text-xs font-mono text-slate-900 focus:outline-none focus:ring-2 focus:ring-[#2563EB]"
            />
            <div className="text-[10px] text-slate-400 mt-1">
              Passcode is validated against backend security vault.
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full py-2.5 bg-[#0B1F44] hover:bg-[#1E3A8A] text-white font-semibold text-xs rounded-lg transition-colors flex items-center justify-center gap-2 shadow-sm disabled:opacity-50"
          >
            <span>{loading ? 'Validating...' : 'Verify Developer Clearance'}</span>
            <ArrowRight className="w-4 h-4" />
          </button>
        </form>

      </div>
    </div>
  );
}
