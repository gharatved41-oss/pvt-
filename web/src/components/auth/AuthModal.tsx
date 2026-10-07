'use client';

import React, { useState } from 'react';
import {
  loginWithGoogle,
  loginWithEmail,
  registerWithEmail,
} from '@/lib/authService';

interface AuthModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess?: () => void;
  targetAction?: string;
}

export function AuthModal({
  isOpen,
  onClose,
  onSuccess,
  targetAction,
}: AuthModalProps) {
  const [tab, setTab] = useState<'signin' | 'register'>('signin');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [errorCode, setErrorCode] = useState<string | null>(null);
  const [registrationSuccess, setRegistrationSuccess] = useState(false);

  if (!isOpen) return null;

  const resetFormState = () => {
    setEmail('');
    setPassword('');
    setErrorCode(null);
    setRegistrationSuccess(false);
  };

  const handleTabSwitch = (selectedTab: 'signin' | 'register') => {
    setTab(selectedTab);
    setErrorCode(null);
    setRegistrationSuccess(false);
  };

  const handleGoogleSignIn = async () => {
    setErrorCode(null);
    setLoading(true);
    try {
      await loginWithGoogle();
      if (onSuccess) onSuccess();
      onClose();
    } catch (err: unknown) {
      const errorWithCode = err as { code?: string; message?: string };
      setErrorCode(errorWithCode?.code || errorWithCode?.message || 'auth/unknown-error');
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorCode(null);
    setLoading(true);

    try {
      if (tab === 'register') {
        await registerWithEmail(email, password);
        setRegistrationSuccess(true);
      } else {
        await loginWithEmail(email, password);
        if (onSuccess) onSuccess();
        onClose();
      }
    } catch (err: unknown) {
      const errorWithCode = err as { code?: string; message?: string };
      setErrorCode(errorWithCode?.code || errorWithCode?.message || 'auth/unknown-error');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/90 flex items-center justify-center p-4 select-none">
      <div className="w-full max-w-sm bg-zinc-950 border border-zinc-800 text-zinc-100 rounded-none p-5 relative shadow-none">
        {/* Close Button */}
        <button
          type="button"
          onClick={() => {
            resetFormState();
            onClose();
          }}
          className="absolute right-3 top-3 text-zinc-500 hover:text-zinc-200 font-mono text-xs uppercase"
        >
          [ESC / CLOSE]
        </button>

        {/* Header */}
        <div className="mb-4 pb-2 border-b border-zinc-800">
          <div className="font-mono text-xs font-bold uppercase tracking-wider text-zinc-100">
            SEC_GATEWAY // AUTH_REQUIRED
          </div>
          <div className="font-mono text-[10px] text-zinc-500 uppercase tracking-widest mt-0.5">
            {targetAction ? `GATED_ACTION: ${targetAction}` : 'VULNTWIN AI WORKSPACE'}
          </div>
        </div>

        {/* Registration Success Message */}
        {registrationSuccess ? (
          <div className="space-y-4">
            <div className="border border-emerald-800 bg-emerald-950/20 p-3 text-emerald-400 font-mono text-xs">
              <div className="font-bold uppercase tracking-wider mb-1">
                REGISTRATION_SUCCESSFUL
              </div>
              <p className="text-zinc-300 font-mono text-[11px] leading-relaxed">
                Verification link dispatched. Please verify your email before logging in.
              </p>
            </div>

            <button
              type="button"
              onClick={() => {
                setTab('signin');
                setRegistrationSuccess(false);
                setErrorCode(null);
              }}
              className="w-full bg-zinc-900 hover:bg-zinc-800 border border-zinc-700 text-zinc-100 font-mono text-xs py-2 uppercase tracking-wider rounded-none transition-colors"
            >
              PROCEED TO SIGN IN
            </button>
          </div>
        ) : (
          <>
            {/* Tabs: Sign In / Register */}
            <div className="flex border-b border-zinc-800 mb-4 font-mono text-xs">
              <button
                type="button"
                onClick={() => handleTabSwitch('signin')}
                className={`flex-1 py-1.5 text-center uppercase tracking-wider border-b-2 transition-colors ${
                  tab === 'signin'
                    ? 'border-zinc-100 text-zinc-100 font-bold'
                    : 'border-transparent text-zinc-500 hover:text-zinc-300'
                }`}
              >
                SIGN IN
              </button>
              <button
                type="button"
                onClick={() => handleTabSwitch('register')}
                className={`flex-1 py-1.5 text-center uppercase tracking-wider border-b-2 transition-colors ${
                  tab === 'register'
                    ? 'border-zinc-100 text-zinc-100 font-bold'
                    : 'border-transparent text-zinc-500 hover:text-zinc-300'
                }`}
              >
                REGISTER
              </button>
            </div>

            {/* Error Code Box */}
            {errorCode && (
              <div className="mb-4 p-2.5 border border-red-500 bg-red-950/20 text-red-400 font-mono text-xs break-all">
                <span className="font-bold text-red-500">[ERROR]:</span> {errorCode}
              </div>
            )}

            {/* Google Authentication Trigger */}
            <div className="mb-4">
              <button
                type="button"
                disabled={loading}
                onClick={handleGoogleSignIn}
                className="w-full bg-zinc-900 hover:bg-zinc-850 border border-zinc-800 text-zinc-200 font-mono text-xs py-2 px-3 rounded-none flex items-center justify-center gap-2 uppercase tracking-wider transition-colors disabled:opacity-50"
              >
                CONTINUE WITH GOOGLE
              </button>
            </div>

            <div className="relative my-4 text-center border-t border-zinc-800">
              <span className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 bg-zinc-950 px-2 font-mono text-[10px] text-zinc-600 uppercase">
                OR EMAIL KEY
              </span>
            </div>

            {/* Email / Password Form */}
            <form onSubmit={handleSubmit} className="space-y-3 font-mono text-xs">
              <div>
                <label className="block text-[10px] text-zinc-400 uppercase tracking-wider mb-1">
                  EMAIL_ADDRESS
                </label>
                <input
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="analyst@enterprise.com"
                  className="w-full bg-zinc-950 border border-zinc-800 rounded-none py-1.5 px-2.5 text-zinc-100 placeholder:text-zinc-700 font-mono text-xs focus:outline-none focus:border-zinc-500"
                />
              </div>

              <div>
                <label className="block text-[10px] text-zinc-400 uppercase tracking-wider mb-1">
                  ACCESS_KEY / PASSWORD
                </label>
                <input
                  type="password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••••••"
                  className="w-full bg-zinc-950 border border-zinc-800 rounded-none py-1.5 px-2.5 text-zinc-100 placeholder:text-zinc-700 font-mono text-xs focus:outline-none focus:border-zinc-500"
                />
              </div>

              <button
                type="submit"
                disabled={loading}
                className="w-full bg-zinc-100 hover:bg-white text-zinc-950 font-bold font-mono text-xs py-2 px-3 rounded-none uppercase tracking-wider transition-colors mt-2 disabled:opacity-50"
              >
                {loading
                  ? 'PROCESSING...'
                  : tab === 'signin'
                  ? 'SIGN IN TO WORKSPACE'
                  : 'REGISTER & DISPATCH LINK'}
              </button>
            </form>
          </>
        )}
      </div>
    </div>
  );
}
