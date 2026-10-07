'use client';

import React, { useState } from 'react';
import { Shield } from 'lucide-react';
import {
  signInWithGoogle,
  signInWithApple,
  loginWithEmail,
  registerWithEmail,
} from '@/lib/authService';

const EMAIL_REGEX = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;

export function AuthForm() {
  const [isRegister, setIsRegister] = useState(false);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [providerLoading, setProviderLoading] = useState<'google' | 'apple' | null>(null);
  const [verificationSent, setVerificationSent] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    const cleanEmail = email.trim();
    const cleanPassword = password;

    if (!cleanEmail || !EMAIL_REGEX.test(cleanEmail)) {
      setError('auth/invalid-email: A valid email address is required. Bare numbers or identifiers are rejected.');
      return;
    }

    if (!cleanPassword || cleanPassword.length < 6) {
      setError('auth/weak-password: Password must contain at least 6 characters.');
      return;
    }

    setLoading(true);

    try {
      if (isRegister) {
        await registerWithEmail(cleanEmail, cleanPassword);
        setVerificationSent(true);
      } else {
        await loginWithEmail(cleanEmail, cleanPassword);
      }
    } catch (err: unknown) {
      const errorWithCode = err as { code?: string; message?: string };
      setError(errorWithCode?.code || errorWithCode?.message || 'auth/authentication-failed');
    } finally {
      setLoading(false);
    }
  };

  const handleGoogleSignIn = async () => {
    setError(null);
    setProviderLoading('google');
    try {
      await signInWithGoogle();
    } catch (err: unknown) {
      const errorWithCode = err as { code?: string; message?: string };
      setError(errorWithCode?.code || errorWithCode?.message || 'auth/google-sign-in-failed');
    } finally {
      setProviderLoading(null);
    }
  };

  const handleAppleSignIn = async () => {
    setError(null);
    setProviderLoading('apple');
    try {
      await signInWithApple();
    } catch (err: unknown) {
      const errorWithCode = err as { code?: string; message?: string };
      setError(errorWithCode?.code || errorWithCode?.message || 'auth/apple-sign-in-failed');
    } finally {
      setProviderLoading(null);
    }
  };

  const isAnyLoading = loading || providerLoading !== null;

  return (
    <div className="w-full max-w-md bg-zinc-950 border border-zinc-800 rounded-none p-6 shadow-none space-y-6 select-none font-mono">
      <div className="text-center space-y-2">
        <div className="inline-flex p-2.5 bg-zinc-900 border border-zinc-800 rounded-none text-emerald-400">
          <Shield className="w-5 h-5" />
        </div>
        <h2 className="text-sm font-bold text-zinc-100 uppercase tracking-wider">
          VulnTwin AI
        </h2>
        <p className="text-[10px] text-zinc-500 uppercase tracking-widest">
          Continuous Threat Exposure Management
        </p>
      </div>

      {verificationSent ? (
        <div className="space-y-4">
          <div className="p-3 border border-emerald-800 bg-emerald-950/20 text-emerald-400 text-xs">
            <span className="font-bold">[SUCCESS]: </span>
            Verification email dispatched to {email}. Verify your inbox before logging in.
          </div>
          <button
            type="button"
            onClick={() => {
              setVerificationSent(false);
              setIsRegister(false);
              setError(null);
            }}
            className="w-full bg-zinc-900 hover:bg-zinc-800 border border-zinc-700 text-zinc-200 py-2 text-xs uppercase"
          >
            RETURN TO SIGN IN
          </button>
        </div>
      ) : (
        <>
          <div className="grid grid-cols-2 p-1 bg-zinc-900 border border-zinc-800 text-xs">
            <button
              type="button"
              onClick={() => {
                setIsRegister(false);
                setError(null);
              }}
              className={`py-1.5 transition-colors uppercase ${
                !isRegister ? 'bg-zinc-800 text-zinc-100 font-bold' : 'text-zinc-500 hover:text-zinc-300'
              }`}
            >
              Sign In
            </button>
            <button
              type="button"
              onClick={() => {
                setIsRegister(true);
                setError(null);
              }}
              className={`py-1.5 transition-colors uppercase ${
                isRegister ? 'bg-zinc-800 text-zinc-100 font-bold' : 'text-zinc-500 hover:text-zinc-300'
              }`}
            >
              Register
            </button>
          </div>

          {error && (
            <div className="p-2.5 bg-red-950/20 border border-red-500 text-red-400 text-xs break-all">
              <span className="font-bold">[ERROR]:</span> {error}
            </div>
          )}

          <div className="space-y-2">
            <button
              type="button"
              disabled={isAnyLoading}
              onClick={handleGoogleSignIn}
              className="w-full bg-zinc-900 hover:bg-zinc-850 border border-zinc-800 text-zinc-200 text-xs py-2 px-3 flex items-center justify-center gap-2 uppercase tracking-wider transition-colors disabled:opacity-50"
            >
              <span>{providerLoading === 'google' ? 'AUTHENTICATING...' : 'CONTINUE WITH GOOGLE'}</span>
            </button>

            <button
              type="button"
              disabled={isAnyLoading}
              onClick={handleAppleSignIn}
              className="w-full bg-zinc-900 hover:bg-zinc-850 border border-zinc-800 text-zinc-200 text-xs py-2 px-3 flex items-center justify-center gap-2 uppercase tracking-wider transition-colors disabled:opacity-50"
            >
              <span>{providerLoading === 'apple' ? 'AUTHENTICATING...' : 'CONTINUE WITH APPLE'}</span>
            </button>
          </div>

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-[10px] text-zinc-400 uppercase tracking-wider mb-1">
                CORPORATE EMAIL
              </label>
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="analyst@enterprise.com"
                className="w-full bg-zinc-950 border border-zinc-800 rounded-none py-1.5 px-3 text-xs text-zinc-100 placeholder:text-zinc-700 focus:outline-none focus:border-zinc-500 font-mono"
              />
            </div>

            <div>
              <label className="block text-[10px] text-zinc-400 uppercase tracking-wider mb-1">
                ACCESS KEY
              </label>
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                className="w-full bg-zinc-950 border border-zinc-800 rounded-none py-1.5 px-3 text-xs text-zinc-100 placeholder:text-zinc-700 focus:outline-none focus:border-zinc-500 font-mono"
              />
            </div>

            <button
              type="submit"
              disabled={isAnyLoading}
              className="w-full bg-zinc-100 hover:bg-white text-zinc-950 font-bold py-2 text-xs uppercase tracking-wider rounded-none transition-colors disabled:opacity-50"
            >
              {loading
                ? 'PROCESSING...'
                : isRegister
                ? 'PROVISION ACCOUNT'
                : 'VERIFY CREDENTIALS'}
            </button>
          </form>
        </>
      )}
    </div>
  );
}
