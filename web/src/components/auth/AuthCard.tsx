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

export function AuthCard() {
  const [mode, setMode] = useState<'login' | 'register'>('login');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [providerLoading, setProviderLoading] = useState<'google' | 'apple' | null>(null);
  const [registeredNotice, setRegisteredNotice] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    const cleanEmail = email.trim();
    const cleanPassword = password;

    if (!cleanEmail || !EMAIL_REGEX.test(cleanEmail)) {
      setError('auth/invalid-email: A valid email address is required (e.g. analyst@company.com). Bare digits or invalid identifiers are rejected.');
      return;
    }

    if (!cleanPassword || cleanPassword.length < 6) {
      setError('auth/weak-password: Password must contain at least 6 characters.');
      return;
    }

    setLoading(true);

    try {
      if (mode === 'login') {
        await loginWithEmail(cleanEmail, cleanPassword);
      } else {
        await registerWithEmail(cleanEmail, cleanPassword);
        setRegisteredNotice(true);
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
    <div className="w-full max-w-md bg-zinc-950 border border-zinc-800 rounded-none p-6 font-mono text-zinc-100 shadow-none select-none">
      {/* Brand Header */}
      <div className="flex items-center gap-3 mb-6 pb-4 border-b border-zinc-800">
        <div className="w-8 h-8 rounded-none bg-zinc-900 border border-zinc-700 flex items-center justify-center text-zinc-100">
          <Shield className="w-4 h-4 text-emerald-400" />
        </div>
        <div>
          <h1 className="text-sm font-semibold tracking-wider text-zinc-100 uppercase">
            VulnTwin AI
          </h1>
          <p className="text-[10px] text-zinc-500 uppercase tracking-widest">
            Adversarial Exposure Validation
          </p>
        </div>
      </div>

      {registeredNotice ? (
        <div className="space-y-4">
          <div className="p-3 border border-emerald-800 bg-emerald-950/20 text-emerald-400 text-xs">
            <span className="font-bold">[SUCCESS]: </span>
            Verification email dispatched to {email}. Verify your inbox before logging in.
          </div>
          <button
            type="button"
            onClick={() => {
              setRegisteredNotice(false);
              setMode('login');
              setError(null);
            }}
            className="w-full bg-zinc-900 hover:bg-zinc-800 border border-zinc-700 text-zinc-200 py-2 text-xs uppercase"
          >
            RETURN TO SIGN IN
          </button>
        </div>
      ) : (
        <>
          {/* Mode Switcher */}
          <div className="flex border-b border-zinc-800 mb-6 text-xs">
            <button
              type="button"
              onClick={() => {
                setMode('login');
                setError(null);
              }}
              className={`pb-2 mr-6 transition-colors border-b-2 font-medium ${
                mode === 'login'
                  ? 'border-zinc-100 text-zinc-100'
                  : 'border-transparent text-zinc-500 hover:text-zinc-300'
              }`}
            >
              SIGN IN
            </button>
            <button
              type="button"
              onClick={() => {
                setMode('register');
                setError(null);
              }}
              className={`pb-2 transition-colors border-b-2 font-medium ${
                mode === 'register'
                  ? 'border-zinc-100 text-zinc-100'
                  : 'border-transparent text-zinc-500 hover:text-zinc-300'
              }`}
            >
              REGISTER
            </button>
          </div>

          {/* Error Message */}
          {error && (
            <div className="mb-4 p-2.5 bg-red-950/20 border border-red-500 text-red-400 text-xs break-all">
              <span className="font-bold">[ERROR]:</span> {error}
            </div>
          )}

          {/* OAuth Buttons */}
          <div className="space-y-2 mb-4">
            <button
              type="button"
              disabled={isAnyLoading}
              onClick={handleGoogleSignIn}
              className="w-full bg-zinc-900 hover:bg-zinc-850 border border-zinc-800 text-zinc-200 text-xs py-2 px-3 flex items-center justify-center gap-2 uppercase tracking-wider transition-colors disabled:opacity-50"
            >
              <svg className="w-3.5 h-3.5" viewBox="0 0 24 24">
                <path
                  fill="currentColor"
                  d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
                />
                <path
                  fill="currentColor"
                  d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
                />
                <path
                  fill="currentColor"
                  d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"
                />
                <path
                  fill="currentColor"
                  d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"
                />
              </svg>
              <span>{providerLoading === 'google' ? 'AUTHENTICATING...' : 'CONTINUE WITH GOOGLE'}</span>
            </button>

            <button
              type="button"
              disabled={isAnyLoading}
              onClick={handleAppleSignIn}
              className="w-full bg-zinc-900 hover:bg-zinc-850 border border-zinc-800 text-zinc-200 text-xs py-2 px-3 flex items-center justify-center gap-2 uppercase tracking-wider transition-colors disabled:opacity-50"
            >
              <svg className="w-3.5 h-3.5 fill-current" viewBox="0 0 170 170">
                <path d="M150.37 130.25c-2.45 5.66-5.35 10.87-8.71 15.66-4.58 6.53-8.33 11.05-11.22 13.56-4.48 4.12-9.28 6.23-14.42 6.35-3.69 0-8.14-1.05-13.32-3.18-5.19-2.12-9.97-3.17-14.34-3.17-4.58 0-9.49 1.05-14.75 3.17-5.26 2.13-9.5 3.24-12.74 3.35-4.35.13-9.16-1.9-14.42-6.08-3.7-3.04-7.66-7.85-11.89-14.42-6.53-10.13-11.75-21.78-15.66-34.96-3.9-13.18-5.86-25.12-5.86-35.83 0-14.42 3.59-26.68 10.76-36.78 7.18-10.1 16.27-15.22 27.28-15.35 4.35 0 9.27 1.13 14.77 3.39 5.49 2.26 9.4 3.44 11.73 3.55 2.12-.11 6.13-1.34 12.02-3.68 5.88-2.34 10.88-3.4 14.99-3.18 13.91.76 24.58 5.76 32 15-11.08 6.74-16.51 16.09-16.3 28.05.21 9.9 4.02 18.06 11.43 24.47 5.11 4.57 11.09 7.4 17.94 8.5-2.61 7.72-5.99 15.22-10.13 22.5zM119.22 31.84c0-7.72 2.72-14.9 8.16-21.53 5.44-6.63 12.18-10.31 20.22-11.05.22 1.09.33 2.07.33 2.94 0 7.61-2.83 14.89-8.48 21.85-5.65 6.96-12.4 10.65-20.23 11.06v-3.27z" />
              </svg>
              <span>{providerLoading === 'apple' ? 'AUTHENTICATING...' : 'CONTINUE WITH APPLE'}</span>
            </button>
          </div>

          <div className="relative my-4 text-center border-t border-zinc-800">
            <span className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 bg-zinc-950 px-2 text-[10px] text-zinc-600 uppercase">
              OR EMAIL KEY
            </span>
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
                : mode === 'login'
                ? 'VERIFY CREDENTIALS'
                : 'PROVISION ACCOUNT'}
            </button>
          </form>
        </>
      )}
    </div>
  );
}
