'use client';

import React, { useState } from 'react';
import { Shield, Lock, Mail, ArrowRight, AlertCircle, RefreshCw, Key, ShieldCheck, UserCheck } from 'lucide-react';
import { useAuth } from '@/context/AuthContext';

export function AuthCard() {
  const { signInWithEmail, signUpWithEmail, signInWithGoogle, demoLogin } = useAuth();
  
  const [mode, setMode] = useState<'login' | 'signup'>('login');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      if (mode === 'login') {
        await signInWithEmail(email, password);
      } else {
        await signUpWithEmail(email, password);
      }
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Authentication failed';
      if (message.includes('auth/invalid-credential') || message.includes('auth/wrong-password')) {
        setError('Invalid credentials. Please verify your email and password, or use Quick Developer Clearance.');
      } else if (message.includes('auth/email-already-in-use')) {
        setError('Email already in use. Please sign in instead.');
      } else if (message.includes('auth/weak-password')) {
        setError('Password must be at least 6 characters.');
      } else {
        setError(message);
      }
    } finally {
      setLoading(false);
    }
  };

  const handleGoogleSignIn = async () => {
    setError(null);
    setLoading(true);
    try {
      await signInWithGoogle();
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Google authentication failed';
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="w-full max-w-md bg-zinc-900 border border-zinc-800 rounded-md p-6 shadow-2xl space-y-6 select-none animate-in fade-in zoom-in-95 duration-200">
      {/* Brand Header */}
      <div className="text-center space-y-2">
        <div className="inline-flex p-2.5 bg-zinc-950 border border-zinc-800 rounded-md text-emerald-400">
          <Shield className="w-6 h-6" />
        </div>
        <h2 className="text-lg font-bold text-zinc-100 tracking-tight">
          VulnTwin AI
        </h2>
        <p className="text-xs text-zinc-400 font-mono">
          Adversarial Exposure Validation • RBAC Engine
        </p>
      </div>

      {/* Mode Switcher */}
      <div className="grid grid-cols-2 p-1 bg-zinc-950 border border-zinc-800 rounded-md text-xs font-mono">
        <button
          type="button"
          onClick={() => { setMode('login'); setError(null); }}
          className={`py-1.5 rounded text-center transition-all ${
            mode === 'login'
              ? 'bg-zinc-800 text-zinc-100 font-semibold shadow-xs'
              : 'text-zinc-500 hover:text-zinc-300'
          }`}
        >
          Sign In
        </button>
        <button
          type="button"
          onClick={() => { setMode('signup'); setError(null); }}
          className={`py-1.5 rounded text-center transition-all ${
            mode === 'signup'
              ? 'bg-zinc-800 text-zinc-100 font-semibold shadow-xs'
              : 'text-zinc-500 hover:text-zinc-300'
          }`}
        >
          Register
        </button>
      </div>

      {/* Error Alert */}
      {error && (
        <div className="p-3 bg-red-950/60 border border-red-800/80 rounded-md text-xs text-red-300 flex items-start gap-2">
          <AlertCircle className="w-4 h-4 shrink-0 text-red-400 mt-0.5" />
          <span className="leading-snug">{error}</span>
        </div>
      )}

      {/* Email / Password Form */}
      <form onSubmit={handleSubmit} className="space-y-4 text-xs">
        <div className="space-y-1.5">
          <label className="text-zinc-400 font-mono flex items-center gap-1.5">
            <Mail className="w-3.5 h-3.5 text-zinc-500" />
            <span>Email Address</span>
          </label>
          <input
            type="email"
            required
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="analyst@enterprise.com"
            className="w-full px-3 py-2 bg-zinc-950 border border-zinc-800 rounded-md text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-zinc-500 font-mono text-xs transition-colors"
          />
        </div>

        <div className="space-y-1.5">
          <label className="text-zinc-400 font-mono flex items-center gap-1.5">
            <Lock className="w-3.5 h-3.5 text-zinc-500" />
            <span>Password</span>
          </label>
          <input
            type="password"
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="••••••••••••"
            className="w-full px-3 py-2 bg-zinc-950 border border-zinc-800 rounded-md text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-zinc-500 font-mono text-xs transition-colors"
          />
        </div>

        <button
          type="submit"
          disabled={loading}
          className="w-full py-2 bg-zinc-100 hover:bg-white text-zinc-950 font-semibold rounded-md flex items-center justify-center gap-2 transition-all cursor-pointer disabled:opacity-50"
        >
          {loading ? (
            <RefreshCw className="w-4 h-4 animate-spin" />
          ) : (
            <>
              <span>{mode === 'login' ? 'Authenticate Session' : 'Create Security Account'}</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </>
          )}
        </button>
      </form>

      {/* Alternative Login Actions */}
      <div className="relative flex items-center justify-center">
        <div className="border-t border-zinc-800 w-full" />
        <span className="bg-zinc-900 px-2 text-[10px] font-mono text-zinc-500 uppercase absolute">
          or evaluate tier
        </span>
      </div>

      <div className="space-y-2">
        <button
          type="button"
          onClick={handleGoogleSignIn}
          disabled={loading}
          className="w-full py-2 bg-zinc-950 hover:bg-zinc-800/80 border border-zinc-800 hover:border-zinc-700 text-zinc-300 font-medium rounded-md text-xs flex items-center justify-center gap-2 transition-colors cursor-pointer"
        >
          <svg className="w-4 h-4" viewBox="0 0 24 24">
            <path fill="#EA4335" d="M12 5c1.6 0 3 .6 4.1 1.6l3.1-3.1C17.3 1.7 14.8 1 12 1 7.5 1 3.7 3.6 1.9 7.4l3.7 2.9C6.5 7.4 9 5 12 5z"/>
            <path fill="#4285F4" d="M23.5 12.3c0-.8-.1-1.6-.2-2.3H12v4.5h6.5c-.3 1.5-1.1 2.8-2.4 3.7l3.7 2.9c2.2-2 3.7-5 3.7-8.8z"/>
            <path fill="#FBBC05" d="M5.6 14.7c-.2-.7-.4-1.5-.4-2.3 0-.8.2-1.6.4-2.3L1.9 7.2C.7 9.6 0 12.2 0 15s.7 5.4 1.9 7.8l3.7-3.1z"/>
            <path fill="#34A853" d="M12 23c3.2 0 6-1.1 8-3l-3.7-2.9c-1.1.7-2.5 1.2-4.3 1.2-3 0-5.5-2-6.4-4.8L1.9 16.4C3.7 20.2 7.5 23 12 23z"/>
          </svg>
          <span>Continue with Google</span>
        </button>

        {/* Quick RBAC Role Presets for Instant Testing */}
        <div className="grid grid-cols-2 gap-2 pt-1">
          <button
            type="button"
            onClick={() => demoLogin('developer')}
            className="p-2 bg-emerald-950/40 hover:bg-emerald-950/70 border border-emerald-800/60 text-emerald-300 font-mono rounded-md text-[11px] flex flex-col items-center justify-center text-center transition-colors cursor-pointer"
          >
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400 mb-0.5" />
            <span className="font-semibold">Developer Tier</span>
            <span className="text-[9px] text-emerald-500/80">Unlimited + Admin</span>
          </button>

          <button
            type="button"
            onClick={() => demoLogin('user')}
            className="p-2 bg-zinc-950 hover:bg-zinc-800/80 border border-zinc-800 text-zinc-300 font-mono rounded-md text-[11px] flex flex-col items-center justify-center text-center transition-colors cursor-pointer"
          >
            <UserCheck className="w-3.5 h-3.5 text-zinc-400 mb-0.5" />
            <span className="font-semibold">Standard User</span>
            <span className="text-[9px] text-zinc-500">Quota: 3 Scans/Day</span>
          </button>
        </div>
      </div>

      <div className="text-[10px] text-zinc-500 font-mono text-center">
        Encrypted Session Tokens • Firestore RBAC Persistence
      </div>
    </div>
  );
}
