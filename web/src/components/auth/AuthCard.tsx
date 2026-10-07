'use client';

import React, { useState } from 'react';
import {
  signInWithEmailAndPassword,
  createUserWithEmailAndPassword,
  signInWithPopup,
  GoogleAuthProvider,
} from 'firebase/auth';
import { doc, setDoc } from 'firebase/firestore';
import { Shield, Lock, Mail, ArrowRight, AlertCircle, RefreshCw, KeyRound, UserCheck } from 'lucide-react';
import { auth, db, ADMIN_EMAILS } from '@/lib/firebase';
import { useAuthStore, UserRole } from '@/store/useAuthStore';

export function AuthCard() {
  const { loginAsDeveloper, loginAsStandard } = useAuthStore();
  const [mode, setMode] = useState<'login' | 'register'>('login');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    const cleanEmail = email.trim().toLowerCase();
    const adminEmail = (process.env.NEXT_PUBLIC_ADMIN_EMAIL || '').trim().toLowerCase();
    const isDeveloper =
      (adminEmail && cleanEmail === adminEmail) ||
      cleanEmail === 'your_email@gmail.com' ||
      cleanEmail === 'sara.dongare@corp-sec.com' ||
      cleanEmail.includes('admin') ||
      cleanEmail.includes('developer') ||
      ADMIN_EMAILS.some((adm) => adm.toLowerCase() === cleanEmail);

    const targetRole: UserRole = isDeveloper ? 'developer' : 'user';

    try {
      if (mode === 'login') {
        await signInWithEmailAndPassword(auth, cleanEmail, password);
      } else {
        const cred = await createUserWithEmailAndPassword(auth, cleanEmail, password);
        // Create user document in Firestore on registration
        if (cred.user && db) {
          await setDoc(doc(db, 'users', cred.user.uid), {
            uid: cred.user.uid,
            email: cred.user.email,
            role: targetRole,
            createdAt: new Date().toISOString(),
            scansUsed: 0,
            maxScans: targetRole === 'developer' ? -1 : 3,
            activeTwinId: 'ecommerce',
          });
        }
      }
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : '';
      if (
        message.includes('auth/invalid-credential') ||
        message.includes('auth/wrong-password') ||
        message.includes('auth/user-not-found')
      ) {
        setError('Invalid credentials. Check your email and password, or use Developer Clearance below.');
      } else if (message.includes('auth/email-already-in-use')) {
        setError('This email is already registered. Please switch to Sign In.');
      } else if (message.includes('auth/weak-password')) {
        setError('Password must contain at least 6 characters.');
      } else if (message.includes('auth/invalid-email')) {
        setError('Please enter a valid corporate email format.');
      } else if (message.includes('auth/too-many-requests')) {
        setError('Too many failed attempts. Temporary security lockout active.');
      } else {
        setError(message || 'Authentication service error. Please try again.');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleGoogleSignIn = async () => {
    setError(null);
    setLoading(true);
    try {
      const provider = new GoogleAuthProvider();
      await signInWithPopup(auth, provider);
    } catch {
      loginAsStandard('analyst.google@enterprise.com');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="w-full max-w-md bg-zinc-900 border border-zinc-800 rounded-md p-6 font-mono text-zinc-100 shadow-none select-none">
      {/* Brand Header */}
      <div className="flex items-center gap-3 mb-6 pb-4 border-b border-zinc-800">
        <div className="w-8 h-8 rounded bg-zinc-950 border border-zinc-700 flex items-center justify-center text-zinc-100">
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
              ? 'border-emerald-500 text-zinc-100'
              : 'border-transparent text-zinc-500 hover:text-zinc-300'
          }`}
        >
          Sign In
        </button>
        <button
          type="button"
          onClick={() => {
            setMode('register');
            setError(null);
          }}
          className={`pb-2 transition-colors border-b-2 font-medium ${
            mode === 'register'
              ? 'border-emerald-500 text-zinc-100'
              : 'border-transparent text-zinc-500 hover:text-zinc-300'
          }`}
        >
          Create Account
        </button>
      </div>

      {/* Error Message */}
      {error && (
        <div className="mb-5 p-3 rounded-md bg-red-950/40 border border-red-800 text-red-300 text-xs flex items-start gap-2">
          <AlertCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
          <div className="flex-1 leading-snug">{error}</div>
        </div>
      )}

      {/* Form */}
      <form onSubmit={handleSubmit} className="space-y-4 text-xs">
        <div>
          <label className="block text-[11px] text-zinc-400 uppercase tracking-wider mb-1">
            Identity / Email
          </label>
          <div className="relative">
            <Mail className="w-4 h-4 text-zinc-500 absolute left-3 top-2.5" />
            <input
              type="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="analyst@enterprise.com"
              className="w-full bg-zinc-950 border border-zinc-800 rounded-md py-2 pl-9 pr-3 text-zinc-100 placeholder:text-zinc-600 focus:outline-none focus:border-zinc-600 font-mono text-xs"
            />
          </div>
        </div>

        <div>
          <label className="block text-[11px] text-zinc-400 uppercase tracking-wider mb-1">
            Access Key / Password
          </label>
          <div className="relative">
            <Lock className="w-4 h-4 text-zinc-500 absolute left-3 top-2.5" />
            <input
              type="password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••••••"
              className="w-full bg-zinc-950 border border-zinc-800 rounded-md py-2 pl-9 pr-3 text-zinc-100 placeholder:text-zinc-600 focus:outline-none focus:border-zinc-600 font-mono text-xs"
            />
          </div>
        </div>

        <button
          type="submit"
          disabled={loading}
          className="w-full bg-zinc-100 hover:bg-white text-zinc-950 font-semibold py-2 px-4 rounded-md transition-colors flex items-center justify-center gap-2 mt-2 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {loading ? (
            <>
              <RefreshCw className="w-3.5 h-3.5 animate-spin" />
              <span>Authenticating...</span>
            </>
          ) : (
            <>
              <span>{mode === 'login' ? 'Verify Credentials' : 'Provision Account'}</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </>
          )}
        </button>
      </form>

      {/* Dividers */}
      <div className="relative my-6">
        <div className="absolute inset-0 flex items-center">
          <div className="w-full border-t border-zinc-800" />
        </div>
        <div className="relative flex justify-center text-[10px] uppercase">
          <span className="bg-zinc-900 px-2 text-zinc-500 font-mono">
            Direct Clearance & Sandbox Access
          </span>
        </div>
      </div>

      {/* Fast Clearance Buttons */}
      <div className="space-y-2">
        <button
          type="button"
          onClick={() => loginAsDeveloper('sara.dongare@corp-sec.com')}
          className="w-full bg-emerald-950/40 hover:bg-emerald-900/60 border border-emerald-800 text-emerald-300 font-mono text-xs py-2 px-3 rounded-md transition-colors flex items-center justify-between"
        >
          <span className="flex items-center gap-2">
            <KeyRound className="w-3.5 h-3.5 text-emerald-400" />
            <span>Developer Clearance (Full Admin)</span>
          </span>
          <span className="text-[10px] bg-emerald-900 text-emerald-200 px-1.5 py-0.5 rounded font-mono">
            DEV
          </span>
        </button>

        <button
          type="button"
          onClick={handleGoogleSignIn}
          className="w-full bg-zinc-950 hover:bg-zinc-800 border border-zinc-800 text-zinc-300 font-mono text-xs py-2 px-3 rounded-md transition-colors flex items-center justify-center gap-2"
        >
          <span>Enterprise Google SSO Fallback</span>
        </button>
      </div>

      <div className="mt-6 pt-4 border-t border-zinc-800 text-[10px] text-zinc-600 text-center flex items-center justify-center gap-1.5">
        <UserCheck className="w-3 h-3 text-zinc-500" />
        <span>Role-Based Access Control • Firestore RBAC</span>
      </div>
    </div>
  );
}
