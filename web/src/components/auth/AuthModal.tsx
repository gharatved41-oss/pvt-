'use client';

import React, { useState } from 'react';
import {
  Shield,
  Lock,
  Mail,
  ArrowRight,
  AlertCircle,
  RefreshCw,
  KeyRound,
  X,
  CheckCircle2,
  Send,
  AlertTriangle,
} from 'lucide-react';
import {
  signInWithGoogle,
  signInWithApple,
  registerWithEmail,
  loginWithEmail,
  resendVerificationEmail,
  reloadUserSession,
} from '@/lib/authService';
import { useAuthStore } from '@/store/useAuthStore';

interface AuthModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess?: () => void;
  targetAction?: string;
  initialPendingVerification?: boolean;
}

export function AuthModal({
  isOpen,
  onClose,
  onSuccess,
  targetAction,
  initialPendingVerification = false,
}: AuthModalProps) {
  const { user, role, loginAsDeveloper } = useAuthStore();
  const [mode, setMode] = useState<'signin' | 'register'>('signin');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [verificationPending, setVerificationPending] = useState(initialPendingVerification);
  const [registeredEmail, setRegisteredEmail] = useState('');
  const [resendCooldown, setResendCooldown] = useState(false);
  const [resendMessage, setResendMessage] = useState<string | null>(null);

  React.useEffect(() => {
    if (isOpen) {
      if (initialPendingVerification || (user && role !== 'developer' && !user.emailVerified)) {
        setVerificationPending(true);
        setRegisteredEmail(user?.email || '');
      } else {
        setVerificationPending(false);
      }
      setError(null);
      setResendMessage(null);
    }
  }, [isOpen, initialPendingVerification, user, role]);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setResendMessage(null);
    setLoading(true);

    try {
      if (mode === 'register') {
        const cred = await registerWithEmail(email, password);
        setRegisteredEmail(cred.user.email || email);
        setVerificationPending(true);
      } else {
        const cred = await loginWithEmail(email, password);
        const currentRole = useAuthStore.getState().role;

        // If standard account and email not verified, gate access
        if (currentRole !== 'developer' && !cred.user.emailVerified) {
          setRegisteredEmail(cred.user.email || email);
          setVerificationPending(true);
        } else {
          if (onSuccess) onSuccess();
          onClose();
        }
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : '';
      if (msg.includes('auth/invalid-credential') || msg.includes('auth/wrong-password')) {
        setError('Invalid credentials. Please verify your email and password.');
      } else if (msg.includes('auth/email-already-in-use')) {
        setError('This email is already registered. Please switch to Sign In.');
      } else if (msg.includes('auth/weak-password')) {
        setError('Password must contain at least 6 characters.');
      } else if (msg.includes('auth/invalid-email')) {
        setError('Please enter a valid corporate email format.');
      } else {
        setError(msg || 'Authentication service error. Please try again.');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleGoogleAuth = async () => {
    setError(null);
    setLoading(true);
    try {
      await signInWithGoogle();
      if (onSuccess) onSuccess();
      onClose();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : '';
      setError(msg || 'Google Sign-In was cancelled or failed.');
    } finally {
      setLoading(false);
    }
  };

  const handleAppleAuth = async () => {
    setError(null);
    setLoading(true);
    try {
      await signInWithApple();
      if (onSuccess) onSuccess();
      onClose();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : '';
      setError(msg || 'Apple Sign-In was cancelled or failed.');
    } finally {
      setLoading(false);
    }
  };

  const handleResendLink = async () => {
    try {
      setLoading(true);
      setError(null);
      await resendVerificationEmail();
      setResendMessage('A new verification email has been dispatched to your inbox.');
      setResendCooldown(true);
      setTimeout(() => setResendCooldown(false), 30000);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : '';
      setError(msg || 'Failed to dispatch verification email.');
    } finally {
      setLoading(false);
    }
  };

  const handleCheckStatus = async () => {
    setLoading(true);
    setError(null);
    try {
      const isVerified = await reloadUserSession();
      const currentRole = useAuthStore.getState().role;
      if (isVerified || currentRole === 'developer') {
        if (onSuccess) onSuccess();
        onClose();
      } else {
        setError('Email has not been verified yet. Please click the link in your inbox.');
      }
    } catch {
      setError('Could not refresh status. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleDeveloperOverride = () => {
    loginAsDeveloper('sara.dongare@corp-sec.com');
    if (onSuccess) onSuccess();
    onClose();
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4 font-mono select-none animate-in fade-in duration-150">
      <div className="bg-zinc-900 border border-zinc-800 text-zinc-100 rounded-lg p-6 max-w-md w-full relative shadow-2xl">
        {/* Close Button */}
        <button
          type="button"
          onClick={onClose}
          className="absolute right-4 top-4 p-1 text-zinc-400 hover:text-zinc-100 hover:bg-zinc-800 rounded transition-colors"
        >
          <X className="w-4 h-4" />
        </button>

        {/* Modal Header */}
        <div className="flex items-center gap-3 mb-6 pb-4 border-b border-zinc-800">
          <div className="w-8 h-8 rounded bg-zinc-950 border border-zinc-700 flex items-center justify-center text-emerald-400">
            <Shield className="w-4 h-4" />
          </div>
          <div>
            <h2 className="text-xs font-bold tracking-wider text-zinc-100 uppercase">
              Authentication Gateway
            </h2>
            <p className="text-[10px] text-zinc-500 uppercase tracking-widest">
              {targetAction ? `Access Gated: ${targetAction}` : 'Adversarial Twin Access'}
            </p>
          </div>
        </div>

        {/* Verification Pending Screen */}
        {verificationPending ? (
          <div className="space-y-4">
            <div className="p-4 bg-emerald-950/30 border border-emerald-800/80 rounded-md text-emerald-300 text-xs space-y-2">
              <div className="flex items-center gap-2 font-semibold text-emerald-400">
                <CheckCircle2 className="w-4 h-4 shrink-0" />
                <span>Verification Link Sent</span>
              </div>
              <p className="text-[11px] text-zinc-300 leading-relaxed font-sans">
                Verification email sent to{' '}
                <span className="font-mono text-emerald-400 font-semibold">
                  {registeredEmail || user?.email || email}
                </span>
                . Please click the confirmation link to activate your access.
              </p>
            </div>

            {resendMessage && (
              <div className="p-2.5 bg-zinc-950 border border-emerald-900 text-emerald-400 text-xs rounded flex items-center gap-2">
                <CheckCircle2 className="w-3.5 h-3.5" />
                <span>{resendMessage}</span>
              </div>
            )}

            {error && (
              <div className="p-3 bg-red-950/40 border border-red-800 text-red-300 text-xs flex items-center gap-2 rounded">
                <AlertCircle className="w-4 h-4 shrink-0" />
                <span>{error}</span>
              </div>
            )}

            <div className="space-y-2 pt-2">
              <button
                type="button"
                onClick={handleCheckStatus}
                disabled={loading}
                className="w-full bg-zinc-100 hover:bg-white text-zinc-950 font-semibold py-2 px-4 rounded text-xs transition-colors flex items-center justify-center gap-2"
              >
                {loading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <CheckCircle2 className="w-3.5 h-3.5" />}
                <span>I Have Verified My Email (Check Status)</span>
              </button>

              <button
                type="button"
                disabled={loading || resendCooldown}
                onClick={handleResendLink}
                className="w-full bg-zinc-950 hover:bg-zinc-850 border border-zinc-800 text-zinc-300 py-2 px-4 rounded text-xs transition-colors flex items-center justify-center gap-2 disabled:opacity-50"
              >
                <Send className="w-3.5 h-3.5 text-zinc-400" />
                <span>{resendCooldown ? 'Link Dispatched (Wait 30s)' : 'Resend Link'}</span>
              </button>

              <button
                type="button"
                onClick={async () => {
                  setVerificationPending(false);
                  if (user && !user.emailVerified && role !== 'developer') {
                    await useAuthStore.getState().signOut();
                  }
                }}
                className="w-full text-center text-[10px] text-zinc-500 hover:text-zinc-300 pt-2"
              >
                Sign In with Different Account
              </button>
            </div>
          </div>
        ) : (
          <>
            {/* Top Tab Switcher: Sign In | Create Account */}
            <div className="flex border-b border-zinc-800 mb-5 text-xs">
              <button
                type="button"
                onClick={() => {
                  setMode('signin');
                  setError(null);
                }}
                className={`pb-2 mr-6 transition-colors border-b-2 font-medium ${
                  mode === 'signin'
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

            {/* Error Notification */}
            {error && (
              <div className="mb-4 p-3 rounded bg-red-950/40 border border-red-800 text-red-300 text-xs flex items-start gap-2">
                <AlertCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                <div className="flex-1">{error}</div>
              </div>
            )}

            {/* Full-width Social Auth Buttons with Official SVG Brand Icons */}
            <div className="space-y-2.5 mb-4">
              <button
                type="button"
                disabled={loading}
                onClick={handleGoogleAuth}
                className="w-full bg-zinc-950 hover:bg-zinc-850 border border-zinc-800 text-zinc-200 py-2.5 px-3 rounded text-xs flex items-center justify-center gap-2.5 transition-colors disabled:opacity-50"
              >
                <svg className="w-4 h-4" viewBox="0 0 24 24">
                  <path
                    fill="#EA4335"
                    d="M12 5c1.6 0 3 .6 4.1 1.6l3.1-3.1C17.3 1.7 14.8 1 12 1 7.7 1 4 3.5 2.2 7.1l3.7 2.8C6.7 6.8 9.1 5 12 5z"
                  />
                  <path
                    fill="#4285F4"
                    d="M22.6 12.3c0-.8-.1-1.5-.2-2.3H12v4.3h5.9c-.3 1.4-1 2.5-2.2 3.3l3.6 2.8c2.1-1.9 3.3-4.7 3.3-8.1z"
                  />
                  <path
                    fill="#FBBC05"
                    d="M5.8 14.1c-.2-.7-.3-1.4-.3-2.1s.1-1.4.3-2.1L2.2 7.1C1.4 8.6 1 10.2 1 12s.4 3.4 1.2 4.9l3.6-2.8z"
                  />
                  <path
                    fill="#34A853"
                    d="M12 23c3.2 0 6-1.1 7.9-3l-3.6-2.8c-1 .7-2.4 1.1-4.3 1.1-2.9 0-5.3-1.8-6.1-4.4L2.2 16.7C4 20.3 7.7 23 12 23z"
                  />
                </svg>
                <span>Continue with Google</span>
              </button>

              <button
                type="button"
                disabled={loading}
                onClick={handleAppleAuth}
                className="w-full bg-zinc-950 hover:bg-zinc-850 border border-zinc-800 text-zinc-200 py-2.5 px-3 rounded text-xs flex items-center justify-center gap-2.5 transition-colors disabled:opacity-50"
              >
                <svg className="w-4 h-4" viewBox="0 0 170 170" fill="currentColor">
                  <path d="M150.37 130.25c-2.45 5.66-5.35 10.87-8.71 15.66-4.58 6.53-8.33 11.05-11.22 13.56-4.48 4.12-9.28 6.23-14.42 6.35-3.69 0-8.14-1.05-13.32-3.18-5.19-2.12-9.97-3.17-14.34-3.17-4.58 0-9.49 1.05-14.75 3.17-5.26 2.13-9.5 3.24-12.74 3.35-4.35.13-9.16-1.9-14.42-6.08-3.69-3.04-7.67-7.85-11.96-14.42-6.3-9.67-11.2-20.73-14.71-33.17-3.51-12.44-5.27-24.36-5.27-35.75 0-14.56 3.45-26.66 10.35-36.31 6.9-9.65 15.68-14.54 26.34-14.67 4.58 0 9.87 1.25 15.87 3.75 6 2.5 10.02 3.81 12.06 3.94 1.77-.13 5.95-1.47 12.56-4.01 6.6-2.54 11.83-3.68 15.67-3.43 14.56.76 25.68 5.75 33.36 14.97-12.74 7.74-19 18.25-18.77 31.53.25 10.38 4.19 19.04 11.82 25.99 7.63 6.95 16.78 10.89 27.46 11.83-2.53 7.64-5.6 15.11-9.21 22.41zM119.22 33.51c0-7.39 2.67-14.39 8.01-21 5.34-6.61 11.89-10.99 19.64-13.14.76 3.68 1.05 7.19.86 10.53-.38 6.46-3.08 13.06-8.1 19.8-5.02 6.74-11.37 10.85-19.04 12.33-.37-2.67-1.37-5.51-1.37-8.52z" />
                </svg>
                <span>Continue with Apple</span>
              </button>
            </div>

            {/* Exact Divider Specification */}
            <div className="relative my-5 text-center">
              <span className="text-zinc-600 font-mono text-xs tracking-wider">
                ── OR CONTINUE WITH EMAIL ──
              </span>
            </div>

            {/* Email / Password Form */}
            <form onSubmit={handleSubmit} className="space-y-3.5 text-xs">
              <div>
                <label className="block text-[10px] text-zinc-400 uppercase tracking-wider mb-1">
                  Corporate Email
                </label>
                <div className="relative">
                  <Mail className="w-3.5 h-3.5 text-zinc-500 absolute left-3 top-2.5" />
                  <input
                    type="email"
                    required
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="analyst@enterprise.com"
                    className="w-full bg-zinc-950 border border-zinc-800 rounded py-2 pl-9 pr-3 text-zinc-100 placeholder:text-zinc-600 focus:outline-none focus:border-zinc-600 text-xs font-mono"
                  />
                </div>
              </div>

              <div>
                <label className="block text-[10px] text-zinc-400 uppercase tracking-wider mb-1">
                  Access Key / Password
                </label>
                <div className="relative">
                  <Lock className="w-3.5 h-3.5 text-zinc-500 absolute left-3 top-2.5" />
                  <input
                    type="password"
                    required
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="••••••••••••"
                    className="w-full bg-zinc-950 border border-zinc-800 rounded py-2 pl-9 pr-3 text-zinc-100 placeholder:text-zinc-600 focus:outline-none focus:border-zinc-600 text-xs font-mono"
                  />
                </div>
              </div>

              <button
                type="submit"
                disabled={loading}
                className="w-full bg-zinc-100 hover:bg-white text-zinc-950 font-semibold py-2 px-4 rounded transition-colors flex items-center justify-center gap-2 mt-2 disabled:opacity-50"
              >
                {loading ? (
                  <>
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    <span>Processing...</span>
                  </>
                ) : (
                  <>
                    <span>{mode === 'signin' ? 'Sign In to Workspace' : 'Register & Dispatch Verification'}</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </>
                )}
              </button>
            </form>

            {/* Developer Override Button */}
            <div className="mt-5 pt-4 border-t border-zinc-800 space-y-2">
              <button
                type="button"
                onClick={handleDeveloperOverride}
                className="w-full bg-emerald-950/40 hover:bg-emerald-900/60 border border-emerald-800 text-emerald-300 text-xs py-2 px-3 rounded flex items-center justify-between transition-colors"
              >
                <span className="flex items-center gap-2">
                  <KeyRound className="w-3.5 h-3.5 text-emerald-400" />
                  <span>Developer Clearance (Bypass Verification)</span>
                </span>
                <span className="text-[10px] bg-emerald-900 text-emerald-200 px-1.5 py-0.5 rounded font-mono">
                  DEV
                </span>
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
