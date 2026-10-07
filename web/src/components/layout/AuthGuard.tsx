'use client';

import React, { useEffect, useState, ReactNode } from 'react';
import { useAuthStore } from '@/store/useAuthStore';
import { AuthForm } from '@/components/auth/AuthForm';

interface AuthGuardProps {
  children: ReactNode;
}

export function AuthGuard({ children }: AuthGuardProps) {
  const { user, loading, setupAuthListener } = useAuthStore();
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
    const unsubscribe = setupAuthListener();
    return () => {
      if (unsubscribe) unsubscribe();
    };
  }, [setupAuthListener]);

  // Prevent Next.js hydration mismatch between server and client
  if (!mounted || loading) {
    return (
      <div className="h-screen w-full bg-zinc-950 flex flex-col items-center justify-center gap-2 text-zinc-400 font-mono text-xs select-none">
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
          <span className="text-zinc-300 font-semibold">[SYSTEM]</span>
          <span>Authenticating session state...</span>
        </div>
        <div className="text-[10px] text-zinc-600">
          VulnTwin AI Security Core • Verified JWT Engine
        </div>
      </div>
    );
  }

  // Unauthenticated State: Render clean dark-mode authentication panel
  if (!user) {
    return (
      <div className="min-h-screen w-full bg-zinc-950 flex items-center justify-center p-4">
        <AuthForm />
      </div>
    );
  }

  // Authenticated State: Reveal protected dashboard application
  return <>{children}</>;
}
