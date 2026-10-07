'use client';

import React, { useEffect } from 'react';
import { onAuthStateChanged } from 'firebase/auth';
import { auth } from '@/lib/firebase';
import { syncUserRole } from '@/lib/authService';
import { useAuthStore } from '@/store/useAuthStore';

interface AuthProviderProps {
  children: React.ReactNode;
}

export function AuthProvider({ children }: AuthProviderProps) {
  const { isInitialized, setAuthState } = useAuthStore();

  useEffect(() => {
    const unsubscribe = onAuthStateChanged(auth, async (firebaseUser) => {
      if (!firebaseUser) {
        setAuthState(null, null);
        return;
      }

      try {
        const role = await syncUserRole(firebaseUser);
        setAuthState(firebaseUser, role);
      } catch (err) {
        console.error('[AUTH_ERROR] Error synchronizing user role:', err);
        setAuthState(firebaseUser, 'user');
      }
    });

    return () => unsubscribe();
  }, [setAuthState]);

  if (!isInitialized) {
    return (
      <div className="fixed inset-0 z-[200] bg-zinc-950 flex flex-col items-center justify-center font-mono text-xs text-zinc-100 select-none">
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 bg-emerald-400 rounded-none animate-ping" />
          <span className="tracking-widest uppercase text-zinc-300">
            [SYSTEM] Initializing Auth Sequence...
          </span>
        </div>
      </div>
    );
  }

  return <>{children}</>;
}
