"use client";

import React from 'react';
import { useAuthStore } from '@/store/useAuthStore';
import { logout } from '@/lib/authService';
import { useRouter } from 'next/navigation';

export default function TopNav() {
  const { user, role } = useAuthStore();
  const router = useRouter();

  const handleLogout = async () => {
    await logout();
    router.push('/');
  };

  return (
    <div className="h-12 w-full bg-zinc-950 border-b border-zinc-800 flex items-center justify-between px-4 font-mono text-xs text-zinc-200">
      <div className="font-bold tracking-widest uppercase">
        VulnTwin AI <span className="text-zinc-600">//</span> CTEM Console
      </div>
      
      <div className="flex items-center gap-4">
        {user && (
          <>
            <span className="text-zinc-400">{user.email}</span>
            {role === 'developer' ? (
              <span className="px-2 py-0.5 bg-emerald-950 text-emerald-400 border border-emerald-800">
                DEVELOPER
              </span>
            ) : (
              <span className="px-2 py-0.5 bg-zinc-900 text-zinc-400 border border-zinc-700">
                STANDARD
              </span>
            )}
            <button 
              onClick={handleLogout}
              className="text-zinc-500 hover:text-zinc-200 transition-colors uppercase ml-2"
            >
              [Sign Out]
            </button>
          </>
        )}
      </div>
    </div>
  );
}
