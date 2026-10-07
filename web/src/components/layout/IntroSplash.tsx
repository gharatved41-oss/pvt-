'use client';

import React, { useEffect, useState } from 'react';

interface IntroSplashProps {
  onComplete: () => void;
}

export function IntroSplash({ onComplete }: IntroSplashProps) {
  const [fading, setFading] = useState(false);

  useEffect(() => {
    // Check if user has already seen the intro during this browser session
    const seen = typeof window !== 'undefined' ? sessionStorage.getItem('hasSeenIntro') : null;
    if (seen === 'true') {
      onComplete();
      return;
    }

    // Set fading state after 1.4s, and terminate at 1.8s
    const fadeTimer = setTimeout(() => {
      setFading(true);
    }, 1400);

    const completeTimer = setTimeout(() => {
      if (typeof window !== 'undefined') {
        sessionStorage.setItem('hasSeenIntro', 'true');
      }
      onComplete();
    }, 1800);

    return () => {
      clearTimeout(fadeTimer);
      clearTimeout(completeTimer);
    };
  }, [onComplete]);

  return (
    <div
      className={`fixed inset-0 z-50 bg-zinc-950 flex flex-col items-center justify-center select-none transition-opacity duration-400 ease-out ${
        fading ? 'opacity-0 pointer-events-none' : 'opacity-100'
      }`}
    >
      <div className="flex flex-col items-center gap-6">
        {/* Minimal SVG Network Node Animation */}
        <div className="w-24 h-24 relative flex items-center justify-center">
          <svg viewBox="0 0 100 100" className="w-full h-full" fill="none" xmlns="http://www.w3.org/2000/svg">
            {/* Edges */}
            <line x1="50" y1="20" x2="20" y2="70" stroke="#3f3f46" strokeWidth="1" strokeDasharray="3 3" />
            <line x1="50" y1="20" x2="80" y2="70" stroke="#3f3f46" strokeWidth="1" strokeDasharray="3 3" />
            <line x1="20" y1="70" x2="80" y2="70" stroke="#3f3f46" strokeWidth="1" strokeDasharray="3 3" />
            <line x1="50" y1="20" x2="50" y2="52" stroke="#71717a" strokeWidth="1" />
            <line x1="20" y1="70" x2="50" y2="52" stroke="#71717a" strokeWidth="1" />
            <line x1="80" y1="70" x2="50" y2="52" stroke="#71717a" strokeWidth="1" />

            {/* Nodes */}
            <circle cx="50" cy="20" r="3.5" fill="#f43f5e" />
            <circle cx="20" cy="70" r="3" fill="#a1a1aa" />
            <circle cx="80" cy="70" r="3" fill="#a1a1aa" />
            <circle cx="50" cy="52" r="4" fill="#10b981" />
          </svg>
        </div>

        {/* Monospaced Title */}
        <div className="text-center font-mono space-y-1">
          <div className="text-xs sm:text-sm font-bold tracking-widest text-zinc-100 uppercase">
            VULNTWIN AI // EXPOSURE VALIDATION
          </div>
          <div className="text-[10px] text-zinc-500 uppercase tracking-widest">
            INITIALIZING ADVERSARIAL GRAPH ENGINE
          </div>
        </div>
      </div>
    </div>
  );
}
