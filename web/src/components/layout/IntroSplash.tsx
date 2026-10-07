'use client';

import React, { useEffect, useState } from 'react';

interface IntroSplashProps {
  onComplete: () => void;
}

export function IntroSplash({ onComplete }: IntroSplashProps) {
  const [phase, setPhase] = useState<'drawing' | 'illuminating' | 'fading' | 'done'>('drawing');

  useEffect(() => {
    // 0ms - 800ms: SVG edges drawing
    const t1 = setTimeout(() => {
      setPhase('illuminating');
    }, 800);

    // 800ms - 1400ms: Node points illuminate & typography fades in
    const t2 = setTimeout(() => {
      setPhase('fading');
    }, 1400);

    // 1400ms - 1800ms: Fade out splash completely
    const t3 = setTimeout(() => {
      setPhase('done');
      if (typeof window !== 'undefined') {
        sessionStorage.setItem('hasSeenIntro', 'true');
      }
      onComplete();
    }, 1800);

    return () => {
      clearTimeout(t1);
      clearTimeout(t2);
      clearTimeout(t3);
    };
  }, [onComplete]);

  if (phase === 'done') return null;

  return (
    <div
      className={`fixed inset-0 z-50 bg-zinc-950 flex flex-col items-center justify-center select-none transition-opacity duration-400 ease-out ${
        phase === 'fading' ? 'opacity-0 pointer-events-none' : 'opacity-100'
      }`}
    >
      <div className="flex flex-col items-center gap-6">
        {/* Stylized Network Topology Graph SVG Monogram */}
        <div className="relative w-36 h-36 flex items-center justify-center">
          <svg
            viewBox="0 0 140 140"
            className="w-full h-full overflow-visible"
            fill="none"
            xmlns="http://www.w3.org/2000/svg"
          >
            {/* Geometric Shield / Topology Boundary */}
            <path
              d="M70 12 L120 36 V76 C120 102 96 122 70 130 C44 122 20 102 20 76 V36 L70 12 Z"
              stroke="#27272a"
              strokeWidth="1.5"
              strokeDasharray="400"
              strokeDashoffset={phase === 'drawing' ? '400' : '0'}
              className="transition-all duration-700 ease-in-out"
            />

            {/* Interconnected Graph Edges */}
            {/* Top Node -> Left / Right */}
            <line
              x1="70"
              y1="34"
              x2="40"
              y2="66"
              stroke={phase !== 'drawing' ? '#34d399' : '#10b981'}
              strokeWidth="2"
              strokeDasharray="100"
              strokeDashoffset={phase === 'drawing' ? '100' : '0'}
              className="transition-all duration-500 ease-out"
            />
            <line
              x1="70"
              y1="34"
              x2="100"
              y2="66"
              stroke={phase !== 'drawing' ? '#34d399' : '#10b981'}
              strokeWidth="2"
              strokeDasharray="100"
              strokeDashoffset={phase === 'drawing' ? '100' : '0'}
              className="transition-all duration-500 ease-out"
            />
            {/* Center Bridge */}
            <line
              x1="40"
              y1="66"
              x2="100"
              y2="66"
              stroke="#3f3f46"
              strokeWidth="1.5"
              strokeDasharray="100"
              strokeDashoffset={phase === 'drawing' ? '100' : '0'}
              className="transition-all duration-600 ease-out"
            />
            {/* Left -> Core / Right -> Core */}
            <line
              x1="40"
              y1="66"
              x2="70"
              y2="98"
              stroke={phase !== 'drawing' ? '#34d399' : '#10b981'}
              strokeWidth="2"
              strokeDasharray="100"
              strokeDashoffset={phase === 'drawing' ? '100' : '0'}
              className="transition-all duration-700 ease-out"
            />
            <line
              x1="100"
              y1="66"
              x2="70"
              y2="98"
              stroke={phase !== 'drawing' ? '#34d399' : '#10b981'}
              strokeWidth="2"
              strokeDasharray="100"
              strokeDashoffset={phase === 'drawing' ? '100' : '0'}
              className="transition-all duration-700 ease-out"
            />

            {/* Illuminated Topology Graph Nodes */}
            {/* Node 1: Ingress (Top) */}
            <circle
              cx="70"
              cy="34"
              r="4.5"
              className={`transition-all duration-500 ${
                phase !== 'drawing' ? 'fill-emerald-400 stroke-zinc-950 stroke-2 filter drop-shadow-[0_0_6px_rgba(52,211,153,0.8)]' : 'fill-zinc-700'
              }`}
            />
            {/* Node 2: Web Compute (Left) */}
            <circle
              cx="40"
              cy="66"
              r="4"
              className={`transition-all duration-500 delay-100 ${
                phase !== 'drawing' ? 'fill-emerald-400 stroke-zinc-950 stroke-2 filter drop-shadow-[0_0_6px_rgba(52,211,153,0.8)]' : 'fill-zinc-700'
              }`}
            />
            {/* Node 3: Auth Authority (Right) */}
            <circle
              cx="100"
              cy="66"
              r="4"
              className={`transition-all duration-500 delay-150 ${
                phase !== 'drawing' ? 'fill-emerald-400 stroke-zinc-950 stroke-2 filter drop-shadow-[0_0_6px_rgba(52,211,153,0.8)]' : 'fill-zinc-700'
              }`}
            />
            {/* Node 4: Crown Jewel DB (Bottom) */}
            <circle
              cx="70"
              cy="98"
              r="5"
              className={`transition-all duration-500 delay-200 ${
                phase !== 'drawing' ? 'fill-emerald-300 stroke-zinc-950 stroke-2 filter drop-shadow-[0_0_8px_rgba(110,231,183,0.9)]' : 'fill-zinc-700'
              }`}
            />
          </svg>
        </div>

        {/* Monospaced Brand Typography */}
        <div
          className={`flex flex-col items-center text-center transition-all duration-500 ${
            phase !== 'drawing' ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-2'
          }`}
        >
          <div className="text-xl font-bold font-mono tracking-[0.25em] text-zinc-100 uppercase">
            VulnTwin AI
          </div>
          <div className="text-[10px] font-mono tracking-[0.3em] text-emerald-400/90 uppercase mt-1">
            Continuous Threat Exposure Management
          </div>
          <div className="flex items-center gap-2 mt-3 text-[10px] font-mono text-zinc-500">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-ping" />
            <span>INITIALIZING GRAPH RUNTIME</span>
          </div>
        </div>
      </div>
    </div>
  );
}
