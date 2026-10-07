'use client';

import React, { useEffect, useState } from 'react';

interface IntroSplashProps {
  onComplete: () => void;
}

export function IntroSplash({ onComplete }: IntroSplashProps) {
  const [fading, setFading] = useState(false);
  const [stage, setStage] = useState<'drawing' | 'locked' | 'fading'>('drawing');

  useEffect(() => {
    // 0ms - 1100ms: SVG topology path calculation & node drawing
    const tStage = setTimeout(() => {
      setStage('locked');
    }, 1100);

    // 2200ms: Start fade transition
    const tFade = setTimeout(() => {
      setFading(true);
      setStage('fading');
    }, 2200);

    // 2700ms: Complete and notify parent
    const tComplete = setTimeout(() => {
      if (typeof window !== 'undefined') {
        sessionStorage.setItem('hasSeenIntro', 'true');
      }
      onComplete();
    }, 2700);

    return () => {
      clearTimeout(tStage);
      clearTimeout(tFade);
      clearTimeout(tComplete);
    };
  }, [onComplete]);

  const handleSkip = () => {
    if (typeof window !== 'undefined') {
      sessionStorage.setItem('hasSeenIntro', 'true');
    }
    onComplete();
  };

  return (
    <div
      className={`fixed inset-0 z-[100] bg-zinc-950 flex flex-col items-center justify-center select-none font-mono transition-opacity duration-500 ease-out ${
        fading ? 'opacity-0 pointer-events-none' : 'opacity-100'
      }`}
    >
      {/* Skip Button */}
      <button
        type="button"
        onClick={handleSkip}
        className="absolute top-6 right-6 px-3 py-1 bg-zinc-900 hover:bg-zinc-800 border border-zinc-800 text-zinc-400 hover:text-zinc-100 text-[11px] uppercase tracking-wider transition-colors z-10"
      >
        [SKIP_INTRO]
      </button>

      <div className="flex flex-col items-center gap-7 px-4">
        {/* Architectural Network Twin Logo Reveal */}
        <div className="w-44 h-44 relative flex items-center justify-center">
          <svg
            viewBox="0 0 160 160"
            className="w-full h-full overflow-visible"
            fill="none"
            xmlns="http://www.w3.org/2000/svg"
          >
            {/* Outer Hexagonal Security Boundary */}
            <polygon
              points="80,14 136,46 136,114 80,146 24,114 24,46"
              stroke="#3f3f46"
              strokeWidth="2"
              className="anim-draw-edge"
            />

            {/* Inner Directed Graph Edges */}
            {/* Ingress (80, 42) -> Web Gateway (48, 86) */}
            <line
              x1="80"
              y1="42"
              x2="48"
              y2="86"
              stroke={stage !== 'drawing' ? '#ef4444' : '#71717a'}
              strokeWidth="2.5"
              className="anim-draw-edge"
            />
            {/* Ingress (80, 42) -> Auth Microservice (112, 86) */}
            <line
              x1="80"
              y1="42"
              x2="112"
              y2="86"
              stroke={stage !== 'drawing' ? '#10b981' : '#71717a'}
              strokeWidth="2.5"
              className="anim-draw-edge"
            />
            {/* Web Gateway (48, 86) -> Crown Jewel Database (80, 122) */}
            <line
              x1="48"
              y1="86"
              x2="80"
              y2="122"
              stroke={stage !== 'drawing' ? '#ef4444' : '#71717a'}
              strokeWidth="2.5"
              strokeDasharray={stage === 'drawing' ? '4 4' : undefined}
              className="anim-draw-edge"
            />
            {/* Auth Microservice (112, 86) -> Crown Jewel Database (80, 122) */}
            <line
              x1="112"
              y1="86"
              x2="80"
              y2="122"
              stroke={stage !== 'drawing' ? '#10b981' : '#71717a'}
              strokeWidth="2"
              className="anim-draw-edge"
            />
            {/* Inter-Tier Lateral Bridge (48, 86) -> (112, 86) */}
            <line
              x1="48"
              y1="86"
              x2="112"
              y2="86"
              stroke="#52525b"
              strokeWidth="1.5"
              strokeDasharray="3 3"
            />

            {/* Traversal Particle Radar Beam */}
            <polygon
              points="80,14 136,46 136,114 80,146 24,114 24,46"
              stroke="#3b82f6"
              strokeWidth="1.5"
              className="anim-beam"
            />

            {/* Graph Vertices / Nodes */}
            {/* Vertex 1: Ingress Gateway (Top) */}
            <circle
              cx="80"
              cy="42"
              r="7"
              className={stage !== 'drawing' ? 'fill-red-500 stroke-zinc-950 stroke-2' : 'fill-zinc-600'}
            />
            <circle cx="80" cy="42" r="11" className="stroke-red-500/50 stroke-1 fill-none anim-node-pulse" />

            {/* Vertex 2: Compute Node (Left) */}
            <circle
              cx="48"
              cy="86"
              r="6.5"
              className={stage !== 'drawing' ? 'fill-amber-500 stroke-zinc-950 stroke-2' : 'fill-zinc-600'}
            />

            {/* Vertex 3: IAM Authority Node (Right) */}
            <circle
              cx="112"
              cy="86"
              r="6.5"
              className={stage !== 'drawing' ? 'fill-emerald-400 stroke-zinc-950 stroke-2' : 'fill-zinc-600'}
            />

            {/* Vertex 4: Crown Jewel Target (Bottom) */}
            <circle
              cx="80"
              cy="122"
              r="8"
              className={stage !== 'drawing' ? 'fill-red-600 stroke-zinc-950 stroke-2' : 'fill-zinc-600'}
            />
            <circle cx="80" cy="122" r="14" className="stroke-red-500/60 stroke-1 fill-none anim-node-pulse" />
          </svg>
        </div>

        {/* Monospaced Precision Typography */}
        <div className="flex flex-col items-center text-center space-y-2">
          <div className="text-sm sm:text-base font-bold tracking-[0.25em] text-zinc-100 uppercase">
            VULNTWIN AI // EXPOSURE VALIDATION
          </div>
          <div className="text-[11px] text-zinc-400 tracking-[0.2em] uppercase flex items-center gap-2">
            <span className="w-2 h-2 bg-emerald-400 rounded-none inline-block animate-ping" />
            <span>CONTINUOUS THREAT EXPOSURE MANAGEMENT</span>
          </div>
          <div className="text-[10px] text-zinc-600 uppercase tracking-widest mt-1">
            INITIALIZING ADVERSARIAL TOPOLOGY ENGINE...
          </div>
        </div>
      </div>
    </div>
  );
}
