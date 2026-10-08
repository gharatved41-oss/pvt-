"use client";

import React, { useEffect } from 'react';
import { AlertTriangle, RotateCcw } from 'lucide-react';

export default function DashboardError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    // Log the error to an error reporting service if available
    console.error('[CRITICAL_FAILURE] UI Subsystem Offline:', error);
  }, [error]);

  return (
    <div className="h-full w-full bg-zinc-950 flex flex-col items-center justify-center font-mono p-8 text-xs">
      <div className="border border-red-500/50 bg-red-950/10 p-8 max-w-lg w-full flex flex-col items-center text-center gap-6">
        <div className="bg-red-950/50 border border-red-900 text-red-500 p-4 rounded-full">
          <AlertTriangle className="w-8 h-8" />
        </div>
        
        <div className="flex flex-col gap-2">
          <h2 className="text-red-500 font-bold uppercase tracking-widest text-sm">
            [CRITICAL_FAILURE] UI Subsystem Offline
          </h2>
          <p className="text-red-400/70 bg-red-950/30 p-4 border border-red-900/50 break-words whitespace-pre-wrap">
            {error.message || "An unexpected runtime anomaly caused the workspace to crash."}
          </p>
        </div>

        <button
          onClick={() => reset()}
          className="bg-red-950 border border-red-900 text-red-500 hover:bg-red-900 hover:text-white transition-colors px-6 py-3 uppercase tracking-widest font-bold flex items-center gap-2 mt-4"
        >
          <RotateCcw className="w-4 h-4" />
          [ REBOOT WORKSPACE ]
        </button>
      </div>
    </div>
  );
}
