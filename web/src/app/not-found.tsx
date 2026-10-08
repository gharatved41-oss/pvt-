import React from 'react';
import Link from 'next/link';
import { TerminalSquare } from 'lucide-react';

export default function NotFound() {
  return (
    <div className="h-screen w-full bg-zinc-950 flex flex-col items-center justify-center font-mono p-4 text-xs">
      <div className="max-w-md w-full border border-zinc-800 bg-zinc-950 p-6 flex flex-col gap-6 shadow-2xl">
        <div className="flex items-center gap-3 border-b border-zinc-800 pb-4">
          <TerminalSquare className="w-5 h-5 text-zinc-500" />
          <span className="text-zinc-400 uppercase tracking-widest font-bold">System Exception</span>
        </div>
        
        <div className="flex flex-col gap-2">
          <h1 className="text-zinc-300 font-bold text-lg">404 // ENDPOINT_NOT_FOUND</h1>
          <p className="text-zinc-500 leading-relaxed">
            The requested resource or directory path does not exist within the current environment topology. 
            Traffic has been null-routed.
          </p>
        </div>

        <div className="pt-4 mt-2 border-t border-zinc-800">
          <Link 
            href="/dashboard"
            className="inline-flex w-full bg-zinc-200 text-zinc-950 items-center justify-center py-3 font-bold uppercase tracking-widest hover:bg-white transition-colors"
          >
            [ RETURN TO GATEWAY ]
          </Link>
        </div>
      </div>
    </div>
  );
}
