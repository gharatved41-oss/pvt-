import React from 'react';

export default function DashboardLoading() {
  return (
    <div className="h-full w-full bg-zinc-950 flex flex-col items-center justify-center font-mono p-8 gap-8">
      <div className="text-zinc-500 text-xs tracking-widest uppercase font-bold animate-pulse">
        &gt; INITIALIZING SECURE WORKSPACE...
      </div>
      
      <div className="w-full max-w-4xl grid grid-cols-12 gap-4 h-64">
        {/* Skeleton Sidebar / Sub-nav Area */}
        <div className="col-span-3 flex flex-col gap-2">
          <div className="h-8 bg-zinc-900 border border-zinc-800 animate-pulse w-full"></div>
          <div className="h-8 bg-zinc-900 border border-zinc-800 animate-pulse w-5/6"></div>
          <div className="h-8 bg-zinc-900 border border-zinc-800 animate-pulse w-4/6"></div>
          <div className="h-8 bg-zinc-900 border border-zinc-800 animate-pulse w-full"></div>
        </div>
        
        {/* Skeleton Main Workspace */}
        <div className="col-span-9 flex flex-col gap-4">
          <div className="h-16 bg-zinc-900 border border-zinc-800 animate-pulse w-full"></div>
          <div className="flex-1 bg-zinc-900 border border-zinc-800 animate-pulse w-full"></div>
        </div>
      </div>
    </div>
  );
}
