import React from 'react';

interface ModuleWrapperProps {
  title: string;
  description: string;
  children: React.ReactNode;
}

export default function ModuleWrapper({ title, description, children }: ModuleWrapperProps) {
  return (
    <div className="flex-1 flex flex-col h-full bg-zinc-950 p-6 overflow-y-auto">
      <div className="shrink-0">
        <h1 className="font-mono text-lg text-zinc-100 uppercase tracking-widest">{title}</h1>
        <p className="font-mono text-xs text-zinc-500 mb-6 uppercase tracking-wider">{description}</p>
      </div>
      <div className="flex-1">
        {children}
      </div>
    </div>
  );
}
