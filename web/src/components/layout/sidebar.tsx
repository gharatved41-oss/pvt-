"use client";

import React from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { 
  LayoutDashboard, 
  Search, 
  AlertTriangle, 
  FileSearch, 
  Network, 
  ShieldCheck, 
  Wrench, 
  BrainCircuit, 
  FileText 
} from 'lucide-react';

const NAV_ITEMS = [
  { name: 'Dashboard', path: '/dashboard', icon: LayoutDashboard },
  { name: 'Analyze', path: '/dashboard/analyze', icon: Search },
  { name: 'Findings', path: '/dashboard/findings', icon: AlertTriangle },
  { name: 'File & OS Forensics', path: '/dashboard/forensics', icon: FileSearch },
  { name: 'Digital Twin', path: '/dashboard/twin', icon: Network },
  { name: 'Validation', path: '/dashboard/validation', icon: ShieldCheck },
  { name: 'Remediation', path: '/dashboard/remediation', icon: Wrench },
  { name: 'Security Memory', path: '/dashboard/memory', icon: BrainCircuit },
  { name: 'Reports', path: '/dashboard/reports', icon: FileText },
];

export function Sidebar({ className }: { className?: string }) {
  const pathname = usePathname();

  return (
    <div className={`w-64 bg-zinc-950 border-r border-zinc-800 flex flex-col h-full shrink-0 font-mono text-xs select-none ${className || ''}`}>
      <div className="p-4 border-b border-zinc-800">
        <div className="text-zinc-500 uppercase tracking-widest text-[10px] mb-2 font-bold">
          WORKSPACE_NAVIGATION
        </div>
      </div>
      <nav className="flex-1 overflow-y-auto py-2">
        <ul className="flex flex-col">
          {NAV_ITEMS.map((item) => {
            // Precise active matching
            const isActive = pathname === item.path || (pathname.startsWith(item.path) && item.path !== '/dashboard');
            
            return (
              <li key={item.name}>
                <Link
                  href={item.path}
                  className={`flex items-center gap-3 px-4 py-3 transition-colors duration-200 uppercase tracking-wider ${
                    isActive 
                      ? 'bg-blue-600/10 text-blue-500 border-r-2 border-blue-500 font-bold' 
                      : 'text-zinc-400 hover:bg-zinc-900 hover:text-zinc-200 border-r-2 border-transparent'
                  }`}
                >
                  <item.icon className="w-4 h-4" />
                  <span>{item.name}</span>
                </Link>
              </li>
            );
          })}
        </ul>
      </nav>
      <div className="p-4 border-t border-zinc-800 text-[10px] text-zinc-600 uppercase text-center tracking-widest">
        SEC_GATEWAY // v2.0.4
      </div>
    </div>
  );
}
