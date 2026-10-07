'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import Image from 'next/image';
import { 
  LayoutDashboard, 
  Cpu, 
  Terminal, 
  Wrench, 
  Sparkles, 
  Settings, 
  BarChart3, 
  ShieldCheck, 
  Lock,
  ChevronRight,
  Zap
} from 'lucide-react';
import { useUserRole } from '@/lib/firebase';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter
} from '@/components/ui/dialog';
import { cn } from '@/lib/utils';

interface NavItem {
  name: string;
  href: string;
  icon: React.ElementType;
  badge?: string;
  isProOnly?: boolean;
  developerOnly?: boolean;
}

const NAV_ITEMS: NavItem[] = [
  { name: 'Overview', href: '/dashboard', icon: LayoutDashboard },
  { name: 'Twins', href: '/dashboard/twins', icon: Cpu },
  { name: 'Simulations', href: '/dashboard/simulations', icon: Terminal },
  { name: 'Remediation', href: '/dashboard/remediation', icon: Wrench },
  { name: 'Automated Patching', href: '/dashboard/patching', icon: Sparkles, badge: 'PRO', isProOnly: true },
  { name: 'Settings', href: '/dashboard/settings', icon: Settings },
  { name: 'Admin Analytics', href: '/dashboard/admin', icon: BarChart3, developerOnly: true },
];

export function Sidebar({ className }: { className?: string }) {
  const pathname = usePathname();
  const { role, isDeveloper, isPro, user, loading } = useUserRole();
  const [proModalOpen, setProModalOpen] = useState(false);

  const handleProClick = (e: React.MouseEvent, item: NavItem) => {
    if (item.isProOnly && !isPro && !isDeveloper) {
      e.preventDefault();
      setProModalOpen(true);
    }
  };

  // Quota calculation / presentation
  const getQuotaDisplay = () => {
    if (loading) {
      return { tierLabel: 'Authenticating...', scanInfo: 'Verifying clearance' };
    }
    if (isDeveloper) {
      return { tierLabel: 'DEVELOPER CLEARANCE', scanInfo: 'Unlimited Twin Simulations' };
    }
    if (isPro) {
      return { tierLabel: 'PRO TIER ACTIVE', scanInfo: '50 Simulations / Month' };
    }
    return { tierLabel: 'STANDARD TIER', scanInfo: '1 / 3 Scans Used Today' };
  };

  const quota = getQuotaDisplay();

  return (
    <>
      <aside 
        className={cn(
          "w-64 h-screen bg-zinc-950 border-r border-zinc-800 flex flex-col justify-between shrink-0 select-none",
          className
        )}
      >
        {/* 1. Header: Logo, Name & Tagline */}
        <div className="p-3.5 border-b border-zinc-800">
          <Link href="/dashboard" className="flex items-center gap-2.5 group">
            {/* Logo Emblem */}
            <div className="relative w-9 h-9 rounded-md overflow-hidden border border-zinc-700 bg-zinc-900 shrink-0">
              <Image 
                src="/vulntwin-logo.jpg" 
                alt="VulnTwin AI Logo" 
                width={36} 
                height={36} 
                className="w-full h-full object-cover"
                priority
              />
            </div>
            {/* Name & Tagline */}
            <div className="flex flex-col min-w-0">
              <div className="flex items-center gap-1.5">
                <span className="font-mono text-xs font-bold tracking-tight text-zinc-100 uppercase">
                  VulnTwin
                </span>
                <span className="font-mono text-xs font-bold text-zinc-400">
                  AI
                </span>
              </div>
              <span className="text-[10px] text-zinc-500 font-mono tracking-tight truncate">
                Detect • Validate • Remediate
              </span>
            </div>
          </Link>
        </div>

        {/* 2. Navigation Menu */}
        <nav className="flex-1 px-2.5 py-3 space-y-1 overflow-y-auto">
          <div className="px-2 pb-1.5 text-[10px] font-mono uppercase tracking-wider text-zinc-600 font-semibold">
            Platform Operations
          </div>

          {NAV_ITEMS.map((item) => {
            // RBAC Filtering: Developer-only navigation links
            if (item.developerOnly && !isDeveloper) {
              return null;
            }

            const isActive = pathname === item.href || (item.href !== '/dashboard' && pathname?.startsWith(item.href));

            return (
              <Link
                key={item.name}
                href={item.href}
                onClick={(e) => handleProClick(e, item)}
                className={cn(
                  "group flex items-center justify-between px-2.5 py-1.5 rounded-md text-xs font-medium transition-colors border border-transparent",
                  isActive
                    ? "bg-zinc-900 text-zinc-50 border-zinc-800/80 font-semibold"
                    : "text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900/60"
                )}
              >
                <div className="flex items-center gap-2.5 min-w-0">
                  <item.icon className={cn(
                    "w-4 h-4 shrink-0 transition-colors",
                    isActive ? "text-zinc-100" : "text-zinc-500 group-hover:text-zinc-300"
                  )} />
                  <span className="truncate">{item.name}</span>
                </div>

                {item.badge && (
                  <Badge 
                    variant="pro" 
                    className="ml-auto text-[9px] px-1 py-0 h-4 uppercase font-mono tracking-widest font-semibold"
                  >
                    {item.badge}
                  </Badge>
                )}
              </Link>
            );
          })}
        </nav>

        {/* 3. Footer: Tier Quota & Identity */}
        <div className="p-3 border-t border-zinc-800 bg-zinc-950/60 space-y-2.5">
          <div className="p-2.5 rounded-md border border-zinc-800 bg-zinc-900/50 space-y-1.5">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-mono font-semibold uppercase tracking-wider text-zinc-400">
                {quota.tierLabel}
              </span>
              {isDeveloper ? (
                <ShieldCheck className="w-3.5 h-3.5 text-emerald-500" />
              ) : isPro ? (
                <Zap className="w-3.5 h-3.5 text-blue-400" />
              ) : (
                <Lock className="w-3.5 h-3.5 text-zinc-500" />
              )}
            </div>
            
            <p className="text-[11px] font-mono text-zinc-300 leading-none">
              {quota.scanInfo}
            </p>

            {/* Quota bar for Standard Tier */}
            {!isDeveloper && !isPro && (
              <div className="w-full bg-zinc-800 h-1 rounded-sm overflow-hidden mt-1.5">
                <div className="bg-zinc-400 h-full w-1/3 rounded-sm" />
              </div>
            )}
          </div>

          <div className="text-[10px] font-mono text-zinc-600 text-center tracking-tight">
            VulnTwin AI • Enterprise Kernel v2.4
          </div>
        </div>
      </aside>

      {/* Upgrade to Pro Modal (shadcn Dialog) */}
      <Dialog open={proModalOpen} onOpenChange={setProModalOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <div className="flex items-center gap-2 mb-1">
              <Badge variant="pro" className="uppercase font-mono text-[10px]">
                Tier Restricted
              </Badge>
            </div>
            <DialogTitle className="text-base font-semibold font-mono">
              Upgrade to Pro Clearance
            </DialogTitle>
            <DialogDescription className="text-xs text-zinc-400">
              Automated Patching and Blast-Radius Forensics require active Pro or Developer clearance.
            </DialogDescription>
          </DialogHeader>

          <div className="py-3 space-y-2.5 text-xs text-zinc-300 border-y border-zinc-800">
            <div className="flex items-start gap-2">
              <ChevronRight className="w-3.5 h-3.5 text-blue-400 shrink-0 mt-0.5" />
              <span>Up to 50 automated digital twin attack simulations per month</span>
            </div>
            <div className="flex items-start gap-2">
              <ChevronRight className="w-3.5 h-3.5 text-blue-400 shrink-0 mt-0.5" />
              <span>Context-aware regression testing &amp; atomic code remediations</span>
            </div>
            <div className="flex items-start gap-2">
              <ChevronRight className="w-3.5 h-3.5 text-blue-400 shrink-0 mt-0.5" />
              <span>Comprehensive blast-radius forensics &amp; compliance reports</span>
            </div>
          </div>

          <DialogFooter className="flex-row gap-2 justify-end sm:justify-end">
            <Button 
              variant="outline" 
              size="sm" 
              onClick={() => setProModalOpen(false)}
            >
              Dismiss
            </Button>
            <Button 
              variant="default" 
              size="sm"
              onClick={() => {
                alert('Enterprise checkout gateway initialized for VulnTwin Pro.');
                setProModalOpen(false);
              }}
            >
              Request Upgrade
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
