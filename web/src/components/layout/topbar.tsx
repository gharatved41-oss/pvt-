'use client';

import React from 'react';
import { usePathname } from 'next/navigation';
import { 
  Menu, 
  User as UserIcon, 
  CreditCard, 
  LogOut, 
  ShieldAlert,
  SlidersHorizontal 
} from 'lucide-react';
import { useUserRole, signOut } from '@/lib/firebase';
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from '@/components/ui/breadcrumb';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { Avatar, AvatarFallback } from '@/components/ui/avatar';
import { Button } from '@/components/ui/button';
import { Sheet, SheetContent, SheetTrigger } from '@/components/ui/sheet';
import { Sidebar } from './sidebar';

interface BreadcrumbItemType {
  name: string;
  href?: string;
  isCurrent?: boolean;
}

// Dynamic breadcrumb path parser
function generateBreadcrumbs(pathname: string): BreadcrumbItemType[] {
  if (!pathname || pathname === '/' || pathname === '/dashboard') {
    return [
      { name: 'VulnTwin', href: '/dashboard' },
      { name: 'Environment Overview', isCurrent: true }
    ];
  }

  const segments = pathname.split('/').filter(Boolean);
  const breadcrumbs: BreadcrumbItemType[] = [{ name: 'VulnTwin', href: '/dashboard' }];

  let currentPath = '';
  segments.forEach((segment, index) => {
    currentPath += `/${segment}`;
    const isCurrent = index === segments.length - 1;
    const formatted = segment
      .replace(/-/g, ' ')
      .replace(/\b\w/g, (char) => char.toUpperCase());

    breadcrumbs.push({
      name: formatted,
      href: currentPath,
      isCurrent
    });
  });

  return breadcrumbs;
}

export function Topbar() {
  const pathname = usePathname();
  const { user, role, isDeveloper } = useUserRole();
  const breadcrumbs = generateBreadcrumbs(pathname);

  const handleLogout = async () => {
    try {
      await signOut();
      window.location.href = '/login';
    } catch (err) {
      console.error('Logout error:', err);
    }
  };

  const userInitial = user?.email ? user.email.charAt(0).toUpperCase() : 'U';

  return (
    <header className="sticky top-0 z-40 h-14 bg-zinc-950/95 backdrop-blur-none border-b border-zinc-800 px-4 sm:px-6 flex items-center justify-between select-none">
      
      {/* Left: Mobile Sheet Trigger + Dynamic Breadcrumbs */}
      <div className="flex items-center gap-3">
        {/* Mobile Sidebar Sheet */}
        <div className="md:hidden">
          <Sheet>
            <SheetTrigger asChild>
              <Button variant="ghost" size="icon" className="h-8 w-8 text-zinc-400 hover:text-zinc-100">
                <Menu className="w-4 h-4" />
                <span className="sr-only">Toggle navigation</span>
              </Button>
            </SheetTrigger>
            <SheetContent side="left" className="p-0 w-64 border-r border-zinc-800">
              <Sidebar className="w-full h-full border-r-0" />
            </SheetContent>
          </Sheet>
        </div>

        {/* Dynamic Breadcrumbs */}
        <nav aria-label="Breadcrumb" className="flex items-center space-x-1.5 text-xs font-mono">
          {breadcrumbs.map((crumb, idx) => (
            <React.Fragment key={crumb.name}>
              {idx > 0 && (
                <span className="text-zinc-600 text-[10px]">/</span>
              )}
              {crumb.isCurrent ? (
                <span className="text-zinc-100 font-semibold text-[11px] tracking-tight">
                  {crumb.name}
                </span>
              ) : (
                <a 
                  href={crumb.href || '/dashboard'} 
                  className="text-zinc-400 hover:text-zinc-200 transition-colors text-[11px]"
                >
                  {crumb.name}
                </a>
              )}
            </React.Fragment>
          ))}
        </nav>
      </div>

      {/* Right Side: Status Indicator & User Dropdown */}
      <div className="flex items-center gap-3 sm:gap-4">
        
        {/* Pulsing System Status Indicator */}
        <div className="hidden sm:flex items-center gap-2 px-2.5 py-1 rounded-sm border border-zinc-800 bg-zinc-900/60 text-[11px] font-mono text-zinc-300">
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
            <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500" />
          </span>
          <span className="tracking-tight text-zinc-300">System Status: <span className="text-emerald-400 font-medium">Online</span></span>
        </div>

        {/* User Dropdown Avatar */}
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" className="relative h-8 w-8 rounded-md p-0 focus-visible:ring-1 focus-visible:ring-zinc-400">
              <Avatar className="h-8 w-8 rounded-md border border-zinc-700">
                <AvatarFallback className="bg-zinc-900 text-zinc-100 font-mono text-xs">
                  {userInitial}
                </AvatarFallback>
              </Avatar>
            </Button>
          </DropdownMenuTrigger>

          <DropdownMenuContent className="w-56" align="end" forceMount>
            <DropdownMenuLabel className="font-normal p-2">
              <div className="flex flex-col space-y-1">
                <p className="text-xs font-medium text-zinc-100 truncate font-mono">
                  {user?.email || 'security.analyst@vulntwin.ai'}
                </p>
                <div className="flex items-center gap-1.5">
                  <span className="text-[10px] font-mono uppercase tracking-wider text-zinc-400">
                    Role: {role}
                  </span>
                  {isDeveloper && (
                    <span className="text-[9px] font-mono px-1 py-0 rounded bg-red-950 text-red-400 border border-red-800/50">
                      ADMIN
                    </span>
                  )}
                </div>
              </div>
            </DropdownMenuLabel>
            
            <DropdownMenuSeparator />

            <DropdownMenuItem className="text-xs text-zinc-300 focus:bg-zinc-900 focus:text-zinc-100">
              <UserIcon className="mr-2 h-3.5 w-3.5 text-zinc-400" />
              <span>Profile Settings</span>
            </DropdownMenuItem>

            <DropdownMenuItem className="text-xs text-zinc-300 focus:bg-zinc-900 focus:text-zinc-100">
              <CreditCard className="mr-2 h-3.5 w-3.5 text-zinc-400" />
              <span>Billing &amp; Usage Quota</span>
            </DropdownMenuItem>

            <DropdownMenuItem className="text-xs text-zinc-300 focus:bg-zinc-900 focus:text-zinc-100">
              <SlidersHorizontal className="mr-2 h-3.5 w-3.5 text-zinc-400" />
              <span>Environment Secrets</span>
            </DropdownMenuItem>

            <DropdownMenuSeparator />

            <DropdownMenuItem 
              onClick={handleLogout}
              className="text-xs text-red-400 focus:bg-red-950/60 focus:text-red-300 cursor-pointer"
            >
              <LogOut className="mr-2 h-3.5 w-3.5 text-red-400" />
              <span>Logout</span>
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>

      </div>

    </header>
  );
}
