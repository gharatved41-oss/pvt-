import React from 'react';
import TopNav from '@/components/layout/TopNav';
import { Sidebar } from '@/components/layout/sidebar';

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="h-screen w-full flex flex-col bg-zinc-950 overflow-hidden text-zinc-200">
      {/* Top section */}
      <TopNav />
      
      {/* Main workspace */}
      <div className="flex-1 flex overflow-hidden">
        {/* Left Sidebar */}
        <Sidebar />
        
        {/* Right Workspace (Main content area) */}
        <main className="flex-1 overflow-y-auto bg-zinc-950 relative">
          {children}
        </main>
      </div>
    </div>
  );
}
