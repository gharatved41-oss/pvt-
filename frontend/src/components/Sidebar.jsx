import React from 'react';
import { 
  LayoutDashboard, Search, AlertTriangle, Cpu, CheckCircle2, 
  Wrench, History, FileText, Settings, Users, LogIn, LogOut,
  Shield, Lock, ChevronRight, X, FileCheck
} from 'lucide-react';

export default function Sidebar({ 
  activeTab, 
  setActiveTab, 
  currentUser, 
  onOpenAuth, 
  onLogout,
  isMobileOpen,
  onCloseMobile
}) {
  const navItems = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { id: 'analyze', label: 'Analyze', icon: Search },
    { id: 'findings', label: 'Findings', icon: AlertTriangle },
    { id: 'forensics', label: 'File & OS Forensics', icon: FileCheck },
    { id: 'twin', label: 'Digital Twin', icon: Cpu },
    { id: 'validation', label: 'Validation', icon: CheckCircle2 },
    { id: 'remediation', label: 'Remediation', icon: Wrench },
    { id: 'history', label: 'Security Memory', icon: History },
    { id: 'reports', label: 'Reports', icon: FileText },
  ];

  const isDeveloper = currentUser?.role === 'developer';

  const handleNavClick = (tabId) => {
    setActiveTab(tabId);
    if (onCloseMobile) onCloseMobile();
  };

  const sidebarContent = (
    <div className="w-64 bg-[#0B1F44] text-white flex flex-col shrink-0 h-full border-r border-[#1E3A8A]/30 select-none">
      
      {/* 1. Header & Brand Logo */}
      <div className="p-4 border-b border-white/10 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg overflow-hidden border border-blue-400/30 shadow-md shrink-0 bg-slate-900">
            <img 
              src="/vulntwin-logo.jpg" 
              alt="VulnTwin AI Logo" 
              className="w-full h-full object-cover"
            />
          </div>
          <div>
            <h1 className="text-sm font-bold tracking-tight text-white leading-tight">
              VulnTwin <span className="text-[#60A5FA]">AI</span>
            </h1>
            <p className="text-[10px] text-blue-200/80 font-medium tracking-wide">
              Detect • Validate • Remediate
            </p>
          </div>
        </div>

        {/* Mobile close button */}
        {onCloseMobile && (
          <button
            type="button"
            onClick={onCloseMobile}
            className="md:hidden text-slate-400 hover:text-white p-1 rounded-md transition-colors"
            aria-label="Close navigation"
          >
            <X className="w-5 h-5" />
          </button>
        )}
      </div>

      {/* 2. Navigation Items */}
      <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
        <div className="px-3 pb-2 text-[11px] font-semibold tracking-wider text-blue-200/50 uppercase">
          Core Operations
        </div>

        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              type="button"
              onClick={() => handleNavClick(item.id)}
              className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-[#2563EB] ${
                isActive
                  ? 'bg-[#2563EB] text-white shadow-sm'
                  : 'text-slate-300 hover:bg-white/10 hover:text-white'
              }`}
            >
              <Icon className={`w-4 h-4 shrink-0 ${isActive ? 'text-white' : 'text-slate-400'}`} />
              <span className="truncate">{item.label}</span>
            </button>
          );
        })}

        <div className="pt-4 px-3 pb-2 text-[11px] font-semibold tracking-wider text-blue-200/50 uppercase">
          Administration
        </div>

        <button
          type="button"
          onClick={() => handleNavClick('team')}
          className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-[#2563EB] ${
            activeTab === 'team'
              ? 'bg-[#2563EB] text-white shadow-sm'
              : 'text-slate-300 hover:bg-white/10 hover:text-white'
          }`}
        >
          <Users className={`w-4 h-4 shrink-0 ${activeTab === 'team' ? 'text-white' : 'text-slate-400'}`} />
          <span>Project Team</span>
        </button>
      </nav>

      {/* 3. User Clearance / Profile Card */}
      <div className="p-3 border-t border-white/10 bg-[#071530]/80">
        {currentUser ? (
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 overflow-hidden">
                <div className={`w-7 h-7 rounded-full flex items-center justify-center text-xs font-bold shrink-0 ${
                  isDeveloper ? 'bg-emerald-600 text-white' : 'bg-[#2563EB] text-white'
                }`}>
                  {currentUser.name ? currentUser.name.charAt(0) : 'U'}
                </div>
                <div className="truncate">
                  <div className="text-xs font-semibold text-white truncate">
                    {currentUser.name || currentUser.username}
                  </div>
                  <div className="text-[10px] text-slate-300 truncate">
                    {currentUser.title || (isDeveloper ? 'Security Engineering' : 'Security Operations')}
                  </div>
                </div>
              </div>

              <button
                type="button"
                onClick={onLogout}
                title="Sign out"
                aria-label="Sign out"
                className="text-slate-400 hover:text-rose-400 p-1.5 rounded transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-rose-500"
              >
                <LogOut className="w-4 h-4" />
              </button>
            </div>
          </div>
        ) : (
          <button
            type="button"
            onClick={onOpenAuth}
            className="w-full py-2 px-3 bg-[#2563EB] hover:bg-blue-600 text-white rounded-lg text-xs font-semibold flex items-center justify-center gap-2 transition-colors shadow-sm focus:outline-none focus-visible:ring-2 focus-visible:ring-white"
          >
            <LogIn className="w-4 h-4" />
            <span>Sign In / Clearance</span>
          </button>
        )}
      </div>

    </div>
  );

  return (
    <>
      {/* Desktop Sidebar (hidden on mobile) */}
      <aside className="hidden md:flex flex-col h-screen shrink-0">
        {sidebarContent}
      </aside>

      {/* Mobile Drawer (visible when isMobileOpen is true) */}
      {isMobileOpen && (
        <div className="fixed inset-0 z-50 md:hidden flex">
          {/* Backdrop */}
          <div 
            onClick={onCloseMobile}
            className="fixed inset-0 bg-slate-900/60 backdrop-blur-xs transition-opacity"
          />

          {/* Slide-over panel */}
          <aside className="relative z-10 flex flex-col h-full shadow-2xl">
            {sidebarContent}
          </aside>
        </div>
      )}
    </>
  );
}
