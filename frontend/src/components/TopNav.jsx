import React, { useState, useEffect } from 'react';
import { Bell, Menu, Shield, Server } from 'lucide-react';
import BackendStatusModal from './BackendStatusModal';
import { API_BASE, checkBackendHealth } from '../config/api';

export default function TopNav({ activeTab, currentUser, onOpenAuth, onToggleMobileMenu }) {
  const [isBackendModalOpen, setIsBackendModalOpen] = useState(false);
  const [backendOnline, setBackendOnline] = useState(true);
  const [currentApi, setCurrentApi] = useState(API_BASE);

  useEffect(() => {
    let mounted = true;
    const verifyHealth = async () => {
      const res = await checkBackendHealth();
      if (mounted) {
        setBackendOnline(res.ok);
      }
    };
    verifyHealth();
    const interval = setInterval(verifyHealth, 20000);

    const onApiChange = (e) => {
      if (mounted) {
        setCurrentApi(e.detail.apiBase);
        verifyHealth();
      }
    };
    window.addEventListener('vulntwin:api-base-changed', onApiChange);

    return () => {
      mounted = false;
      clearInterval(interval);
      window.removeEventListener('vulntwin:api-base-changed', onApiChange);
    };
  }, []);

  const getTabTitle = (tab) => {
    switch (tab) {
      case 'dashboard': return 'Dashboard';
      case 'analyze': return 'Vulnerability Analysis';
      case 'findings': return 'Findings & Weaknesses';
      case 'forensics': return 'File & OS Forensics';
      case 'twin': return 'Digital Twin Workspace';
      case 'validation': return 'Security Validation';
      case 'remediation': return 'Remediation & Regression';
      case 'history': return 'Security Memory';
      case 'reports': return 'Compliance Reports';
      case 'team': return 'Engineering Squad';
      default: return 'Security Operations';
    }
  };

  const isDeveloper = currentUser?.role === 'developer';

  return (
    <header className="h-14 bg-white border-b border-[#E2E8F0] px-4 sm:px-6 flex items-center justify-between shrink-0">
      
      {/* Left: Mobile Toggle & Page Title */}
      <div className="flex items-center gap-3">
        <button
          type="button"
          onClick={onToggleMobileMenu}
          className="md:hidden p-1.5 rounded-lg text-slate-600 hover:text-slate-900 hover:bg-slate-100 transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-[#2563EB]"
          aria-label="Toggle navigation menu"
        >
          <Menu className="w-5 h-5" />
        </button>

        <h2 className="text-sm sm:text-base font-semibold text-[#0B1F44] tracking-tight">
          {getTabTitle(activeTab)}
        </h2>
      </div>

      {/* Right: Backend Gateway Badge, Notifications & User Profile */}
      <div className="flex items-center gap-3 sm:gap-4">
        
        {/* Backend Gateway Status Badge */}
        <button
          type="button"
          onClick={() => setIsBackendModalOpen(true)}
          className={`flex items-center gap-1.5 px-2.5 py-1 rounded border text-xs transition-colors font-mono ${
            backendOnline 
              ? 'border-emerald-200 bg-emerald-50/50 hover:bg-emerald-50 text-emerald-800' 
              : 'border-rose-200 bg-rose-50/50 hover:bg-rose-50 text-rose-800'
          }`}
          title={`Backend Gateway: ${currentApi} (Click to configure)`}
        >
          <span className={`w-2 h-2 rounded-full ${backendOnline ? 'bg-emerald-500' : 'bg-rose-500 animate-pulse'}`} />
          <span className="hidden md:inline font-sans font-medium text-slate-600">Gateway:</span>
          <span className="font-semibold">{backendOnline ? 'Online' : 'Offline'}</span>
        </button>
        
        {/* Subtle Notifications */}
        <button
          type="button"
          className="p-1.5 text-slate-400 hover:text-slate-600 rounded-lg hover:bg-slate-50 transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-[#2563EB]"
          title="Notifications"
          aria-label="View notifications"
        >
          <Bell className="w-4 h-4" />
        </button>

        {/* User Identity */}
        <div 
          onClick={onOpenAuth}
          className="flex items-center gap-2.5 pl-3 border-l border-slate-200 cursor-pointer"
          title="User Account"
        >
          <div className="w-7 h-7 rounded-full bg-[#0B1F44] text-white flex items-center justify-center text-xs font-semibold shrink-0">
            {currentUser?.name ? currentUser.name.charAt(0) : 'U'}
          </div>
          <div className="hidden sm:block text-left">
            <div className="text-xs font-semibold text-slate-800 leading-tight">
              {currentUser?.name || currentUser?.username || 'Security Analyst'}
            </div>
            <div className="text-[11px] text-slate-500 font-normal">
              {currentUser?.title || (isDeveloper ? 'Security Engineering' : 'Security Operations')}
            </div>
          </div>
        </div>

      </div>

      <BackendStatusModal
        isOpen={isBackendModalOpen}
        onClose={() => setIsBackendModalOpen(false)}
      />

    </header>
  );
}
