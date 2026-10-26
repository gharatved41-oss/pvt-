import React from 'react';
import { NavLink, Outlet, useNavigate } from 'react-router-dom';
import {
  LayoutDashboard, Server, ShieldAlert, Cpu, FlaskConical,
  Wrench, RotateCcw, FileText, ScrollText, Settings, ShieldCheck,
  LogOut, Activity, Lock
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';

export const AppLayout: React.FC = () => {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  const navItems = [
    { name: 'Dashboard', path: '/dashboard', icon: LayoutDashboard },
    { name: 'Assets', path: '/assets', icon: Server },
    { name: 'Assessments', path: '/assessments', icon: Activity },
    { name: 'Vulnerabilities', path: '/vulnerabilities', icon: ShieldAlert },
    { name: 'Digital Twins', path: '/twins', icon: Cpu },
    { name: 'Validation Lab', path: '/validation', icon: FlaskConical },
    { name: 'Remediation', path: '/remediation', icon: Wrench },
    { name: 'Retesting', path: '/retesting', icon: RotateCcw },
    { name: 'Reports', path: '/reports', icon: FileText },
    { name: 'Audit Logs', path: '/audit', icon: ScrollText },
    { name: 'Settings', path: '/settings', icon: Settings },
  ];

  return (
    <div className="flex h-screen bg-[#070b14] text-slate-100 overflow-hidden">
      {/* Sidebar */}
      <aside className="w-64 bg-[#0c1222] border-r border-slate-800 flex flex-col flex-shrink-0 z-20">
        {/* Brand */}
        <div className="h-16 flex items-center px-5 border-b border-slate-800 bg-[#090d19]">
          <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center mr-3 shadow-lg shadow-cyan-500/20">
            <ShieldCheck className="w-5 h-5 text-slate-950 font-bold" />
          </div>
          <div>
            <h1 className="font-bold text-base tracking-wider text-slate-100 flex items-center">
              VULN <span className="text-cyan-400 ml-1">TWIN</span>
            </h1>
            <p className="text-[10px] text-slate-400 uppercase tracking-widest font-mono">Cyber Twin Platform</p>
          </div>
        </div>

        {/* Navigation */}
        <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
          {navItems.map((item) => (
            <NavLink
              key={item.path}
              to={item.path}
              className={({ isActive }) =>
                `flex items-center px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-150 ${
                  isActive
                    ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 shadow-sm shadow-cyan-500/10'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60 border border-transparent'
                }`
              }
            >
              <item.icon className="w-4 h-4 mr-3 flex-shrink-0" />
              <span>{item.name}</span>
            </NavLink>
          ))}
        </nav>

        {/* User Card */}
        <div className="p-3 border-t border-slate-800 bg-[#090d19]/80">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2.5 min-w-0">
              <div className="w-8 h-8 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center text-cyan-400 text-xs font-bold">
                {user?.full_name ? user.full_name[0] : 'U'}
              </div>
              <div className="min-w-0 flex-1">
                <p className="text-xs font-semibold text-slate-200 truncate">{user?.full_name || 'Cyber Analyst'}</p>
                <p className="text-[10px] text-cyan-400 uppercase font-mono tracking-wider">{user?.role || 'Analyst'}</p>
              </div>
            </div>
            <button
              onClick={handleLogout}
              title="Sign Out"
              className="p-1.5 text-slate-400 hover:text-rose-400 hover:bg-slate-800 rounded transition-colors"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        </div>
      </aside>

      {/* Main Area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Top Navbar */}
        <header className="h-16 bg-[#090d19]/90 backdrop-blur border-b border-slate-800 flex items-center justify-between px-6 z-10">
          <div className="flex items-center space-x-3">
            <div className="inline-flex items-center px-2.5 py-1 rounded-full text-xs font-mono bg-emerald-950/60 border border-emerald-600/40 text-emerald-400">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse mr-2" />
              TWIN SANDBOX: ISOLATED LAB READY
            </div>
            <span className="text-xs text-slate-400 font-mono hidden md:inline">
              VLAN 1099 | Subnet 192.168.100.0/24
            </span>
          </div>

          <div className="flex items-center space-x-4">
            <div className="flex items-center text-xs text-slate-400 font-mono space-x-2">
              <Lock className="w-3.5 h-3.5 text-cyan-400" />
              <span>NON-DESTRUCTIVE TESTING POLICY ENFORCED</span>
            </div>
          </div>
        </header>

        {/* Page Content */}
        <main className="flex-1 overflow-y-auto p-6 bg-[#070b14]">
          <Outlet />
        </main>
      </div>
    </div>
  );
};
