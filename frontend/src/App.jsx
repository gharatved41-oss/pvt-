import React, { useState, useEffect } from 'react';
import Sidebar from './components/Sidebar';
import TopNav from './components/TopNav';
import DashboardView from './components/DashboardView';
import AnalyzeView from './components/AnalyzeView';
import FindingsView from './components/FindingsView';
import DigitalTwinView from './components/DigitalTwinView';
import ValidationView from './components/ValidationView';
import RemediationView from './components/RemediationView';
import HistoryView from './components/HistoryView';
import ReportsView from './components/ReportsView';
import AboutUsView from './components/AboutUsView';
import FileForensicsView from './components/FileForensicsView';
import AuthModal from './components/AuthModal';
import LoginScreen from './components/LoginScreen';
import { API_BASE } from './config/api';

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [currentUser, setCurrentUser] = useState(null);
  const [isAuthOpen, setIsAuthOpen] = useState(false);
  const [activeAnalysis, setActiveAnalysis] = useState(null);
  const [quotaInfo, setQuotaInfo] = useState(null);

  // Load user from localStorage
  useEffect(() => {
    const saved = localStorage.getItem('vulntwin_user') || localStorage.getItem('sentinalx_user') || localStorage.getItem('autosectwin_user');
    if (saved) {
      try {
        setCurrentUser(JSON.parse(saved));
      } catch (e) {
        localStorage.removeItem('vulntwin_user');
        localStorage.removeItem('sentinalx_user');
        localStorage.removeItem('autosectwin_user');
      }
    }
  }, []);

  // Fetch quota info when user changes
  useEffect(() => {
    if (!currentUser) return;
    const fetchQuota = async () => {
      try {
        const headers = {
          'x-user-identifier': currentUser?.email || currentUser?.username || 'anonymous',
          'x-user-role': currentUser?.role || 'user'
        };
        const res = await fetch(`${API_BASE}/api/v1/user/quota`, { headers });
        if (res.ok) {
          const data = await res.json();
          setQuotaInfo(data);
        }
      } catch (err) {
        console.warn('Quota check error:', err);
      }
    };
    fetchQuota();
    window.addEventListener('vulntwin:api-base-changed', fetchQuota);
    return () => window.removeEventListener('vulntwin:api-base-changed', fetchQuota);
  }, [currentUser]);

  const handleLogin = (user) => {
    setCurrentUser(user);
    localStorage.setItem('vulntwin_user', JSON.stringify(user));
  };

  const handleLogout = () => {
    setCurrentUser(null);
    localStorage.removeItem('vulntwin_user');
    localStorage.removeItem('sentinalx_user');
    localStorage.removeItem('autosectwin_user');
  };

  const [isMobileNavOpen, setIsMobileNavOpen] = useState(false);

  // 1. GATED ACCESS: User must log in before accessing VulnTwin AI
  if (!currentUser) {
    return <LoginScreen onLogin={handleLogin} />;
  }

  return (
    <div className="flex h-screen bg-[#F8FAFC] text-[#334155] font-sans overflow-hidden">
      
      {/* 1. Deep Navy Sidebar */}
      <Sidebar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        currentUser={currentUser}
        onOpenAuth={() => setIsAuthOpen(true)}
        onLogout={handleLogout}
        isMobileOpen={isMobileNavOpen}
        onCloseMobile={() => setIsMobileNavOpen(false)}
      />

      {/* 2. Main Content Layout Area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        
        {/* Top Navigation Bar */}
        <TopNav
          activeTab={activeTab}
          currentUser={currentUser}
          onOpenAuth={() => setIsAuthOpen(true)}
          quotaInfo={quotaInfo}
          onToggleMobileMenu={() => setIsMobileNavOpen((prev) => !prev)}
        />

        {/* Scrollable Viewport */}
        <main className="flex-1 overflow-y-auto p-6 lg:p-8">
          
          {/* Dashboard Overview */}
          {activeTab === 'dashboard' && (
            <DashboardView
              onNavigateToAnalyze={() => setActiveTab('analyze')}
              onNavigateToTwin={(item) => {
                if (item) setActiveAnalysis(item);
                setActiveTab('twin');
              }}
            />
          )}

          {/* Analyze Scanner */}
          {activeTab === 'analyze' && (
            <AnalyzeView
              currentUser={currentUser}
              onOpenAuth={() => setIsAuthOpen(true)}
              onSelectAnalysis={(data) => setActiveAnalysis(data)}
              onNavigateToTwin={(data) => {
                setActiveAnalysis(data);
                setActiveTab('twin');
              }}
            />
          )}

          {/* Findings Inventory Table */}
          {activeTab === 'findings' && (
            <FindingsView
              activeAnalysis={activeAnalysis}
              onNavigateToTwin={(item) => {
                if (item) setActiveAnalysis(item);
                setActiveTab('twin');
              }}
            />
          )}

          {/* Digital Twin Workspace */}
          {activeTab === 'twin' && (
            <DigitalTwinView
              activeAnalysis={activeAnalysis}
              onBackToAnalyze={() => setActiveTab('analyze')}
            />
          )}

          {/* Controlled Security Validation */}
          {activeTab === 'validation' && (
            <ValidationView
              onNavigateToTwin={() => setActiveTab('twin')}
            />
          )}

          {/* Remediation & Before vs After Matrix */}
          {activeTab === 'remediation' && (
            <RemediationView
              activeAnalysis={activeAnalysis}
              onNavigateToTwin={() => setActiveTab('twin')}
            />
          )}

          {/* Security Memory Graph */}
          {activeTab === 'history' && (
            <HistoryView
              onSelectAnalysis={(record) => {
                setActiveAnalysis(record);
                setActiveTab('twin');
              }}
            />
          )}

          {/* Compliance & Executive Reports */}
          {activeTab === 'reports' && (
            <ReportsView />
          )}

          {/* File & OS Forensics */}
          {activeTab === 'forensics' && (
            <FileForensicsView
              onAnalyzeHash={(hash) => {
                setActiveTab('analyze');
              }}
            />
          )}

          {/* Team Squad Overview */}
          {activeTab === 'team' && (
            <AboutUsView
              onNavigateToAnalyze={() => setActiveTab('analyze')}
            />
          )}

        </main>
      </div>

      {/* Authentication & Clearance Modal */}
      <AuthModal
        isOpen={isAuthOpen}
        onClose={() => setIsAuthOpen(false)}
        onLogin={handleLogin}
        currentUser={currentUser}
      />

    </div>
  );
}
