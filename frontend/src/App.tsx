import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext';
import { AppLayout } from './components/AppLayout';

import { LandingPage } from './pages/LandingPage';
import { LoginPage } from './pages/LoginPage';
import { RegisterPage } from './pages/RegisterPage';
import { DashboardPage } from './pages/DashboardPage';
import { AssetsPage } from './pages/AssetsPage';
import { AssessmentsPage } from './pages/AssessmentsPage';
import { VulnerabilitiesPage } from './pages/VulnerabilitiesPage';
import { DigitalTwinsPage } from './pages/DigitalTwinsPage';
import { ValidationLabPage } from './pages/ValidationLabPage';
import { RemediationPage } from './pages/RemediationPage';
import { RetestingPage } from './pages/RetestingPage';
import { ReportsPage } from './pages/ReportsPage';
import { AuditLogsPage } from './pages/AuditLogsPage';
import { SettingsPage } from './pages/SettingsPage';

// Protected Route Guard
const ProtectedRoute: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { user, loading } = useAuth();
  if (loading) {
    return (
      <div className="h-screen bg-[#070b14] flex items-center justify-center text-cyan-400 font-mono text-sm">
        Authenticating session security credentials...
      </div>
    );
  }
  // If not logged in, redirect to login
  if (!user && !localStorage.getItem('vuln_twin_token')) {
    return <Navigate to="/login" replace />;
  }
  return <>{children}</>;
};

export function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          {/* Public Routes */}
          <Route path="/" element={<LandingPage />} />
          <Route path="/login" element={<LoginPage />} />
          <Route path="/register" element={<RegisterPage />} />

          {/* Protected Application Routes */}
          <Route
            path="/"
            element={
              <ProtectedRoute>
                <AppLayout />
              </ProtectedRoute>
            }
          >
            <Route path="dashboard" element={<DashboardPage />} />
            <Route path="assets" element={<AssetsPage />} />
            <Route path="assessments" element={<AssessmentsPage />} />
            <Route path="vulnerabilities" element={<VulnerabilitiesPage />} />
            <Route path="twins" element={<DigitalTwinsPage />} />
            <Route path="validation" element={<ValidationLabPage />} />
            <Route path="remediation" element={<RemediationPage />} />
            <Route path="retesting" element={<RetestingPage />} />
            <Route path="reports" element={<ReportsPage />} />
            <Route path="audit" element={<AuditLogsPage />} />
            <Route path="settings" element={<SettingsPage />} />
          </Route>

          {/* Catch-all */}
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
}

export default App;
