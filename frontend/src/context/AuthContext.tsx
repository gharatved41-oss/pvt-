import React, { createContext, useContext, useState, useEffect } from 'react';
import { User } from '../types';
import { api } from '../services/api';

interface AuthContextType {
  user: User | null;
  token: string | null;
  loading: boolean;
  login: (token: string, user: User) => void;
  logout: () => void;
  isAdmin: boolean;
  isAnalyst: boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(localStorage.getItem('vuln_twin_token'));
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const initializeAuth = async () => {
      const storedToken = localStorage.getItem('vuln_twin_token');
      const storedUser = localStorage.getItem('vuln_twin_user');

      if (storedToken && storedUser) {
        try {
          setUser(JSON.parse(storedUser));
          setToken(storedToken);
          // Verify with backend
          const freshUser = await api.getCurrentUser();
          setUser(freshUser);
        } catch (e) {
          console.error('Session expired or invalid:', e);
          api.logout();
          setUser(null);
          setToken(null);
        }
      } else {
        // Fallback to initial demo admin login if no session present
        try {
          const freshUser = await api.getCurrentUser();
          setUser(freshUser);
        } catch {
          setUser(null);
        }
      }
      setLoading(false);
    };

    initializeAuth();
  }, []);

  const login = (newToken: string, newUser: User) => {
    setToken(newToken);
    setUser(newUser);
    localStorage.setItem('vuln_twin_token', newToken);
    localStorage.setItem('vuln_twin_user', JSON.stringify(newUser));
  };

  const logout = () => {
    api.logout();
    setToken(null);
    setUser(null);
  };

  const isAdmin = user?.role === 'admin';
  const isAnalyst = user?.role === 'analyst' || user?.role === 'admin';

  return (
    <AuthContext.Provider value={{ user, token, loading, login, logout, isAdmin, isAnalyst }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
