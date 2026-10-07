'use client';

import React, { createContext, useContext, useEffect, useState, ReactNode } from 'react';
import { 
  User, 
  onAuthStateChanged, 
  signInWithEmailAndPassword, 
  createUserWithEmailAndPassword, 
  signInWithPopup, 
  GoogleAuthProvider, 
  signOut as firebaseSignOut,
  UserCredential
} from 'firebase/auth';
import { 
  doc, 
  getDoc, 
  setDoc, 
  updateDoc, 
  increment, 
  serverTimestamp 
} from 'firebase/firestore';
import { auth, db, ADMIN_EMAILS } from '@/lib/firebase';

export type UserRole = 'developer' | 'user';

interface AuthContextType {
  user: User | null;
  role: UserRole;
  scansUsed: number;
  loading: boolean;
  signInWithEmail: (email: string, pass: string) => Promise<UserCredential>;
  signUpWithEmail: (email: string, pass: string) => Promise<UserCredential>;
  signInWithGoogle: () => Promise<UserCredential>;
  signOut: () => Promise<void>;
  logout: () => Promise<void>;
  demoLogin: (role?: UserRole) => void;
  incrementScanCount: () => Promise<number>;
  refreshUserData: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [role, setRole] = useState<UserRole>('user');
  const [scansUsed, setScansUsed] = useState<number>(0);
  const [loading, setLoading] = useState<boolean>(true);

  // Sync user profile and RBAC role with Firestore
  const syncUserWithFirestore = async (firebaseUser: User) => {
    try {
      const userRef = doc(db, 'users', firebaseUser.uid);
      const userSnap = await getDoc(userRef);

      const emailLower = (firebaseUser.email || '').trim().toLowerCase();
      const isAdminEmail = ADMIN_EMAILS.some(adminEmail => 
        adminEmail.toLowerCase() === emailLower || 
        emailLower.includes('developer') || 
        emailLower.includes('admin')
      );

      const targetRole: UserRole = isAdminEmail ? 'developer' : 'user';

      if (!userSnap.exists()) {
        // Document does not exist: Initialize in Firestore
        const newRecord = {
          email: firebaseUser.email || 'anonymous@vulntwin.ai',
          role: targetRole,
          createdAt: serverTimestamp(),
          scansUsed: 0,
          lastActiveAt: serverTimestamp(),
        };
        await setDoc(userRef, newRecord);
        setRole(targetRole);
        setScansUsed(0);
      } else {
        // Document exists: Ingest current role and scan quota
        const data = userSnap.data();
        // If user email qualifies for developer, ensure role is developer
        const assignedRole: UserRole = isAdminEmail ? 'developer' : (data.role || 'user');
        setRole(assignedRole);
        setScansUsed(data.scansUsed ?? 0);

        // Update lastActiveAt and role if promoted
        await updateDoc(userRef, {
          lastActiveAt: serverTimestamp(),
          ...(assignedRole !== data.role ? { role: assignedRole } : {})
        }).catch(() => {});
      }
    } catch (err) {
      console.warn('Firestore RBAC sync warning (using client fallback):', err);
      // Client fallback logic
      const emailLower = (firebaseUser.email || '').toLowerCase();
      const isDev = ADMIN_EMAILS.includes(emailLower) || emailLower.includes('admin') || emailLower.includes('developer');
      setRole(isDev ? 'developer' : 'user');
    }
  };

  useEffect(() => {
    // Check local demo evaluation state first
    const savedDemo = typeof window !== 'undefined' ? localStorage.getItem('vulntwin_active_user') : null;
    if (savedDemo) {
      try {
        const parsed = JSON.parse(savedDemo);
        setUser(parsed as unknown as User);
        setRole(parsed.role || 'user');
        setScansUsed(parsed.scansUsed || 0);
        setLoading(false);
      } catch {
        localStorage.removeItem('vulntwin_active_user');
      }
    }

    const unsubscribe = onAuthStateChanged(auth, async (firebaseUser) => {
      if (firebaseUser) {
        setUser(firebaseUser);
        await syncUserWithFirestore(firebaseUser);
        if (typeof window !== 'undefined') {
          localStorage.removeItem('vulntwin_active_user');
        }
      } else {
        const currentSavedDemo = typeof window !== 'undefined' ? localStorage.getItem('vulntwin_active_user') : null;
        if (!currentSavedDemo) {
          setUser(null);
          setRole('user');
          setScansUsed(0);
        }
      }
      setLoading(false);
    });

    return () => unsubscribe();
  }, []);

  const signInWithEmail = (email: string, pass: string) => {
    return signInWithEmailAndPassword(auth, email.trim(), pass);
  };

  const signUpWithEmail = (email: string, pass: string) => {
    return createUserWithEmailAndPassword(auth, email.trim(), pass);
  };

  const signInWithGoogle = () => {
    const provider = new GoogleAuthProvider();
    return signInWithPopup(auth, provider);
  };

  const signOut = async () => {
    if (typeof window !== 'undefined') {
      localStorage.removeItem('vulntwin_active_user');
    }
    await firebaseSignOut(auth).catch(() => {});
    setUser(null);
    setRole('user');
    setScansUsed(0);
  };

  const demoLogin = (selectedRole: UserRole = 'developer') => {
    const isDev = selectedRole === 'developer';
    const mockUser = {
      uid: 'demo-' + (isDev ? 'dev-' : 'user-') + Math.random().toString(36).substring(2, 9),
      email: isDev ? 'sara.dongare@corp-sec.com' : 'analyst.standard@enterprise.com',
      displayName: isDev ? 'Principal Security Engineer' : 'Standard SOC Analyst',
      role: selectedRole,
      scansUsed: 0,
      isAnonymous: false,
    };

    if (typeof window !== 'undefined') {
      localStorage.setItem('vulntwin_active_user', JSON.stringify(mockUser));
    }
    setUser(mockUser as unknown as User);
    setRole(selectedRole);
    setScansUsed(0);
  };

  const incrementScanCount = async (): Promise<number> => {
    const nextCount = scansUsed + 1;
    setScansUsed(nextCount);

    if (user?.uid && !user.uid.startsWith('demo-')) {
      try {
        const userRef = doc(db, 'users', user.uid);
        await updateDoc(userRef, {
          scansUsed: increment(1),
          lastScanAt: serverTimestamp(),
        });
      } catch (e) {
        console.warn('Could not increment scansUsed in Firestore:', e);
      }
    } else if (typeof window !== 'undefined') {
      // Update local storage demo user
      const saved = localStorage.getItem('vulntwin_active_user');
      if (saved) {
        try {
          const parsed = JSON.parse(saved);
          parsed.scansUsed = nextCount;
          localStorage.setItem('vulntwin_active_user', JSON.stringify(parsed));
        } catch {}
      }
    }
    return nextCount;
  };

  const refreshUserData = async () => {
    if (user && !user.uid.startsWith('demo-')) {
      await syncUserWithFirestore(user);
    }
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        role,
        scansUsed,
        loading,
        signInWithEmail,
        signUpWithEmail,
        signInWithGoogle,
        signOut,
        logout: signOut,
        demoLogin,
        incrementScanCount,
        refreshUserData,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextType {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
