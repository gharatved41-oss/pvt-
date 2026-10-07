import { create } from 'zustand';
import { User, signOut as firebaseSignOut } from 'firebase/auth';
import { doc, updateDoc } from 'firebase/firestore';
import { auth, db } from '@/lib/firebase';

export type UserRole = 'developer' | 'user' | null;

interface AuthState {
  // Directive 1 State: user, role, isInitialized
  user: User | null;
  role: UserRole;
  isInitialized: boolean;

  // Ergonomic compatibility properties
  loading: boolean;
  scansUsed: number;
  maxScans: number;

  // Actions
  setAuthState: (user: User | null, role: UserRole) => void;
  setUser: (user: User | null) => void;
  setRole: (role: UserRole) => void;
  setInitialized: (initialized: boolean) => void;
  setSession: (user: User | null, role: UserRole, scansUsed?: number) => void;
  incrementScan: () => Promise<void>;
  resetScans: () => Promise<void>;
  signOut: () => Promise<void>;
  clearSession: () => void;
  loginAsDeveloper: (email?: string) => void;
  loginAsStandard: (email?: string) => void;
  setupAuthListener: () => () => void;
}

export const useAuthStore = create<AuthState>((set, get) => ({
  user: null,
  role: null,
  isInitialized: false,
  loading: true,
  scansUsed: 0,
  maxScans: 3,

  setAuthState: (user: User | null, role: UserRole) => {
    set({
      user,
      role,
      isInitialized: true,
      loading: false,
      maxScans: role === 'developer' ? -1 : 3,
    });
  },

  setUser: (user: User | null) => set({ user }),

  setRole: (role: UserRole) => {
    set({
      role,
      maxScans: role === 'developer' ? -1 : 3,
    });
  },

  setInitialized: (isInitialized: boolean) => {
    set({ isInitialized, loading: !isInitialized });
  },

  setSession: (user: User | null, role: UserRole, scansUsed = 0) => {
    set({
      user,
      role,
      scansUsed,
      maxScans: role === 'developer' ? -1 : 3,
      isInitialized: true,
      loading: false,
    });
  },

  incrementScan: async () => {
    const { user, scansUsed } = get();
    const newCount = scansUsed + 1;
    set({ scansUsed: newCount });

    if (user && db) {
      try {
        const userRef = doc(db, 'users', user.uid);
        await updateDoc(userRef, { scansUsed: newCount });
      } catch (err) {
        console.warn('Could not sync scan count with Firestore:', err);
      }
    }
  },

  resetScans: async () => {
    const { user } = get();
    set({ scansUsed: 0 });
    if (user && db) {
      try {
        const userRef = doc(db, 'users', user.uid);
        await updateDoc(userRef, { scansUsed: 0 });
      } catch (err) {
        console.warn('Could not reset scans in Firestore:', err);
      }
    }
  },

  signOut: async () => {
    set({
      user: null,
      role: null,
      scansUsed: 0,
      maxScans: 3,
      isInitialized: true,
      loading: false,
    });
    if (typeof window !== 'undefined') {
      localStorage.removeItem('vulntwin_session');
    }
    await firebaseSignOut(auth).catch(() => {});
  },

  clearSession: () => {
    set({
      user: null,
      role: null,
      scansUsed: 0,
      maxScans: 3,
      isInitialized: true,
      loading: false,
    });
    if (typeof window !== 'undefined') {
      localStorage.removeItem('vulntwin_session');
    }
  },

  loginAsDeveloper: (customEmail?: string) => {
    const email = customEmail || 'sara.dongare@corp-sec.com';
    const mockDevUser = {
      uid: 'dev-admin-override',
      email,
      displayName: 'Sara Dongare (SecOps Lead)',
      emailVerified: true,
      isAnonymous: false,
    } as unknown as User;

    set({
      user: mockDevUser,
      role: 'developer',
      scansUsed: 0,
      maxScans: -1,
      isInitialized: true,
      loading: false,
    });
  },

  loginAsStandard: (customEmail?: string) => {
    const email = customEmail || 'analyst.standard@enterprise.com';
    const mockStandardUser = {
      uid: 'user-standard-override',
      email,
      displayName: 'Standard Security Analyst',
      emailVerified: true,
      isAnonymous: false,
    } as unknown as User;

    set({
      user: mockStandardUser,
      role: 'user',
      scansUsed: 0,
      maxScans: 3,
      isInitialized: true,
      loading: false,
    });
  },

  setupAuthListener: () => {
    // AuthProvider handles global onAuthStateChanged
    return () => {};
  },
}));
