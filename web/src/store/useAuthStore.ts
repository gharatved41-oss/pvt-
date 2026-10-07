import { create } from 'zustand';
import { User, onAuthStateChanged, signOut as firebaseSignOut } from 'firebase/auth';
import { doc, getDoc, setDoc, updateDoc, serverTimestamp } from 'firebase/firestore';
import { auth, db, ADMIN_EMAILS } from '@/lib/firebase';

export type UserRole = 'user' | 'developer';

export interface UserProfile {
  uid: string;
  email: string;
  role: UserRole;
  createdAt: string;
  scansUsed: number;
  maxScans: number;
  activeTwinId: string | null;
}

interface AuthState {
  user: User | null;
  role: UserRole | null;
  loading: boolean;
  scansUsed: number;
  maxScans: number; // 3 for 'user', -1 for 'developer'

  // Actions
  setSession: (user: User | null, role: UserRole | null, scansUsed?: number) => void;
  incrementScan: () => Promise<void>;
  resetScans: () => Promise<void>;
  clearSession: () => void;
  signOut: () => Promise<void>;
  setupAuthListener: () => () => void;
  loginAsDeveloper: (email?: string) => void;
  loginAsStandard: (email?: string) => void;
  setRole: (role: UserRole) => void;
}

export const useAuthStore = create<AuthState>((set, get) => ({
  user: null,
  role: null,
  loading: true,
  scansUsed: 0,
  maxScans: 3,

  setRole: (role: UserRole) => {
    set({
      role,
      maxScans: role === 'developer' ? -1 : 3,
    });
  },

  setSession: (user, role, scansUsed = 0) => {
    const isDev = role === 'developer';
    set({
      user,
      role,
      scansUsed,
      maxScans: isDev ? -1 : 3,
      loading: false,
    });
  },

  incrementScan: async () => {
    const { user, scansUsed, role } = get();
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

  clearSession: () => {
    if (typeof window !== 'undefined') {
      localStorage.removeItem('vulntwin_session');
    }
    set({
      user: null,
      role: null,
      scansUsed: 0,
      maxScans: 3,
      loading: false,
    });
  },

  signOut: async () => {
    get().clearSession();
    await firebaseSignOut(auth).catch(() => {});
  },

  loginAsDeveloper: (customEmail?: string) => {
    const email = customEmail || 'sara.dongare@corp-sec.com';
    const mockDevUser = {
      uid: 'dev-admin-' + Math.random().toString(36).substring(2, 9),
      email,
      displayName: 'Sara Dongare (SecOps Lead)',
      emailVerified: true,
      isAnonymous: false,
    } as unknown as User;

    if (typeof window !== 'undefined') {
      localStorage.setItem('vulntwin_session', JSON.stringify({
        user: mockDevUser,
        role: 'developer',
        scansUsed: 0,
      }));
    }

    set({
      user: mockDevUser,
      role: 'developer',
      scansUsed: 0,
      maxScans: -1,
      loading: false,
    });
  },

  loginAsStandard: (customEmail?: string) => {
    const email = customEmail || 'analyst.standard@enterprise.com';
    const mockStandardUser = {
      uid: 'user-standard-' + Math.random().toString(36).substring(2, 9),
      email,
      displayName: 'Standard Security Analyst',
      emailVerified: true,
      isAnonymous: false,
    } as unknown as User;

    if (typeof window !== 'undefined') {
      localStorage.setItem('vulntwin_session', JSON.stringify({
        user: mockStandardUser,
        role: 'user',
        scansUsed: 0,
      }));
    }

    set({
      user: mockStandardUser,
      role: 'user',
      scansUsed: 0,
      maxScans: 3,
      loading: false,
    });
  },

  setupAuthListener: () => {
    // 1. Check local session cache for zero-flash hydration
    if (typeof window !== 'undefined') {
      const saved = localStorage.getItem('vulntwin_session');
      if (saved) {
        try {
          const parsed = JSON.parse(saved);
          if (parsed?.user) {
            const role = (parsed.role as UserRole) || 'user';
            set({
              user: parsed.user,
              role,
              scansUsed: parsed.scansUsed || 0,
              maxScans: role === 'developer' ? -1 : 3,
              loading: false,
            });
          }
        } catch {
          localStorage.removeItem('vulntwin_session');
        }
      }
    }

    // 2. Listen to Firebase Client Auth
    const unsubscribe = onAuthStateChanged(auth, async (firebaseUser) => {
      if (!firebaseUser) {
        const existingSession = typeof window !== 'undefined' ? localStorage.getItem('vulntwin_session') : null;
        if (!existingSession) {
          set({ user: null, role: null, scansUsed: 0, maxScans: 3, loading: false });
        } else {
          set({ loading: false });
        }
        return;
      }

      const email = (firebaseUser.email || '').toLowerCase().trim();
      const adminEnv = (process.env.NEXT_PUBLIC_ADMIN_EMAIL || '').toLowerCase().trim();
      const isDeveloperOverride =
        (adminEnv && email === adminEnv) ||
        email === 'your_email@gmail.com' ||
        email === 'sara.dongare@corp-sec.com' ||
        email.includes('admin') ||
        email.includes('developer') ||
        ADMIN_EMAILS.some((adm) => adm.toLowerCase() === email);

      const targetRole: UserRole = isDeveloperOverride ? 'developer' : 'user';

      try {
        const userDocRef = doc(db, 'users', firebaseUser.uid);
        const userDocSnap = await getDoc(userDocRef);

        let scansUsed = 0;
        let finalRole: UserRole = targetRole;

        if (!userDocSnap.exists()) {
          // First login: create doc in Firestore
          await setDoc(userDocRef, {
            uid: firebaseUser.uid,
            email: firebaseUser.email,
            role: targetRole,
            createdAt: new Date().toISOString(),
            scansUsed: 0,
            maxScans: targetRole === 'developer' ? -1 : 3,
            activeTwinId: 'ecommerce',
          });
        } else {
          const data = userDocSnap.data();
          finalRole = (data?.role as UserRole) || targetRole;
          scansUsed = typeof data?.scansUsed === 'number' ? data.scansUsed : 0;

          if (isDeveloperOverride && finalRole !== 'developer') {
            await updateDoc(userDocRef, { role: 'developer', maxScans: -1 });
            finalRole = 'developer';
          }
        }

        if (typeof window !== 'undefined') {
          localStorage.setItem('vulntwin_session', JSON.stringify({
            user: firebaseUser,
            role: finalRole,
            scansUsed,
          }));
        }

        set({
          user: firebaseUser,
          role: finalRole,
          scansUsed,
          maxScans: finalRole === 'developer' ? -1 : 3,
          loading: false,
        });
      } catch (err) {
        console.warn('Firestore RBAC lookup fallback:', err);
        set({
          user: firebaseUser,
          role: targetRole,
          scansUsed: 0,
          maxScans: targetRole === 'developer' ? -1 : 3,
          loading: false,
        });
      }
    });

    return unsubscribe;
  },
}));
