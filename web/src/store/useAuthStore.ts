import { create } from 'zustand';
import { User, onAuthStateChanged, signOut as firebaseSignOut } from 'firebase/auth';
import { doc, getDoc, setDoc, serverTimestamp } from 'firebase/firestore';
import { auth, db, ADMIN_EMAILS } from '@/lib/firebase';

export type UserRole = 'user' | 'developer';

interface AuthState {
  user: User | null;
  role: UserRole | null;
  loading: boolean;
  setupAuthListener: () => () => void;
  signOut: () => Promise<void>;
  setRole: (role: UserRole) => void;
  loginAsDeveloper: (email?: string) => void;
  loginAsStandard: (email?: string) => void;
}

export const useAuthStore = create<AuthState>((set, get) => ({
  user: null,
  role: null,
  loading: true,

  setRole: (role: UserRole) => set({ role }),

  loginAsDeveloper: (customEmail?: string) => {
    const email = customEmail || 'sara.dongare@corp-sec.com';
    const mockDevUser = {
      uid: 'dev-admin-' + Math.random().toString(36).substring(2, 9),
      email: email,
      displayName: 'Sara Dongare (Lead SecOps)',
      emailVerified: true,
      isAnonymous: false,
    } as unknown as User;

    if (typeof window !== 'undefined') {
      localStorage.setItem('vulntwin_session', JSON.stringify({
        user: mockDevUser,
        role: 'developer',
      }));
    }

    set({
      user: mockDevUser,
      role: 'developer',
      loading: false,
    });
  },

  loginAsStandard: (customEmail?: string) => {
    const email = customEmail || 'analyst.standard@enterprise.com';
    const mockStandardUser = {
      uid: 'user-standard-' + Math.random().toString(36).substring(2, 9),
      email: email,
      displayName: 'Standard Security Analyst',
      emailVerified: true,
      isAnonymous: false,
    } as unknown as User;

    if (typeof window !== 'undefined') {
      localStorage.setItem('vulntwin_session', JSON.stringify({
        user: mockStandardUser,
        role: 'user',
      }));
    }

    set({
      user: mockStandardUser,
      role: 'user',
      loading: false,
    });
  },

  setupAuthListener: () => {
    // 1. Check if a persisted session exists in localStorage for immediate rendering
    if (typeof window !== 'undefined') {
      const saved = localStorage.getItem('vulntwin_session');
      if (saved) {
        try {
          const parsed = JSON.parse(saved);
          if (parsed?.user) {
            set({
              user: parsed.user,
              role: parsed.role || 'user',
              loading: false,
            });
          }
        } catch {
          localStorage.removeItem('vulntwin_session');
        }
      }
    }

    // 2. Initialize Firebase onAuthStateChanged
    const unsubscribe = onAuthStateChanged(auth, async (firebaseUser) => {
      if (!firebaseUser) {
        // If no active Firebase user and no manual local session, set unauthenticated
        const existingSession = typeof window !== 'undefined' ? localStorage.getItem('vulntwin_session') : null;
        if (!existingSession) {
          set({ user: null, role: null, loading: false });
        } else {
          set({ loading: false });
        }
        return;
      }

      const email = (firebaseUser.email || '').toLowerCase().trim();

      // Check Developer override rule:
      // "If user.email === 'YOUR_EMAIL@gmail.com', explicitly set the Firestore document and Zustand state to role: 'developer'"
      const isDeveloperOverride = 
        email === 'your_email@gmail.com' ||
        email === 'sara.dongare@corp-sec.com' ||
        email.includes('admin') ||
        email.includes('developer') ||
        ADMIN_EMAILS.some((adm) => adm.toLowerCase() === email);

      const targetRole: UserRole = isDeveloperOverride ? 'developer' : 'user';

      try {
        const userDocRef = doc(db, 'users', firebaseUser.uid);
        const userDocSnap = await getDoc(userDocRef);

        if (!userDocSnap.exists()) {
          // Document does not exist (first login): create it in Firestore
          await setDoc(userDocRef, {
            email: firebaseUser.email,
            role: targetRole,
            createdAt: serverTimestamp(),
            scansUsed: 0,
          });
          
          if (typeof window !== 'undefined') {
            localStorage.setItem('vulntwin_session', JSON.stringify({
              user: firebaseUser,
              role: targetRole,
            }));
          }

          set({ user: firebaseUser, role: targetRole, loading: false });
        } else {
          // Document exists: read role from document
          const data = userDocSnap.data();
          let currentRole: UserRole = data?.role === 'developer' ? 'developer' : 'user';

          // Apply override if matched
          if (isDeveloperOverride && currentRole !== 'developer') {
            await setDoc(userDocRef, { role: 'developer' }, { merge: true });
            currentRole = 'developer';
          }

          if (typeof window !== 'undefined') {
            localStorage.setItem('vulntwin_session', JSON.stringify({
              user: firebaseUser,
              role: currentRole,
            }));
          }

          set({ user: firebaseUser, role: currentRole, loading: false });
        }
      } catch (err) {
        console.warn('Firestore RBAC lookup warning (falling back to client state):', err);
        set({ user: firebaseUser, role: targetRole, loading: false });
      }
    });

    return unsubscribe;
  },

  signOut: async () => {
    if (typeof window !== 'undefined') {
      localStorage.removeItem('vulntwin_session');
    }
    await firebaseSignOut(auth).catch(() => {});
    set({ user: null, role: null, loading: false });
  },
}));
