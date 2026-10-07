import {
  GoogleAuthProvider,
  OAuthProvider,
  signInWithPopup,
  signInWithEmailAndPassword,
  createUserWithEmailAndPassword,
  sendEmailVerification,
  User,
  UserCredential,
} from 'firebase/auth';
import { doc, getDoc, setDoc, updateDoc } from 'firebase/firestore';
import { auth, db, ADMIN_EMAILS } from './firebase';
import { useAuthStore, UserRole } from '@/store/useAuthStore';

/**
 * RBAC Profile Synchronizer
 * 1. Checks if user email matches NEXT_PUBLIC_ADMIN_EMAIL or pre-configured developer accounts.
 * 2. Reads role from Firestore /users/{uid}.
 * 3. Developer accounts bypass email verification and scan quotas automatically.
 */
export async function syncUserProfile(user: User): Promise<UserRole> {
  const email = (user.email || '').toLowerCase().trim();
  const adminEmail = (process.env.NEXT_PUBLIC_ADMIN_EMAIL || '').toLowerCase().trim();

  const isDeveloperEmail =
    (adminEmail && email === adminEmail) ||
    email === 'your_email@gmail.com' ||
    email === 'sara.dongare@corp-sec.com' ||
    email.includes('admin') ||
    email.includes('developer') ||
    ADMIN_EMAILS.some((adm) => adm.toLowerCase() === email);

  let assignedRole: UserRole = isDeveloperEmail ? 'developer' : 'user';

  if (!db) {
    useAuthStore.getState().setSession(user, assignedRole);
    return assignedRole;
  }

  try {
    const userRef = doc(db, 'users', user.uid);
    const snap = await getDoc(userRef);

    if (!snap.exists()) {
      // First login / register: Create Firestore profile
      await setDoc(userRef, {
        email: user.email,
        role: assignedRole,
        scansUsed: 0,
        createdAt: new Date().toISOString(),
      });
    } else {
      const data = snap.data();
      // If Firestore document already has role === 'developer', preserve it
      if (data?.role === 'developer' || isDeveloperEmail) {
        assignedRole = 'developer';
        if (data?.role !== 'developer') {
          await updateDoc(userRef, { role: 'developer' });
        }
      } else {
        assignedRole = (data?.role as UserRole) || 'user';
      }
    }

    useAuthStore.getState().setSession(user, assignedRole);
    return assignedRole;
  } catch (err) {
    console.warn('Firestore profile sync warning:', err);
    useAuthStore.getState().setSession(user, assignedRole);
    return assignedRole;
  }
}

/**
 * 1. Google Sign-In
 */
export const signInWithGoogle = async (): Promise<UserCredential> => {
  const provider = new GoogleAuthProvider();
  provider.setCustomParameters({ prompt: 'select_account' });
  const cred = await signInWithPopup(auth, provider);
  await syncUserProfile(cred.user);
  return cred;
};

/**
 * 2. Apple Sign-In
 */
export const signInWithApple = async (): Promise<UserCredential> => {
  const provider = new OAuthProvider('apple.com');
  provider.addScope('email');
  provider.addScope('name');
  const cred = await signInWithPopup(auth, provider);
  await syncUserProfile(cred.user);
  return cred;
};

/**
 * 3. Email Registration & Verification Flow
 */
export const registerWithEmail = async (email: string, pass: string): Promise<UserCredential> => {
  const cleanEmail = email.trim().toLowerCase();
  const cred = await createUserWithEmailAndPassword(auth, cleanEmail, pass);

  // Immediately dispatch email confirmation link
  await sendEmailVerification(cred.user);

  // Create user document in Firestore under /users/{uid}
  if (db) {
    try {
      const userRef = doc(db, 'users', cred.user.uid);
      const adminEmail = (process.env.NEXT_PUBLIC_ADMIN_EMAIL || '').toLowerCase().trim();
      const isDev =
        (adminEmail && cleanEmail === adminEmail) ||
        cleanEmail === 'your_email@gmail.com' ||
        cleanEmail.includes('admin') ||
        cleanEmail.includes('developer');

      const initialRole: UserRole = isDev ? 'developer' : 'user';

      await setDoc(userRef, {
        email: cred.user.email,
        role: initialRole,
        scansUsed: 0,
        createdAt: new Date().toISOString(),
      });

      useAuthStore.getState().setSession(cred.user, initialRole);
    } catch (err) {
      console.warn('Firestore user doc creation error:', err);
    }
  }

  return cred;
};

/**
 * 4. Email Sign-In
 */
export const loginWithEmail = async (email: string, pass: string): Promise<UserCredential> => {
  const cred = await signInWithEmailAndPassword(auth, email.trim().toLowerCase(), pass);
  await syncUserProfile(cred.user);
  return cred;
};

/**
 * 5. Resend Verification Email
 */
export const resendVerificationEmail = async (user?: User | null): Promise<void> => {
  const currentUser = user || auth.currentUser;
  if (!currentUser) throw new Error('No active user session to dispatch verification email.');
  await sendEmailVerification(currentUser);
};

/**
 * 6. Reload User Session (to check updated emailVerified status)
 */
export const reloadUserSession = async (): Promise<boolean> => {
  if (!auth.currentUser) return false;
  await auth.currentUser.reload();
  const refreshedUser = auth.currentUser;
  const role = useAuthStore.getState().role;
  useAuthStore.getState().setSession(refreshedUser, role);
  return refreshedUser.emailVerified;
};
