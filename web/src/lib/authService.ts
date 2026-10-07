import {
  GoogleAuthProvider,
  signInWithPopup,
  signInWithEmailAndPassword,
  createUserWithEmailAndPassword,
  sendEmailVerification,
  signOut as firebaseSignOut,
  User,
  UserCredential,
} from 'firebase/auth';
import { doc, getDoc, setDoc, serverTimestamp } from 'firebase/firestore';
import { auth, db } from './firebase';

export type UserRole = 'user' | 'developer';

export interface UserProfileData {
  uid: string;
  email: string | null;
  role: UserRole;
  createdAt?: unknown;
  scansUsed?: number;
}

/**
 * Checks if a document exists in Firestore at `/users/{user.uid}`.
 * If not, creates it with role 'user' by default.
 * If user.email matches process.env.NEXT_PUBLIC_ADMIN_EMAIL, sets role to 'developer'.
 */
export async function syncUserProfile(user: User): Promise<UserRole> {
  const adminEmail = (process.env.NEXT_PUBLIC_ADMIN_EMAIL || '').toLowerCase().trim();
  const userEmail = (user.email || '').toLowerCase().trim();
  const isDeveloper = Boolean(adminEmail && userEmail === adminEmail);
  const targetRole: UserRole = isDeveloper ? 'developer' : 'user';

  const userDocRef = doc(db, 'users', user.uid);
  const docSnap = await getDoc(userDocRef);

  if (!docSnap.exists()) {
    await setDoc(userDocRef, {
      uid: user.uid,
      email: user.email,
      role: targetRole,
      createdAt: serverTimestamp(),
      scansUsed: 0,
    });
    return targetRole;
  }

  const existingData = docSnap.data();
  const existingRole = (existingData?.role as UserRole) || targetRole;
  return existingRole;
}

/**
 * Sign in using GoogleAuthProvider with forced account selection prompt.
 */
export async function loginWithGoogle(): Promise<UserCredential> {
  const provider = new GoogleAuthProvider();
  provider.setCustomParameters({ prompt: 'select_account' });
  const credential = await signInWithPopup(auth, provider);
  await syncUserProfile(credential.user);
  return credential;
}

/**
 * Sign in using Email and Password.
 */
export async function loginWithEmail(email: string, password: string): Promise<UserCredential> {
  const credential = await signInWithEmailAndPassword(auth, email.trim(), password);
  await syncUserProfile(credential.user);
  return credential;
}

/**
 * Register account with Email and Password, immediately dispatching email verification link.
 */
export async function registerWithEmail(email: string, password: string): Promise<UserCredential> {
  const credential = await createUserWithEmailAndPassword(auth, email.trim(), password);
  await sendEmailVerification(credential.user);
  await syncUserProfile(credential.user);
  return credential;
}

/**
 * Sign out current authenticated user.
 */
export async function logout(): Promise<void> {
  await firebaseSignOut(auth);
}
