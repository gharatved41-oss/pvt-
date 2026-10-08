import {
  GoogleAuthProvider,
  OAuthProvider,
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

export type UserRole = 'developer' | 'user';

/**
 * syncUserRole(user): Query Firestore `/users/{user.uid}`.
 * If user.email matches process.env.NEXT_PUBLIC_ADMIN_EMAIL, sets role to 'developer'.
 * Otherwise defaults to 'user'. Persists new profiles to Firestore.
 */
export async function syncUserRole(user: User): Promise<UserRole> {
  const adminEmail = (process.env.NEXT_PUBLIC_ADMIN_EMAIL || '').toLowerCase().trim();
  const userEmail = (user.email || '').toLowerCase().trim();
  const isDeveloper = Boolean(adminEmail && userEmail === adminEmail);
  const targetRole: UserRole = isDeveloper ? 'developer' : 'user';

  if (!db) {
    return targetRole;
  }

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
  if (isDeveloper && existingData?.role !== 'developer') {
    await setDoc(userDocRef, { role: 'developer' }, { merge: true });
    return 'developer';
  }

  const existingRole = (existingData?.role as UserRole) || targetRole;
  return existingRole;
}

/**
 * Backward compatibility alias for syncUserRole
 */
export const syncUserProfile = syncUserRole;

/**
 * signInWithGoogle: Use signInWithPopup with provider.setCustomParameters({ prompt: 'select_account' }).
 * MUST throw real errors. NO dummy user fallbacks.
 */
export async function signInWithGoogle(): Promise<UserCredential> {
  const provider = new GoogleAuthProvider();
  provider.setCustomParameters({ prompt: 'select_account' });
  const credential = await signInWithPopup(auth, provider);
  await syncUserRole(credential.user);
  return credential;
}

/**
 * Backward compatibility alias
 */
export const loginWithGoogle = signInWithGoogle;

/**
 * signInWithApple: Use OAuthProvider('apple.com') with email and name scopes.
 * MUST throw real errors. NO dummy user fallbacks.
 */
export async function signInWithApple(): Promise<UserCredential> {
  const provider = new OAuthProvider('apple.com');
  provider.addScope('email');
  provider.addScope('name');
  const credential = await signInWithPopup(auth, provider);
  await syncUserRole(credential.user);
  return credential;
}

/**
 * Backward compatibility alias
 */
export const loginWithApple = signInWithApple;

/**
 * signInWithEmail / loginWithEmail: Real email/password sign-in with syncUserRole.
 */
export async function loginWithEmail(email: string, password: string): Promise<UserCredential> {
  const cleanEmail = email.trim().toLowerCase();
  const credential = await signInWithEmailAndPassword(auth, cleanEmail, password);
  await syncUserRole(credential.user);
  return credential;
}

/**
 * registerWithEmail: Real user registration, immediate verification dispatch, and syncUserRole.
 */
export async function registerWithEmail(email: string, password: string): Promise<UserCredential> {
  const cleanEmail = email.trim().toLowerCase();
  const credential = await createUserWithEmailAndPassword(auth, cleanEmail, password);
  await sendEmailVerification(credential.user);
  await syncUserRole(credential.user);
  return credential;
}

/**
 * logout: Real Firebase sign out.
 */
export async function logout(): Promise<void> {
  await firebaseSignOut(auth);
}

export async function authenticateDeveloper(username: string, passcode: string): Promise<UserCredential> {
  const validPasscodes = (process.env.NEXT_PUBLIC_DEV_PASSCODES || '').split(',').map(p => p.trim());
  if (!validPasscodes.includes(passcode)) {
    throw new Error('[ERROR] INVALID_CLEARANCE_CODE');
  }

  const email = `${username.trim().toLowerCase()}@vulntwin.internal`;
  let credential: UserCredential;

  try {
    credential = await signInWithEmailAndPassword(auth, email, passcode);
  } catch (err: any) {
    if (err.code === 'auth/user-not-found' || err.code === 'auth/invalid-credential' || err.code === 'auth/invalid-login-credentials') {
      try {
        credential = await createUserWithEmailAndPassword(auth, email, passcode);
      } catch (createErr) {
        throw createErr;
      }
    } else {
      throw err;
    }
  }

  if (db) {
    const userDocRef = doc(db, 'users', credential.user.uid);
    await setDoc(userDocRef, {
      uid: credential.user.uid,
      email: credential.user.email,
      role: 'developer',
      quota: 'unlimited',
      createdAt: serverTimestamp(),
      username: username.trim(),
    }, { merge: true });
  }

  return credential;
}
