import { initializeApp, getApps, getApp, FirebaseApp } from 'firebase/app';
import { getAuth, Auth, signOut as firebaseSignOut } from 'firebase/auth';
import { getFirestore, Firestore } from 'firebase/firestore';
import { getFunctions, Functions } from 'firebase/functions';
import { useAuthStore } from '@/store/useAuthStore';

const firebaseConfig = {
  apiKey: process.env.NEXT_PUBLIC_FIREBASE_API_KEY || "AIzaSyAOpVUNZCqR9JjqvnppYs5WqqwtxBPrwKk",
  authDomain: process.env.NEXT_PUBLIC_FIREBASE_AUTH_DOMAIN || "vulntwinai.firebaseapp.com",
  projectId: process.env.NEXT_PUBLIC_FIREBASE_PROJECT_ID || "vulntwinai",
  storageBucket: process.env.NEXT_PUBLIC_FIREBASE_STORAGE_BUCKET || "vulntwinai.firebasestorage.app",
  messagingSenderId: process.env.NEXT_PUBLIC_FIREBASE_MESSAGING_SENDER_ID || "1098180578471",
  appId: process.env.NEXT_PUBLIC_FIREBASE_APP_ID || "1:1098180578471:web:86545343fffab93990df82",
  measurementId: process.env.NEXT_PUBLIC_FIREBASE_MEASUREMENT_ID || "G-4TG4MCG6LK",
};

// Singleton App Initialization (SSR-safe)
export const app: FirebaseApp = getApps().length > 0 ? getApp() : initializeApp(firebaseConfig);
export const auth: Auth = getAuth(app);
export const db: Firestore = getFirestore(app);
export const functions: Functions = getFunctions(app);

// Developer Email Identifiers for Role-Based Overrides
export const ADMIN_EMAILS: string[] = [
  (process.env.NEXT_PUBLIC_ADMIN_EMAIL || '').toLowerCase().trim(),
  'your_email@gmail.com',
  'sara.dongare@corp-sec.com',
  'admin@vulntwin.ai',
  'developer@vulntwin.ai',
].filter(Boolean);

export const signOut = () => firebaseSignOut(auth);

/**
 * useUserRole hook for layout components
 */
export function useUserRole() {
  const { user, role, loading } = useAuthStore();
  const isDeveloper = role === 'developer';
  return {
    user,
    role: role || 'user',
    isDeveloper,
    isPro: isDeveloper,
    isUser: !isDeveloper,
    loading,
    refreshClaims: async () => {},
  };
}
