'use client';

import { collection, addDoc, serverTimestamp } from 'firebase/firestore';
import { db } from './firebase';

export interface SimulationRecord {
  templateId: string;
  templateName: string;
  compromisedCount: number;
  totalAssets: number;
  patchApplied: boolean;
  eventLogsCount: number;
  criticalCve: string;
}

/**
 * Saves completed simulation telemetry to Firestore under users/{uid}/simulations.
 * Includes safe local-storage fallback for demo sessions or offline evaluation.
 */
export async function saveSimulationRecord(uid: string, record: SimulationRecord) {
  if (!uid) return;

  // If running in demo mode or local evaluation, record locally
  if (uid.startsWith('demo-')) {
    try {
      const existing = JSON.parse(localStorage.getItem('vulntwin_local_simulations') || '[]');
      existing.unshift({
        ...record,
        id: 'demo-' + Date.now(),
        createdAt: new Date().toISOString(),
      });
      localStorage.setItem('vulntwin_local_simulations', JSON.stringify(existing.slice(0, 20)));
    } catch {
      // Ignore local storage error
    }
    return;
  }

  try {
    const colRef = collection(db, 'users', uid, 'simulations');
    await addDoc(colRef, {
      ...record,
      createdAt: serverTimestamp(),
      platform: 'VulnTwin AI CTEM Client Engine',
    });
  } catch (err) {
    console.warn('Firestore client write warning (recorded to client audit log):', err);
    try {
      const existing = JSON.parse(localStorage.getItem('vulntwin_local_simulations') || '[]');
      existing.unshift({
        ...record,
        id: 'cached-' + Date.now(),
        createdAt: new Date().toISOString(),
      });
      localStorage.setItem('vulntwin_local_simulations', JSON.stringify(existing.slice(0, 20)));
    } catch {
      // Ignore
    }
  }
}
