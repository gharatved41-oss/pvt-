import * as admin from 'firebase-admin';

// Initialize Firebase Admin SDK once at root
if (!admin.apps.length) {
  admin.initializeApp();
}

export { setCustomUserRole, generateInviteLink } from './auth';
export { initiateScan } from './quotas';
export { initializeDigitalTwin, updateTwinState, executeTwinSimulation, executeAevRemediationLoop } from './twinLifecycle';
export * from './types';
export * from './models/graph';
export * from './utils/synthesizer';
export * from './engine/graphTraversal';
export * from './engine/validator';
export * from './engine/blastRadius';
export * from './engine/runner';
export * from './remediation/patchGenerator';
export * from './remediation/sandboxApplier';
export * from './remediation/retester';

