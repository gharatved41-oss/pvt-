import { onCall, HttpsError, CallableRequest } from 'firebase-functions/v2/https';
import * as admin from 'firebase-admin';
import { 
  UserRole, 
  InitiateScanRequest, 
  InitiateScanResponse, 
  UserDocument, 
  EnvironmentDocument, 
  SimulationDocument 
} from './types';

const db = admin.firestore();

/**
 * Checks if a given timestamp falls on a previous UTC day or previous UTC month,
 * returning whether counters should be reset.
 */
function evaluateResetCycles(lastResetDate: Date, now: Date): { resetDay: boolean; resetMonth: boolean } {
  const isDifferentDay = (
    lastResetDate.getUTCFullYear() !== now.getUTCFullYear() ||
    lastResetDate.getUTCMonth() !== now.getUTCMonth() ||
    lastResetDate.getUTCDate() !== now.getUTCDate()
  );

  const isDifferentMonth = (
    lastResetDate.getUTCFullYear() !== now.getUTCFullYear() ||
    lastResetDate.getUTCMonth() !== now.getUTCMonth()
  );

  return { resetDay: isDifferentDay, resetMonth: isDifferentMonth };
}

/**
 * 3. initiateScan
 * Callable Cloud Function with strict tier quota enforcement and atomic Firestore transactions.
 * - developer: Unlimited scans
 * - pro: Up to 50 simulations / month
 * - user: Up to 3 scans / day
 */
export const initiateScan = onCall<InitiateScanRequest>(
  async (request: CallableRequest<InitiateScanRequest>): Promise<InitiateScanResponse> => {
    // 1. Authenticate caller
    if (!request.auth) {
      throw new HttpsError(
        'unauthenticated', 
        'Authentication required to initiate security simulations.'
      );
    }

    const { uid } = request.auth;
    const role: UserRole = (request.auth.token.role as UserRole) || 'user';
    const { envId } = request.data;

    if (!envId || typeof envId !== 'string') {
      throw new HttpsError('invalid-argument', 'Valid envId parameter is required.');
    }

    const envRef = db.collection('environments').doc(envId);
    const userRef = db.collection('users').doc(uid);
    const simulationsCol = db.collection('simulations');

    const simulationRef = simulationsCol.doc();
    const nowTimestamp = admin.firestore.Timestamp.now();
    const nowDate = nowTimestamp.toDate();

    let updatedDayCount = 0;
    let updatedMonthCount = 0;

    const userEmail = request.auth.token.email || '';

    // 2. Execute Atomic Firestore Transaction
    await db.runTransaction(async (transaction) => {
      // 2.1 Verify Environment
      const envDoc = await transaction.get(envRef);
      if (!envDoc.exists) {
        throw new HttpsError('not-found', `Target environment '${envId}' does not exist.`);
      }

      const envData = envDoc.data() as EnvironmentDocument;

      // Ownership enforcement: non-developers can only trigger scans on their own environments
      if (role !== 'developer' && envData.ownerId !== uid) {
        throw new HttpsError(
          'permission-denied', 
          'Tenant Isolation Violation: You are not authorized to scan this environment.'
        );
      }

      // 2.2 Verify & Enforce Quotas for Non-Developers
      if (role !== 'developer') {
        const userDoc = await transaction.get(userRef);
        
        let currentDayCount = 0;
        let currentMonthCount = 0;
        let lastResetDate = nowDate;

        if (userDoc.exists) {
          const userData = userDoc.data() as UserDocument;
          const usage = userData.scanUsage || {
            currentDayCount: 0,
            currentMonthCount: 0,
            lastResetDate: nowTimestamp
          };

          lastResetDate = usage.lastResetDate ? usage.lastResetDate.toDate() : nowDate;
          const { resetDay, resetMonth } = evaluateResetCycles(lastResetDate, nowDate);

          currentDayCount = resetDay ? 0 : (usage.currentDayCount || 0);
          currentMonthCount = resetMonth ? 0 : (usage.currentMonthCount || 0);
        } else {
          // Provision missing user document
          const initialUser: UserDocument = {
            email: userEmail,
            role,
            scanUsage: {
              currentDayCount: 0,
              currentMonthCount: 0,
              lastResetDate: nowTimestamp
            },
            createdAt: nowTimestamp
          };
          transaction.set(userRef, initialUser);
        }

        // Tier limit evaluation
        if (role === 'user') {
          const DAILY_LIMIT = 3;
          if (currentDayCount >= DAILY_LIMIT) {
            throw new HttpsError(
              'resource-exhausted',
              `Daily scan quota exhausted (${currentDayCount}/${DAILY_LIMIT} used today). Upgrade to Pro or wait until 00:00 UTC for reset.`
            );
          }
        } else if (role === 'pro') {
          const MONTHLY_LIMIT = 50;
          if (currentMonthCount >= MONTHLY_LIMIT) {
            throw new HttpsError(
              'resource-exhausted',
              `Monthly simulation quota exhausted (${currentMonthCount}/${MONTHLY_LIMIT} used). Contact support or platform admin for enterprise limits.`
            );
          }
        }

        // Increment usage counters
        updatedDayCount = currentDayCount + 1;
        updatedMonthCount = currentMonthCount + 1;

        transaction.update(userRef, {
          'scanUsage.currentDayCount': updatedDayCount,
          'scanUsage.currentMonthCount': updatedMonthCount,
          'scanUsage.lastResetDate': nowTimestamp,
          updatedAt: nowTimestamp
        });
      }

      // 2.3 Create Simulation Record in `/simulations/{simId}`
      const newSimulation: SimulationDocument = {
        envId,
        initiatedBy: uid,
        status: 'queued',
        exploitsAttempted: 0,
        provenExploitable: 0,
        createdAt: nowTimestamp
      };

      transaction.set(simulationRef, newSimulation);

      // 2.4 Update Environment state to 'simulating'
      transaction.update(envRef, {
        status: 'simulating',
        updatedAt: nowTimestamp
      });
    });

    return {
      simulationId: simulationRef.id,
      envId,
      status: 'queued',
      role,
      scanUsage: {
        currentDayCount: updatedDayCount,
        currentMonthCount: updatedMonthCount,
        dailyLimit: role === 'user' ? 3 : null,
        monthlyLimit: role === 'pro' ? 50 : null
      }
    };
  }
);
