import { onCall, HttpsError, CallableRequest } from 'firebase-functions/v2/https';
import * as admin from 'firebase-admin';
import { 
  UserRole, 
  CustomUserClaims, 
  SetCustomUserRoleRequest, 
  GenerateInviteLinkRequest,
  UserDocument 
} from './types';

const db = admin.firestore();

/**
 * Validates whether the caller possesses the 'developer' role or provided
 * the emergency bootstrap secret.
 */
function assertDeveloperOrBootstrap(
  request: CallableRequest<any>, 
  bootstrapKey?: string
): void {
  const envBootstrap = process.env.BOOTSTRAP_ADMIN_KEY;
  if (bootstrapKey && envBootstrap && bootstrapKey === envBootstrap) {
    return;
  }

  if (!request.auth) {
    throw new HttpsError(
      'unauthenticated', 
      'Authentication required to execute administrative operations.'
    );
  }

  const role = request.auth.token.role as UserRole | undefined;
  if (role !== 'developer') {
    throw new HttpsError(
      'permission-denied', 
      'Access Denied: Caller lacks developer clearance required for RBAC mutations.'
    );
  }
}

/**
 * 1. setCustomUserRole
 * Assigns Firebase Auth Custom Claims (`role: 'developer' | 'pro' | 'user'`),
 * invalidates existing refresh tokens so the user is forced to refresh claims,
 * and synchronizes the assigned role to `/users/{targetUid}`.
 */
export const setCustomUserRole = onCall<SetCustomUserRoleRequest & { bootstrapKey?: string }>(
  async (request) => {
    const { targetUid, role, bootstrapKey } = request.data;

    assertDeveloperOrBootstrap(request, bootstrapKey);

    if (!targetUid || typeof targetUid !== 'string') {
      throw new HttpsError('invalid-argument', 'Valid targetUid must be provided.');
    }

    const validRoles: UserRole[] = ['developer', 'pro', 'user'];
    if (!validRoles.includes(role)) {
      throw new HttpsError(
        'invalid-argument', 
        `Invalid role. Must be one of: ${validRoles.join(', ')}`
      );
    }

    try {
      // 1. Verify user exists in Firebase Auth
      const userRecord = await admin.auth().getUser(targetUid);

      // 2. Attach Custom Claims directly to user's JWT
      const claims: CustomUserClaims = {
        role,
        assignedAt: Date.now()
      };
      await admin.auth().setCustomUserClaims(targetUid, claims);

      // 3. Revoke existing refresh tokens so client immediately fetches new JWT with updated role
      await admin.auth().revokeRefreshTokens(targetUid);

      // 4. Synchronize role into Firestore `/users/{targetUid}`
      const userRef = db.collection('users').doc(targetUid);
      const now = admin.firestore.Timestamp.now();

      await db.runTransaction(async (transaction) => {
        const doc = await transaction.get(userRef);
        if (!doc.exists) {
          const newUser: UserDocument = {
            email: userRecord.email || '',
            role,
            scanUsage: {
              currentDayCount: 0,
              currentMonthCount: 0,
              lastResetDate: now
            },
            createdAt: now,
            updatedAt: now
          };
          transaction.set(userRef, newUser);
        } else {
          transaction.update(userRef, {
            role,
            updatedAt: now
          });
        }
      });

      return {
        success: true,
        targetUid,
        assignedRole: role,
        email: userRecord.email,
        timestamp: Date.now()
      };
    } catch (error: any) {
      if (error instanceof HttpsError) {
        throw error;
      }
      throw new HttpsError('internal', `Failed to assign custom claims: ${error.message}`);
    }
  }
);

/**
 * 2. generateInviteLink
 * Generates an admin invite / passwordless authentication flow via Firebase Magic Link.
 * Pre-assigns the selected role custom claim and provisions the user in Firestore.
 */
export const generateInviteLink = onCall<GenerateInviteLinkRequest>(
  async (request) => {
    assertDeveloperOrBootstrap(request);

    const { email, role, redirectUrl } = request.data;

    if (!email || typeof email !== 'string' || !email.includes('@')) {
      throw new HttpsError('invalid-argument', 'Valid email address required.');
    }

    const validRoles: UserRole[] = ['developer', 'pro', 'user'];
    if (!validRoles.includes(role)) {
      throw new HttpsError(
        'invalid-argument', 
        `Invalid role. Must be one of: ${validRoles.join(', ')}`
      );
    }

    try {
      // 1. Fetch or create Auth user
      let userRecord: admin.auth.UserRecord;
      try {
        userRecord = await admin.auth().getUserByEmail(email);
      } catch (err: any) {
        if (err.code === 'auth/user-not-found') {
          userRecord = await admin.auth().createUser({
            email,
            emailVerified: false,
            disabled: false
          });
        } else {
          throw err;
        }
      }

      // 2. Set custom claims on user
      const claims: CustomUserClaims = {
        role,
        assignedAt: Date.now()
      };
      await admin.auth().setCustomUserClaims(userRecord.uid, claims);

      // 3. Upsert user in Firestore `/users/{userId}`
      const userRef = db.collection('users').doc(userRecord.uid);
      const now = admin.firestore.Timestamp.now();

      await db.runTransaction(async (transaction) => {
        const doc = await transaction.get(userRef);
        if (!doc.exists) {
          const newUser: UserDocument = {
            email,
            role,
            scanUsage: {
              currentDayCount: 0,
              currentMonthCount: 0,
              lastResetDate: now
            },
            createdAt: now,
            updatedAt: now
          };
          transaction.set(userRef, newUser);
        } else {
          transaction.update(userRef, {
            role,
            updatedAt: now
          });
        }
      });

      // 4. Generate passwordless Firebase Email Sign-in Magic Link
      const fallbackUrl = process.env.VULNTWIN_WEB_URL || 'https://vulntwin.ai/auth/verify';
      const actionCodeSettings: admin.auth.ActionCodeSettings = {
        url: redirectUrl || fallbackUrl,
        handleCodeInApp: true
      };

      const inviteLink = await admin.auth().generateSignInWithEmailLink(email, actionCodeSettings);

      return {
        success: true,
        userId: userRecord.uid,
        email,
        assignedRole: role,
        inviteLink
      };
    } catch (error: any) {
      if (error instanceof HttpsError) {
        throw error;
      }
      throw new HttpsError('internal', `Failed to generate invite link: ${error.message}`);
    }
  }
);
