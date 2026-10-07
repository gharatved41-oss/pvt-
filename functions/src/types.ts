import { Timestamp } from 'firebase-admin/firestore';

export type UserRole = 'developer' | 'pro' | 'user';

export interface CustomUserClaims {
  role: UserRole;
  assignedAt?: number;
}

export interface ScanUsage {
  currentDayCount: number;
  currentMonthCount: number;
  lastResetDate: Timestamp;
}

export interface UserDocument {
  email: string;
  role: UserRole;
  scanUsage: ScanUsage;
  createdAt: Timestamp;
  updatedAt?: Timestamp;
}

export type EnvironmentStatus = 'idle' | 'cloning' | 'ready' | 'simulating';

export interface EnvironmentDocument {
  name: string;
  ownerId: string;
  targetDomain: string;
  status: EnvironmentStatus;
  createdAt: Timestamp;
  updatedAt?: Timestamp;
}

export type SimulationStatus = 'queued' | 'running' | 'completed' | 'failed';

export interface SimulationDocument {
  envId: string;
  initiatedBy: string;
  status: SimulationStatus;
  exploitsAttempted: number;
  provenExploitable: number;
  createdAt: Timestamp;
  completedAt?: Timestamp;
  errorMessage?: string;
}

export interface SetCustomUserRoleRequest {
  targetUid: string;
  role: UserRole;
}

export interface GenerateInviteLinkRequest {
  email: string;
  role: UserRole;
  redirectUrl?: string;
}

export interface InitiateScanRequest {
  envId: string;
}

export interface InitiateScanResponse {
  simulationId: string;
  envId: string;
  status: SimulationStatus;
  role: UserRole;
  scanUsage: {
    currentDayCount: number;
    currentMonthCount: number;
    dailyLimit: number | null;
    monthlyLimit: number | null;
  };
}
