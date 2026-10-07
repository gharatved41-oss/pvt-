export type UserRole = 'developer' | 'pro' | 'user';

export interface CustomUserClaims {
  role?: UserRole;
  assignedAt?: number;
}

export interface ScanUsage {
  currentDayCount: number;
  currentMonthCount: number;
  lastResetDate: any;
}

export interface UserProfile {
  uid: string;
  email: string | null;
  role: UserRole;
  scanUsage?: ScanUsage;
  createdAt?: any;
}

export type EnvironmentStatus = 'idle' | 'cloning' | 'ready' | 'simulating';

export interface Environment {
  id: string;
  name: string;
  ownerId: string;
  targetDomain: string;
  status: EnvironmentStatus;
  createdAt: any;
  updatedAt?: any;
}

export type SimulationStatus = 'queued' | 'running' | 'completed' | 'failed';

export interface Simulation {
  id: string;
  envId: string;
  twinId?: string;
  initiatedBy: string;
  status: SimulationStatus;
  riskScore?: number;
  compoundRiskLevel?: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  validatedPaths?: string[][];
  compromisedNodeIds?: string[];
  totalSyntheticRecordsExposed?: number;
  chokePointsBreached?: string[];
  summary?: string;
  exploitsAttempted: number;
  provenExploitable: number;
  createdAt: any;
  completedAt?: any;
}

export interface SimulationEvent {
  id?: string;
  step: string;
  targetNodeId: string;
  severity: 'info' | 'warning' | 'critical';
  message: string;
  timestamp: any;
}

export interface InitiateScanResult {
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

// =============================================================================
// DIGITAL TWIN GRAPH TOPOLOGY TYPES
// =============================================================================

export type NodeType = 'server' | 'database' | 'firewall' | 'load_balancer';
export type NodeStatus = 'healthy' | 'compromised' | 'offline';

export interface NodeProperties {
  hostname?: string;
  ipAddress?: string;
  osVersion?: string;
  openPorts?: number[];
  softwareStack?: string[];
  cveExposures?: string[];
  syntheticRecordsCount?: number;
  syntheticDataRef?: string;
  [key: string]: any;
}

export interface TwinNode {
  id: string;
  name?: string;
  type: NodeType;
  properties: NodeProperties;
  status: NodeStatus;
  compromiseTimestamp?: any;
  compromiseVector?: string;
  updatedAt?: any;
}

export type EdgeProtocol = 'TCP' | 'UDP' | 'HTTP';
export type EdgeAccessState = 'open' | 'restricted' | 'blocked';

export interface TwinEdge {
  id: string;
  sourceNodeId: string;
  targetNodeId: string;
  protocol: EdgeProtocol;
  port: number;
  accessState: EdgeAccessState;
  ruleDescription?: string;
  updatedAt?: any;
}

export type DigitalTwinStatus = 'cloning' | 'synthesizing' | 'ready' | 'simulating' | 'failed';

export interface DigitalTwinDocument {
  id: string;
  envId: string;
  name?: string;
  targetDomain?: string;
  status: DigitalTwinStatus;
  nodeCount: number;
  edgeCount: number;
  syntheticRecordsGenerated: number;
  createdAt: any;
  updatedAt: any;
  lastSimulatedAt?: any;
}

