import { onCall, HttpsError, CallableRequest } from 'firebase-functions/v2/https';
import { getFirestore, FieldValue } from 'firebase-admin/firestore';
import { TwinNode, TwinEdge, NodeStatus } from './models/graph';
import { generateSyntheticPayload } from './utils/synthesizer';

const db = getFirestore();

// =============================================================================
// 1. INITIALIZE DIGITAL TWIN CLOUD CLONE FUNCTION
// =============================================================================

export interface InitializeTwinRequest {
  envId: string;
  targetDomain?: string;
  presetTopology?: 'enterprise-vpc' | 'microservices' | 'monolith';
}

export interface InitializeTwinResponse {
  success: boolean;
  twinId: string;
  status: string;
  nodeCount: number;
  edgeCount: number;
  syntheticRecordsCount: number;
}

export const initializeDigitalTwin = onCall<InitializeTwinRequest>(
  { cors: true },
  async (request: CallableRequest<InitializeTwinRequest>): Promise<InitializeTwinResponse> => {
    if (!request.auth) {
      throw new HttpsError('unauthenticated', 'User must be authenticated to clone environment.');
    }

    const { envId, targetDomain } = request.data;
    if (!envId) {
      throw new HttpsError('invalid-argument', 'Missing required parameter: envId.');
    }

    const twinId = `twin_${envId.replace(/[^a-zA-Z0-9_-]/g, '_')}_${Date.now()}`;
    const twinRef = db.collection('digital_twins').doc(twinId);

    // 1. Mark twin state as synthesizing
    await twinRef.set({
      id: twinId,
      envId,
      targetDomain: targetDomain || 'internal-vpc.net',
      status: 'synthesizing',
      nodeCount: 0,
      edgeCount: 0,
      syntheticRecordsGenerated: 0,
      createdAt: FieldValue.serverTimestamp(),
      updatedAt: FieldValue.serverTimestamp(),
    });

    // 2. Synthesize Enterprise Production Graph Topology
    const nodes: TwinNode[] = [
      {
        id: 'waf-edge-01',
        name: 'Cloud Armor / WAF Ingress',
        type: 'firewall',
        status: 'healthy',
        properties: {
          hostname: 'waf.us-east-1.internal',
          ipAddress: '10.0.0.1',
          openPorts: [80, 443],
          softwareStack: ['ModSecurity v3', 'Envoy Gateway'],
          cveExposures: [],
        },
      },
      {
        id: 'alb-ingress-01',
        name: 'Application Load Balancer',
        type: 'load_balancer',
        status: 'healthy',
        properties: {
          hostname: 'alb-prod-external.internal',
          ipAddress: '10.0.1.10',
          openPorts: [443],
          softwareStack: ['AWS ALB', 'TLS 1.3 Termination'],
        },
      },
      {
        id: 'web-server-prod-01',
        name: 'Core API Gateway Server',
        type: 'server',
        status: 'healthy',
        properties: {
          hostname: 'api-gateway-01.us-east-1.compute',
          ipAddress: '10.0.2.14',
          osVersion: 'Ubuntu 22.04 LTS (Kernel 5.15)',
          openPorts: [3000, 8080],
          softwareStack: ['Node.js v20.12', 'Express v4.19', 'Nginx 1.24'],
          cveExposures: ['CVE-2024-21338', 'CVE-2023-38606'],
        },
      },
      {
        id: 'auth-microservice-02',
        name: 'Identity & Session Microservice',
        type: 'server',
        status: 'healthy',
        properties: {
          hostname: 'auth-svc-02.internal',
          ipAddress: '10.0.2.25',
          osVersion: 'Alpine Linux 3.19',
          openPorts: [5000],
          softwareStack: ['Go 1.22', 'gRPC v1.62', 'JWT RS256 Engine'],
          cveExposures: ['CVE-2023-48795'],
        },
      },
      {
        id: 'sql-db-main',
        name: 'Primary PostgreSQL Database',
        type: 'database',
        status: 'healthy',
        properties: {
          hostname: 'pg-primary-cluster.internal',
          ipAddress: '10.0.3.50',
          osVersion: 'Debian 12 Bookworm',
          openPorts: [5432],
          softwareStack: ['PostgreSQL 16.2', 'pgcrypto', 'pgvector'],
          syntheticRecordsCount: 1000,
          syntheticDataRef: 'users_schema',
        },
      },
      {
        id: 'redis-cache-cluster',
        name: 'In-Memory Session & Audit Cache',
        type: 'database',
        status: 'healthy',
        properties: {
          hostname: 'redis-cache.internal',
          ipAddress: '10.0.3.75',
          osVersion: 'Alpine Linux 3.19',
          openPorts: [6379],
          softwareStack: ['Redis Enterprise 7.2.4'],
          syntheticRecordsCount: 1000,
          syntheticDataRef: 'access_logs_schema',
        },
      },
    ];

    const edges: TwinEdge[] = [
      {
        id: 'edge_waf_to_alb',
        sourceNodeId: 'waf-edge-01',
        targetNodeId: 'alb-ingress-01',
        protocol: 'HTTP',
        port: 443,
        accessState: 'open',
        ruleDescription: 'Inbound HTTPS traffic inspection',
      },
      {
        id: 'edge_alb_to_web',
        sourceNodeId: 'alb-ingress-01',
        targetNodeId: 'web-server-prod-01',
        protocol: 'HTTP',
        port: 3000,
        accessState: 'open',
        ruleDescription: 'Internal Reverse Proxy Routing to API',
      },
      {
        id: 'edge_alb_to_auth',
        sourceNodeId: 'alb-ingress-01',
        targetNodeId: 'auth-microservice-02',
        protocol: 'HTTP',
        port: 5000,
        accessState: 'open',
        ruleDescription: 'Authentication Handshake Route',
      },
      {
        id: 'edge_web_to_sql',
        sourceNodeId: 'web-server-prod-01',
        targetNodeId: 'sql-db-main',
        protocol: 'TCP',
        port: 5432,
        accessState: 'restricted',
        ruleDescription: 'VPC Peering: Database Connector',
      },
      {
        id: 'edge_auth_to_redis',
        sourceNodeId: 'auth-microservice-02',
        targetNodeId: 'redis-cache-cluster',
        protocol: 'TCP',
        port: 6379,
        accessState: 'open',
        ruleDescription: 'Fast Session Token Verification',
      },
    ];

    // 3. Synthesize fake production data payloads
    const syntheticUsers = generateSyntheticPayload('users', 1000);
    const syntheticLogs = generateSyntheticPayload('logs', 1000);

    // 4. Batch commit nodes, edges, and payloads into Firestore
    const batch = db.batch();

    // Commit Nodes to /digital_twins/{twinId}/nodes
    for (const node of nodes) {
      const nodeDocRef = twinRef.collection('nodes').doc(node.id);
      batch.set(nodeDocRef, {
        ...node,
        updatedAt: FieldValue.serverTimestamp(),
      });
    }

    // Commit Edges to /digital_twins/{twinId}/edges
    for (const edge of edges) {
      const edgeDocRef = twinRef.collection('edges').doc(edge.id);
      batch.set(edgeDocRef, {
        ...edge,
        updatedAt: FieldValue.serverTimestamp(),
      });
    }

    // Attach synthetic payloads to safe sub-collection in PostgreSQL node
    const sqlSyntheticRef = twinRef.collection('nodes').doc('sql-db-main').collection('synthetic_records').doc('sample_users');
    batch.set(sqlSyntheticRef, {
      recordCount: syntheticUsers.length,
      sampleRecords: syntheticUsers.slice(0, 50),
      generatedAt: FieldValue.serverTimestamp(),
    });

    // Attach synthetic payloads to safe sub-collection in Redis node
    const redisSyntheticRef = twinRef.collection('nodes').doc('redis-cache-cluster').collection('synthetic_records').doc('sample_logs');
    batch.set(redisSyntheticRef, {
      recordCount: syntheticLogs.length,
      sampleRecords: syntheticLogs.slice(0, 50),
      generatedAt: FieldValue.serverTimestamp(),
    });

    // Commit the digital twin document as 'ready'
    batch.update(twinRef, {
      status: 'ready',
      nodeCount: nodes.length,
      edgeCount: edges.length,
      syntheticRecordsGenerated: syntheticUsers.length + syntheticLogs.length,
      updatedAt: FieldValue.serverTimestamp(),
    });

    await batch.commit();

    return {
      success: true,
      twinId,
      status: 'ready',
      nodeCount: nodes.length,
      edgeCount: edges.length,
      syntheticRecordsCount: syntheticUsers.length + syntheticLogs.length,
    };
  }
);

// =============================================================================
// 2. UPDATE TWIN STATE ENGINE (REAL-TIME HEARTBEAT)
// =============================================================================

export interface UpdateTwinStateRequest {
  twinId: string;
  nodeId: string;
  status: NodeStatus;
  compromiseVector?: string;
  blastRadius?: string;
}

export interface UpdateTwinStateResponse {
  success: boolean;
  twinId: string;
  nodeId: string;
  previousStatus: NodeStatus;
  newStatus: NodeStatus;
  timestamp: string;
}

export const updateTwinState = onCall<UpdateTwinStateRequest>(
  { cors: true },
  async (request: CallableRequest<UpdateTwinStateRequest>): Promise<UpdateTwinStateResponse> => {
    if (!request.auth) {
      throw new HttpsError('unauthenticated', 'User must be authenticated.');
    }

    const { twinId, nodeId, status, compromiseVector } = request.data;
    if (!twinId || !nodeId || !status) {
      throw new HttpsError('invalid-argument', 'Missing required parameters: twinId, nodeId, and status.');
    }

    const twinRef = db.collection('digital_twins').doc(twinId);
    const nodeRef = twinRef.collection('nodes').doc(nodeId);

    const nodeSnap = await nodeRef.get();
    if (!nodeSnap.exists) {
      throw new HttpsError('not-found', `Node with ID ${nodeId} does not exist in twin ${twinId}.`);
    }

    const previousData = nodeSnap.data() as TwinNode;
    const previousStatus = previousData.status || 'healthy';

    const updates: Record<string, any> = {
      status,
      updatedAt: FieldValue.serverTimestamp(),
    };

    if (status === 'compromised') {
      updates.compromiseTimestamp = FieldValue.serverTimestamp();
      updates.compromiseVector = compromiseVector || 'Lateral Movement via Exploit Chain';
    }

    const batch = db.batch();
    batch.update(nodeRef, updates);
    batch.update(twinRef, {
      updatedAt: FieldValue.serverTimestamp(),
      lastSimulatedAt: FieldValue.serverTimestamp(),
    });

    await batch.commit();

    return {
      success: true,
      twinId,
      nodeId,
      previousStatus,
      newStatus: status,
      timestamp: new Date().toISOString(),
    };
  }
);

// =============================================================================
// 3. EXECUTE AUTONOMOUS TWIN SECURITY VALIDATION SIMULATION
// =============================================================================

export interface ExecuteSimulationRequest {
  simId: string;
  twinId: string;
}

export const executeTwinSimulation = onCall<ExecuteSimulationRequest>(
  { cors: true },
  async (request: CallableRequest<ExecuteSimulationRequest>) => {
    if (!request.auth) {
      throw new HttpsError('unauthenticated', 'User must be authenticated to execute security simulation.');
    }

    const { simId, twinId } = request.data;
    if (!simId || !twinId) {
      throw new HttpsError('invalid-argument', 'Missing required parameters: simId and twinId.');
    }

    const { SimulationRunner } = await import('./engine/runner');
    const runner = new SimulationRunner();
    return await runner.executeSimulation(simId, twinId);
  }
);

// =============================================================================
// 4. EXECUTE AEV REMEDIATION & VERIFICATION RE-TEST LOOP
// =============================================================================

export interface ExecuteAevRemediationRequest {
  simId: string;
  twinId: string;
  maxAttempts?: number;
}

export const executeAevRemediationLoop = onCall<ExecuteAevRemediationRequest>(
  { cors: true },
  async (request: CallableRequest<ExecuteAevRemediationRequest>) => {
    if (!request.auth) {
      throw new HttpsError('unauthenticated', 'User must be authenticated.');
    }

    const { simId, twinId, maxAttempts } = request.data;
    if (!simId || !twinId) {
      throw new HttpsError('invalid-argument', 'Missing required parameters: simId and twinId.');
    }

    const { AevRetestLoop } = await import('./remediation/retester');
    const loop = new AevRetestLoop();
    return await loop.executeRemediationLoop(simId, twinId, maxAttempts || 3);
  }
);


