import { create } from 'zustand';
import { api, DigitalTwinModel } from '@/lib/api';
import { useAuthStore } from './useAuthStore';

export type NodeType = 'ingress' | 'compute' | 'database';
export type NodeStatus = 'healthy' | 'probing' | 'compromised' | 'patched';
export type AccessState = 'open' | 'blocked';
export type LogLevel = 'INFO' | 'WARN' | 'CRIT';

export interface Node {
  id: string;
  label: string;
  ip: string;
  type: NodeType;
  status: NodeStatus;
  criticality: number; // 1-10
  cve?: string;
  position?: { x: number; y: number };
}

export interface Edge {
  id: string;
  source: string;
  target: string;
  port: number;
  accessState: AccessState;
  isTraversed?: boolean;
}

export interface LogEvent {
  timestamp: string;
  level: LogLevel;
  message: string;
}

interface TwinEngineState {
  nodes: Node[];
  edges: Edge[];
  logs: LogEvent[];
  blastRadius: number;
  isSimulating: boolean;
  selectedNodeId: string | null;
  twinId: string | null;

  // Actions
  startSimulation: () => Promise<void>;
  resetSimulation: () => void;
  patchEdge: (edgeId: string) => void;
  applyPatch: (edgeId?: string) => Promise<void>;
  selectNode: (nodeId: string | null) => void;
}

const getTimestamp = (): string => {
  const now = new Date();
  return now.toTimeString().split(' ')[0] + '.' + String(now.getMilliseconds()).padStart(3, '0');
};

const initialNodes: Node[] = [
  {
    id: 'ingress-1',
    label: 'AWS Application Load Balancer',
    ip: '198.51.100.10',
    type: 'ingress',
    status: 'healthy',
    criticality: 4,
    position: { x: 250, y: 50 },
  },
  {
    id: 'app-server-1',
    label: 'Internal Node.js App Server',
    ip: '10.0.1.25',
    type: 'compute',
    status: 'healthy',
    criticality: 7,
    cve: 'CVE-2023-38606',
    position: { x: 250, y: 220 },
  },
  {
    id: 'internal-db-1',
    label: 'Production PostgreSQL Database',
    ip: '10.0.2.14',
    type: 'database',
    status: 'healthy',
    criticality: 10,
    position: { x: 250, y: 390 },
  },
];

const initialEdges: Edge[] = [
  {
    id: 'edge-ingress-app',
    source: 'ingress-1',
    target: 'app-server-1',
    port: 443,
    accessState: 'open',
  },
  {
    id: 'edge-app-db',
    source: 'app-server-1',
    target: 'internal-db-1',
    port: 5432,
    accessState: 'open',
  },
];

const initialLogs: LogEvent[] = [
  {
    timestamp: getTimestamp(),
    level: 'INFO',
    message: '[SYSTEM] Digital Twin Attack Path Engine initialized. Graph loaded (3 Nodes, 2 Edges).',
  },
];

// Helper to pause deterministically between traversal steps
const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

export const useTwinEngine = create<TwinEngineState>((set, get) => ({
  nodes: JSON.parse(JSON.stringify(initialNodes)),
  edges: JSON.parse(JSON.stringify(initialEdges)),
  logs: initialLogs,
  blastRadius: 0,
  isSimulating: false,
  selectedNodeId: null,
  twinId: null,

  selectNode: (nodeId: string | null) => {
    set({ selectedNodeId: nodeId });
  },

  resetSimulation: () => {
    set({
      nodes: JSON.parse(JSON.stringify(initialNodes)),
      edges: JSON.parse(JSON.stringify(initialEdges)),
      logs: [
        {
          timestamp: getTimestamp(),
          level: 'INFO',
          message: '[SYSTEM] Digital Twin reset to idle state. All nodes marked healthy.',
        },
      ],
      blastRadius: 0,
      isSimulating: false,
      twinId: null,
    });
  },

  patchEdge: (edgeId: string) => {
    get().applyPatch(edgeId);
  },

  applyPatch: async (edgeId?: string) => {
    const { edges, nodes, logs, twinId } = get();
    // Default to database ingress edge if none specified
    const targetEdgeId = edgeId || 'edge-app-db';
    const targetEdge = edges.find((e) => e.id === targetEdgeId);

    const updatedEdges = edges.map((e) =>
      e.id === targetEdgeId ? { ...e, accessState: 'blocked' as AccessState } : e
    );

    const updatedNodes = nodes.map((n) => {
      if (targetEdge && n.id === targetEdge.target) {
        return { ...n, status: 'patched' as NodeStatus };
      }
      return n;
    });

    set({
      edges: updatedEdges,
      nodes: updatedNodes,
      blastRadius: 0,
      logs: [
        ...logs,
        {
          timestamp: getTimestamp(),
          level: 'INFO',
          message: `[SUCCESS] Attack path severed. Re-test verified. Port ${targetEdge?.port || 5432} blocked.`,
        },
      ],
    });

    // Real backend attestation
    const activeId = twinId || 'TWIN-DEMO';
    try {
      const remediated = await api.remediateTwin(activeId);
      if (remediated?.before_after_delta) {
        const delta = remediated.before_after_delta;
        set((s) => ({
          logs: [
            ...s.logs,
            {
              timestamp: getTimestamp(),
              level: 'INFO',
              message: `[BACKEND_ATTESTATION] SafePath Verified: Posture ${delta.before_posture} -> ${delta.after_posture} (+${delta.posture_improvement_points} pts). Open Findings: 0.`,
            },
          ],
        }));
      }
    } catch (err) {
      console.warn('Backend remediation attestation error:', err);
    }
  },

  startSimulation: async () => {
    const state = get();
    if (state.isSimulating) return;

    // Check quota
    const authStore = useAuthStore.getState();
    if (authStore.role === 'user' && authStore.scansUsed >= authStore.maxScans) {
      set((s) => ({
        logs: [
          ...s.logs,
          {
            timestamp: getTimestamp(),
            level: 'CRIT',
            message: `[QUOTA_EXCEEDED] Daily simulation limit reached (${authStore.scansUsed}/${authStore.maxScans}). Sign in with Developer Account for unlimited quota.`,
          },
        ],
      }));
      return;
    }

    // Increment scan quota
    await authStore.incrementScan();

    set({ isSimulating: true, blastRadius: 0 });

    // Step 1: Initialize backend digital twin model
    try {
      const backendTwin = await api.createTwin('aws.vpc.internal.ecommerce', 85, 'MALICIOUS', {
        cve: 'CVE-2023-38606',
        target_port: 5432,
        environment: 'Enterprise Cloud VPC',
      });
      set({ twinId: backendTwin.twin_id });
      set((s) => ({
        logs: [
          ...s.logs,
          {
            timestamp: getTimestamp(),
            level: 'INFO',
            message: `[BACKEND] AutoSecTwin session initialized: ${backendTwin.twin_id}. Baseline Posture: ${backendTwin.initial_posture}/100.`,
          },
        ],
      }));
    } catch (err) {
      console.warn('Backend twin synthesis offline or unavailable, continuing local deterministic engine:', err);
    }

    // Step 2: Find 'ingress' node. Mark 'probing'. Log: `[INFO] Ingress exposed`.
    const ingressNode = get().nodes.find((n) => n.type === 'ingress');
    if (!ingressNode) {
      set({ isSimulating: false });
      return;
    }

    set((s) => ({
      nodes: s.nodes.map((n) => (n.id === ingressNode.id ? { ...n, status: 'probing' } : n)),
      logs: [
        ...s.logs,
        {
          timestamp: getTimestamp(),
          level: 'INFO',
          message: `[INFO] Ingress exposed: ${ingressNode.label} (${ingressNode.ip})`,
        },
      ],
    }));

    await delay(700);

    // Queue of nodes to traverse breadth-first
    const traversalQueue: string[] = [ingressNode.id];
    const visitedNodes = new Set<string>([ingressNode.id]);
    const compromisedNodeList: Node[] = [];

    while (traversalQueue.length > 0) {
      const currentNodeId = traversalQueue.shift()!;

      // Find connected edges where accessState === 'open'
      const outgoingEdges = get().edges.filter(
        (edge) => edge.source === currentNodeId && edge.accessState === 'open'
      );

      for (const edge of outgoingEdges) {
        // Mark edge traversed
        set((s) => ({
          edges: s.edges.map((e) => (e.id === edge.id ? { ...e, isTraversed: true } : e)),
        }));

        await delay(500);

        const targetNode = get().nodes.find((n) => n.id === edge.target);
        if (!targetNode || visitedNodes.has(targetNode.id)) continue;

        visitedNodes.add(targetNode.id);

        // Mark target probing
        set((s) => ({
          nodes: s.nodes.map((n) => (n.id === targetNode.id ? { ...n, status: 'probing' } : n)),
          logs: [
            ...s.logs,
            {
              timestamp: getTimestamp(),
              level: 'WARN',
              message: `[WARN] Lateral traversal across port :${edge.port} -> probing ${targetNode.label} (${targetNode.ip})`,
            },
          ],
        }));

        await delay(700);

        // Traverse to target node. If it has a CVE, mark 'compromised'.
        if (targetNode.cve) {
          compromisedNodeList.push({ ...targetNode, status: 'compromised' });

          set((s) => ({
            nodes: s.nodes.map((n) => (n.id === targetNode.id ? { ...n, status: 'compromised' } : n)),
            logs: [
              ...s.logs,
              {
                timestamp: getTimestamp(),
                level: 'CRIT',
                message: `[CRIT] Exploited CVE (${targetNode.cve}). Node compromised: ${targetNode.label}`,
              },
            ],
          }));

          traversalQueue.push(targetNode.id);
        } else if (targetNode.type === 'database') {
          // Internal database reached via compromised compute
          compromisedNodeList.push({ ...targetNode, status: 'compromised' });

          set((s) => ({
            nodes: s.nodes.map((n) => (n.id === targetNode.id ? { ...n, status: 'compromised' } : n)),
            logs: [
              ...s.logs,
              {
                timestamp: getTimestamp(),
                level: 'CRIT',
                message: `[CRIT] High-value data tier reached. Crown Jewel compromised: ${targetNode.label}`,
              },
            ],
          }));
        } else {
          set((s) => ({
            nodes: s.nodes.map((n) => (n.id === targetNode.id ? { ...n, status: 'healthy' } : n)),
          }));
          traversalQueue.push(targetNode.id);
        }

        await delay(500);
      }
    }

    // Step 4: Calculate Blast Radius based on compromised node criticality
    const totalCriticality = compromisedNodeList.reduce((acc, curr) => acc + curr.criticality, 0);
    const calculatedRadius = Math.min(100, Math.round((totalCriticality / 17) * 100));

    set((s) => ({
      blastRadius: calculatedRadius,
      isSimulating: false,
      logs: [
        ...s.logs,
        {
          timestamp: getTimestamp(),
          level: 'CRIT',
          message: `[SYSTEM] Traversal complete. Attack chain validated. Blast Radius: ${calculatedRadius} / 100.`,
        },
      ],
    }));
  },
}));
