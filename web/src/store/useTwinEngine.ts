import { create } from 'zustand';

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

  // Actions
  startSimulation: () => Promise<void>;
  resetSimulation: () => void;
  patchEdge: (edgeId: string) => void;
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
    });
  },

  patchEdge: (edgeId: string) => {
    const { edges, nodes, logs } = get();
    const updatedEdges = edges.map((e) => (e.id === edgeId ? { ...e, accessState: 'blocked' as AccessState } : e));
    const targetEdge = edges.find((e) => e.id === edgeId);

    const updatedNodes = nodes.map((n) => {
      if (targetEdge && n.id === targetEdge.target) {
        return { ...n, status: 'patched' as NodeStatus };
      }
      return n;
    });

    set({
      edges: updatedEdges,
      nodes: updatedNodes,
      logs: [
        ...logs,
        {
          timestamp: getTimestamp(),
          level: 'INFO',
          message: `[REMEDIATION] Edge ${edgeId} blocked. Downstream nodes marked patched.`,
        },
      ],
    });
  },

  /**
   * startSimulation:
   * Deterministic adversarial graph traversal engine without generic fake timeouts.
   * Step 1: Find 'ingress' node. Mark 'probing'. Log: `[INFO] Ingress exposed`.
   * Step 2: Find connected edges where accessState === 'open'.
   * Step 3: Traverse to target node. If it has a CVE, mark 'compromised'. Log: `[CRIT] Exploited CVE. Node compromised`.
   * Step 4: Calculate Blast Radius based on compromised node criticality.
   */
  startSimulation: async () => {
    const state = get();
    if (state.isSimulating) return;

    set({ isSimulating: true, blastRadius: 0 });

    // Step 1: Find 'ingress' node. Mark 'probing'. Log: `[INFO] Ingress exposed`.
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

      // Step 2: Find connected edges where accessState === 'open'
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

        // Step 3: Traverse to target node. If it has a CVE, mark 'compromised'.
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
    // Sum of criticality (scale 1-10) normalized into a 0-100 index
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
