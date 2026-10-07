import { create } from 'zustand';
import {
  TEMPLATES,
  ecommerceTemplate,
  healthcareTemplate,
  ArchitectureTemplate,
  TwinNodeData,
  TwinEdgeData,
  TelemetryEvent,
  RemediationPatch,
  NodeStatus,
} from '@/lib/mockData';
import { useAuthStore } from './useAuthStore';

export type SimulationStatus = 'IDLE' | 'RUNNING' | 'COMPLETED';

interface TwinStoreState {
  // Topology state
  selectedTemplate: string;
  activeTemplate: ArchitectureTemplate;
  nodes: TwinNodeData[];
  edges: TwinEdgeData[];
  selectedNode: TwinNodeData | null;

  // Simulation execution engine
  simulationStatus: SimulationStatus;
  simulationState: SimulationStatus; // Backwards compatible alias
  logs: TelemetryEvent[];
  eventLogs: TelemetryEvent[]; // Backwards compatible alias
  riskScore: number;
  simulationProgress: number;

  // Remediation
  activePatch: RemediationPatch | null;
  isPatchApplied: boolean;
  remediationStatus: 'IDLE' | 'APPLIED' | 'VERIFIED_SAFE';

  // Actions
  loadTemplate: (templateKey: string) => void;
  runValidation: () => Promise<void>;
  runSimulation: () => void; // Alias for runValidation
  resetSimulation: () => void;
  applyRemediation: (edgeId?: string) => void;
  applyPatch: () => void; // Alias for applyRemediation
  selectNode: (nodeId: string | null) => void;
  clearLogs: () => void;

  // Developer Admin Overrides
  injectNode: (customNode?: Partial<TwinNodeData>) => void;
  forceAllStatus: (status: NodeStatus) => void;
}

let activeTimers: NodeJS.Timeout[] = [];

const clearActiveTimers = () => {
  activeTimers.forEach((timer) => clearTimeout(timer));
  activeTimers = [];
};

const getTimestamp = (): string => {
  const now = new Date();
  return now.toTimeString().split(' ')[0] + '.' + String(now.getMilliseconds()).padStart(3, '0');
};

export const useTwinStore = create<TwinStoreState>((set, get) => {
  const initialTemplate = ecommerceTemplate;

  const initialLogs: TelemetryEvent[] = [
    {
      id: 'init-1',
      timestamp: getTimestamp(),
      step: 'INGRESS_DISCOVERY',
      severity: 'INFO',
      targetNodeId: initialTemplate.nodes[0]?.id || 'ingress',
      targetIp: initialTemplate.nodes[0]?.ipAddress || '0.0.0.0',
      message: `[SYSTEM] Digital Twin loaded: ${initialTemplate.name}. Initial topology verified (${initialTemplate.nodes.length} nodes, ${initialTemplate.edges.length} edges).`,
    },
    {
      id: 'init-2',
      timestamp: getTimestamp(),
      step: 'INGRESS_DISCOVERY',
      severity: 'INFO',
      targetNodeId: 'core',
      targetIp: '127.0.0.1',
      message: '[READY] CTEM Autonomous Security Validation Engine initialized. Ready for attack graph traversal.',
    },
  ];

  return {
    selectedTemplate: 'ecommerce',
    activeTemplate: initialTemplate,
    nodes: JSON.parse(JSON.stringify(initialTemplate.nodes)),
    edges: JSON.parse(JSON.stringify(initialTemplate.edges)),
    selectedNode: initialTemplate.nodes[0] || null,
    simulationStatus: 'IDLE',
    simulationState: 'IDLE',
    logs: initialLogs,
    eventLogs: initialLogs,
    riskScore: 0,
    simulationProgress: 0,
    activePatch: null,
    isPatchApplied: false,
    remediationStatus: 'IDLE',

    selectNode: (nodeId: string | null) => {
      if (!nodeId) {
        set({ selectedNode: null });
        return;
      }
      const found = get().nodes.find((n) => n.id === nodeId) || null;
      set({ selectedNode: found });
    },

    loadTemplate: (templateKey: string) => {
      clearActiveTimers();
      const target = TEMPLATES[templateKey] || (templateKey === 'healthcare' ? healthcareTemplate : ecommerceTemplate);
      const cleanNodes: TwinNodeData[] = JSON.parse(JSON.stringify(target.nodes));
      const cleanEdges: TwinEdgeData[] = JSON.parse(JSON.stringify(target.edges));

      const loadLogs: TelemetryEvent[] = [
        {
          id: `load-${Date.now()}-1`,
          timestamp: getTimestamp(),
          step: 'INGRESS_DISCOVERY',
          severity: 'INFO',
          targetNodeId: cleanNodes[0]?.id || 'ingress',
          targetIp: cleanNodes[0]?.ipAddress || '0.0.0.0',
          message: `[SYSTEM] Switched architecture template to "${target.name}".`,
        },
        {
          id: `load-${Date.now()}-2`,
          timestamp: getTimestamp(),
          step: 'INGRESS_DISCOVERY',
          severity: 'INFO',
          targetNodeId: cleanNodes[0]?.id || 'ingress',
          targetIp: cleanNodes[0]?.ipAddress || '0.0.0.0',
          message: `[TOPOLOGY] Ingested ${cleanNodes.length} infrastructure assets and ${cleanEdges.length} active network interconnects.`,
        },
      ];

      set({
        selectedTemplate: target.id,
        activeTemplate: target,
        nodes: cleanNodes,
        edges: cleanEdges,
        selectedNode: cleanNodes[0] || null,
        simulationStatus: 'IDLE',
        simulationState: 'IDLE',
        logs: loadLogs,
        eventLogs: loadLogs,
        riskScore: 0,
        activePatch: null,
        isPatchApplied: false,
        remediationStatus: 'IDLE',
        simulationProgress: 0,
      });
    },

    resetSimulation: () => {
      clearActiveTimers();
      const template = get().activeTemplate;
      const cleanNodes: TwinNodeData[] = JSON.parse(JSON.stringify(template.nodes));
      const cleanEdges: TwinEdgeData[] = JSON.parse(JSON.stringify(template.edges));

      const resetLog: TelemetryEvent = {
        id: `reset-${Date.now()}`,
        timestamp: getTimestamp(),
        step: 'INGRESS_DISCOVERY',
        severity: 'INFO',
        targetNodeId: cleanNodes[0]?.id || 'ingress',
        targetIp: cleanNodes[0]?.ipAddress || '0.0.0.0',
        message: `[RESET] Simulation reset to idle baseline. All node states and edges restored.`,
      };

      set((state) => ({
        nodes: cleanNodes,
        edges: cleanEdges,
        simulationStatus: 'IDLE',
        simulationState: 'IDLE',
        logs: [...state.logs, resetLog],
        eventLogs: [...state.logs, resetLog],
        riskScore: 0,
        activePatch: null,
        isPatchApplied: false,
        remediationStatus: 'IDLE',
        simulationProgress: 0,
      }));
    },

    runValidation: async () => {
      const { simulationStatus, activeTemplate } = get();
      if (simulationStatus === 'RUNNING') return;

      clearActiveTimers();

      // Check user scan quota
      const authStore = useAuthStore.getState();
      if (authStore.role === 'user' && authStore.scansUsed >= authStore.maxScans) {
        const errorLog: TelemetryEvent = {
          id: `quota-err-${Date.now()}`,
          timestamp: getTimestamp(),
          step: 'INGRESS_DISCOVERY',
          severity: 'CRIT',
          targetNodeId: 'quota-gate',
          targetIp: '0.0.0.0',
          message: `[QUOTA_EXCEEDED] Standard Tier execution limit reached (${authStore.scansUsed}/${authStore.maxScans}). Upgrade to Developer Clearance for unlimited simulations.`,
        };
        set((state) => ({
          logs: [...state.logs, errorLog],
          eventLogs: [...state.eventLogs, errorLog],
        }));
        return;
      }

      // Increment quota count
      await authStore.incrementScan();

      // Reset baseline
      const freshNodes: TwinNodeData[] = JSON.parse(JSON.stringify(activeTemplate.nodes));
      const freshEdges: TwinEdgeData[] = JSON.parse(JSON.stringify(activeTemplate.edges));

      const isEcommerce = activeTemplate.id === 'ecommerce';
      const rootNode = freshNodes[0];
      const computeNode = freshNodes[1];
      const dbNode = freshNodes[freshNodes.length - 1];

      const startLog: TelemetryEvent = {
        id: `sim-start-${Date.now()}`,
        timestamp: getTimestamp(),
        step: 'INGRESS_DISCOVERY',
        severity: 'INFO',
        targetNodeId: rootNode.id,
        targetIp: rootNode.ipAddress || '0.0.0.0',
        message: `[INGRESS_DISCOVERY] Ingress edge evaluated: ${rootNode.label || rootNode.name} (${rootNode.ipAddress || '0.0.0.0'}:443 -> ACCEPT).`,
      };

      set({
        nodes: freshNodes,
        edges: freshEdges,
        simulationStatus: 'RUNNING',
        simulationState: 'RUNNING',
        activePatch: null,
        isPatchApplied: false,
        remediationStatus: 'IDLE',
        riskScore: 15,
        simulationProgress: 10,
        logs: [...get().logs, startLog],
        eventLogs: [...get().eventLogs, startLog],
      });

      // TIMEOUT 1 (1.0s): Port Evaluation & Probe Compute Node
      const t1 = setTimeout(() => {
        set((state) => {
          const updatedNodes = state.nodes.map((n) =>
            n.id === computeNode.id ? { ...n, status: 'probing' as NodeStatus } : n
          );
          const updatedEdges = state.edges.map((e, idx) =>
            idx === 0 ? { ...e, isTraversed: true } : e
          );

          const log: TelemetryEvent = {
            id: `step-1-${Date.now()}`,
            timestamp: getTimestamp(),
            step: 'PORT_EVALUATION',
            severity: 'WARN',
            targetNodeId: computeNode.id,
            targetIp: computeNode.ipAddress || '0.0.0.0',
            message: `[PORT_EVALUATION] Probing ${computeNode.label || computeNode.name} (${computeNode.ipAddress || '0.0.0.0'}). Service: ${computeNode.services?.[0]?.serviceName} (${computeNode.services?.[0]?.version}) detected.`,
          };

          return {
            nodes: updatedNodes,
            edges: updatedEdges,
            simulationProgress: 35,
            riskScore: 42,
            logs: [...state.logs, log],
            eventLogs: [...state.eventLogs, log],
          };
        });
      }, 1000);
      activeTimers.push(t1);

      // TIMEOUT 2 (2.5s): Exploit Verified on Compute Tier
      const t2 = setTimeout(() => {
        set((state) => {
          const updatedNodes = state.nodes.map((n) =>
            n.id === computeNode.id ? { ...n, status: 'compromised' as NodeStatus } : n
          );

          const log: TelemetryEvent = {
            id: `step-2-${Date.now()}`,
            timestamp: getTimestamp(),
            step: 'EXPLOIT_VERIFIED',
            severity: 'CRIT',
            targetNodeId: computeNode.id,
            targetIp: computeNode.ipAddress || '0.0.0.0',
            message: `[EXPLOIT_VERIFIED] ${computeNode.cve || 'CVE-2024-21338'} confirmed reachable. Ingress validation succeeded. Remote code execution simulated.`,
          };

          return {
            nodes: updatedNodes,
            simulationProgress: 60,
            riskScore: 68,
            logs: [...state.logs, log],
            eventLogs: [...state.eventLogs, log],
          };
        });
      }, 2500);
      activeTimers.push(t2);

      // TIMEOUT 3 (4.0s): Lateral Pivot Evaluation
      const t3 = setTimeout(() => {
        set((state) => {
          const updatedEdges = state.edges.map((e) =>
            e.target === dbNode.id ? { ...e, isTraversed: true } : e
          );
          const updatedNodes = state.nodes.map((n) =>
            n.id === dbNode.id ? { ...n, status: 'probing' as NodeStatus } : n
          );

          const log1: TelemetryEvent = {
            id: `step-3a-${Date.now()}`,
            timestamp: getTimestamp(),
            step: 'LATERAL_PIVOT',
            severity: 'WARN',
            targetNodeId: dbNode.id,
            targetIp: dbNode.ipAddress || '0.0.0.0',
            message: `[LATERAL_PIVOT] Evaluating internal firewall edge: ${computeNode.label || computeNode.name} -> ${dbNode.label || dbNode.name}.`,
          };

          const log2: TelemetryEvent = {
            id: `step-3b-${Date.now()}`,
            timestamp: getTimestamp(),
            step: 'EXPLOIT_VERIFIED',
            severity: 'CRIT',
            targetNodeId: dbNode.id,
            targetIp: dbNode.ipAddress || '0.0.0.0',
            message: `[EXPLOIT_VERIFIED] Edge policy permissive (Port ${isEcommerce ? 5432 : 27017} unsegmented). Lateral pivot successful.`,
          };

          return {
            edges: updatedEdges,
            nodes: updatedNodes,
            simulationProgress: 80,
            riskScore: 82,
            logs: [...state.logs, log1, log2],
            eventLogs: [...state.eventLogs, log1, log2],
          };
        });
      }, 4000);
      activeTimers.push(t3);

      // TIMEOUT 4 (5.5s): Blast Radius Established & Simulation Completed
      const t4 = setTimeout(() => {
        set((state) => {
          const updatedNodes = state.nodes.map((n) =>
            n.id === dbNode.id ? { ...n, status: 'compromised' as NodeStatus } : n
          );

          // Calculate Blast Radius compound risk score:
          // R = min(100, sum(Ci * 8) + log10(D + 1) * 5 - (Path Length * 2))
          const compromised = updatedNodes.filter((n) => n.status === 'compromised');
          const sumCriticality = compromised.reduce((acc, n) => acc + (n.criticality || 5), 0);
          const syntheticRecords = dbNode.syntheticRecordsCount || 50000;
          const logRecords = Math.log10(syntheticRecords + 1) * 5;
          const pathLength = 2;
          const calculatedScore = Math.min(
            100,
            Math.round(sumCriticality * 8 + logRecords - pathLength * 2)
          );

          const log1: TelemetryEvent = {
            id: `step-4a-${Date.now()}`,
            timestamp: getTimestamp(),
            step: 'BLAST_RADIUS_ESTABLISHED',
            severity: 'CRIT',
            targetNodeId: dbNode.id,
            targetIp: dbNode.ipAddress || '0.0.0.0',
            message: `[BLAST_RADIUS_ESTABLISHED] Node [${dbNode.label || dbNode.name}] compromised. ${syntheticRecords.toLocaleString()} synthetic records exposed.`,
          };

          const log2: TelemetryEvent = {
            id: `step-4b-${Date.now()}`,
            timestamp: getTimestamp(),
            step: 'BLAST_RADIUS_ESTABLISHED',
            severity: 'INFO',
            targetNodeId: 'summary',
            targetIp: '0.0.0.0',
            message: `[COMPLETED] Adversarial simulation complete. Compound Risk Score: ${calculatedScore}/100 [CRITICAL]. Remediation patch prepared.`,
          };

          return {
            nodes: updatedNodes,
            simulationStatus: 'COMPLETED',
            simulationState: 'COMPLETED',
            simulationProgress: 100,
            riskScore: calculatedScore,
            activePatch: activeTemplate.patch,
            logs: [...state.logs, log1, log2],
            eventLogs: [...state.eventLogs, log1, log2],
          };
        });
      }, 5500);
      activeTimers.push(t4);
    },

    runSimulation: () => {
      get().runValidation();
    },

    applyRemediation: (edgeId?: string) => {
      const { activePatch, nodes, edges } = get();
      if (!activePatch) return;

      const targetEdge = edgeId || activePatch.targetEdgeId;

      // Close the permissive edge
      const updatedEdges = edges.map((e) =>
        e.id === targetEdge || e.target === activePatch.targetNodeId
          ? { ...e, accessState: 'blocked' as const, isTraversed: false }
          : e
      );

      // Set target node to 'patched'
      const updatedNodes = nodes.map((node) => {
        if (node.id === activePatch.targetNodeId || node.status === 'compromised') {
          return { ...node, status: 'patched' as NodeStatus };
        }
        return node;
      });

      const patchLog1: TelemetryEvent = {
        id: `patch-${Date.now()}-1`,
        timestamp: getTimestamp(),
        step: 'LATERAL_PIVOT',
        severity: 'INFO',
        targetNodeId: activePatch.targetNodeId,
        targetIp: '0.0.0.0',
        message: `[AEV_REMEDIATION] Applying infrastructure rule: "${activePatch.machineAction}" to digital twin edge [${targetEdge}]. Edge closed.`,
      };

      const patchLog2: TelemetryEvent = {
        id: `patch-${Date.now()}-2`,
        timestamp: getTimestamp(),
        step: 'EXPLOIT_VERIFIED',
        severity: 'SUCCESS',
        targetNodeId: activePatch.targetNodeId,
        targetIp: '0.0.0.0',
        message: `[SUCCESS] Lateral path severed. Autonomous verification re-test passed: Port restricted. Blast radius neutralized. Node status: PATCHED. Status: VERIFIED_SAFE.`,
      };

      set((state) => ({
        nodes: updatedNodes,
        edges: updatedEdges,
        isPatchApplied: true,
        remediationStatus: 'VERIFIED_SAFE',
        riskScore: 12,
        logs: [...state.logs, patchLog1, patchLog2],
        eventLogs: [...state.eventLogs, patchLog1, patchLog2],
      }));
    },

    applyPatch: () => {
      get().applyRemediation();
    },

    clearLogs: () => {
      const clearLog: TelemetryEvent = {
        id: `clear-${Date.now()}`,
        timestamp: getTimestamp(),
        step: 'INGRESS_DISCOVERY',
        severity: 'INFO',
        targetNodeId: 'admin',
        targetIp: '127.0.0.1',
        message: `[ADMIN] Execution audit logs cleared by developer clearance session.`,
      };
      set({
        logs: [clearLog],
        eventLogs: [clearLog],
      });
    },

    injectNode: (customNode) => {
      const existing = get().nodes;
      const count = existing.length + 1;
      const newNode: TwinNodeData = {
        id: customNode?.id || `node-worker-${count}`,
        label: customNode?.label || `Kube-Worker-0${count}`,
        name: customNode?.name || `Kube-Worker-0${count}`,
        type: customNode?.type || 'compute',
        status: customNode?.status || 'healthy',
        ipAddress: customNode?.ipAddress || `10.0.9.${10 + count}`,
        subnet: '10.0.9.0/24 (Dynamic Injected)',
        os: 'Linux Alpine Container',
        port: 6443,
        services: [
          {
            port: 6443,
            protocol: 'TCP',
            serviceName: 'Kubelet Debug Port',
            version: '1.28.2',
            cve: 'CVE-2024-10221',
            vulnerable: true,
          },
        ],
        criticality: 6,
        cve: 'CVE-2024-10221',
        cvss: 8.8,
        description: 'Developer Injected Micro-Container Node via Admin Override drawer.',
        position: customNode?.position || { x: 340 + count * 20, y: 300 },
      };

      const newEdge: TwinEdgeData = {
        id: `edge-dev-${Date.now()}`,
        source: existing[0]?.id || 'node-ingress-alb',
        target: newNode.id,
        allowedPorts: [6443],
        protocol: 'TCP',
        accessState: 'open',
        isTraversed: false,
        label: 'Debug Bridge :6443',
      };

      const injectLog: TelemetryEvent = {
        id: `inject-${Date.now()}`,
        timestamp: getTimestamp(),
        step: 'INGRESS_DISCOVERY',
        severity: 'WARN',
        targetNodeId: newNode.id,
        targetIp: newNode.ipAddress || '0.0.0.0',
        message: `[ADMIN_OVERRIDE] Injected synthetic asset "${newNode.label || newNode.name}" (${newNode.ipAddress || '0.0.0.0'}:6443) into active topology.`,
      };

      set((state) => ({
        nodes: [...state.nodes, newNode],
        edges: [...state.edges, newEdge],
        logs: [...state.logs, injectLog],
        eventLogs: [...state.eventLogs, injectLog],
      }));
    },

    forceAllStatus: (status: NodeStatus) => {
      set((state) => {
        const updated = state.nodes.map((n) => ({ ...n, status }));
        const forceLog: TelemetryEvent = {
          id: `force-${Date.now()}`,
          timestamp: getTimestamp(),
          step: 'PORT_EVALUATION',
          severity: status === 'compromised' ? 'CRIT' : 'INFO',
          targetNodeId: 'all',
          targetIp: '0.0.0.0',
          message: `[ADMIN_OVERRIDE] Forced all topology node statuses to "${status.toUpperCase()}".`,
        };
        return {
          nodes: updated,
          logs: [...state.logs, forceLog],
          eventLogs: [...state.eventLogs, forceLog],
        };
      });
    },
  };
});
