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
import { runThreatScan, getAiRemediation } from '@/lib/apiClient';
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

      const rootNode = freshNodes[0];
      const targetUrl = `http://${rootNode.ipAddress || '127.0.0.1'}`;

      const startLog: TelemetryEvent = {
        id: `sim-start-${Date.now()}`,
        timestamp: getTimestamp(),
        step: 'INGRESS_DISCOVERY',
        severity: 'INFO',
        targetNodeId: rootNode.id,
        targetIp: rootNode.ipAddress || '0.0.0.0',
        message: `[INGRESS_DISCOVERY] Initiating threat scan against: ${targetUrl}`,
      };

      set({
        nodes: freshNodes,
        edges: freshEdges,
        simulationStatus: 'RUNNING',
        simulationState: 'RUNNING',
        activePatch: null,
        isPatchApplied: false,
        remediationStatus: 'IDLE',
        riskScore: 0,
        simulationProgress: 50,
        logs: [...get().logs, startLog],
        eventLogs: [...get().eventLogs, startLog],
      });

      // Execute actual API call
      const scanResult = await runThreatScan(targetUrl);

      set((state) => {
        const isMalicious = scanResult.verdict === 'MALICIOUS' || scanResult.risk_score >= 75;
        const finalStatus: NodeStatus = isMalicious ? 'compromised' : (scanResult.risk_score >= 25 ? 'probing' : 'healthy');

        const updatedNodes = state.nodes.map((n, idx) =>
          idx > 0 ? { ...n, status: finalStatus } : n
        );
        const updatedEdges = state.edges.map((e) => ({ ...e, isTraversed: true }));

        const resultLog: TelemetryEvent = {
          id: `scan-${Date.now()}`,
          timestamp: getTimestamp(),
          step: 'EXPLOIT_VERIFIED',
          severity: isMalicious ? 'CRIT' : (scanResult.risk_score >= 25 ? 'WARN' : 'INFO'),
          targetNodeId: rootNode.id,
          targetIp: rootNode.ipAddress || '0.0.0.0',
          message: `[SCAN_COMPLETE] Verdict: ${scanResult.verdict} | Score: ${scanResult.risk_score}. Engine: ${scanResult.heuristics_applied ? 'Heuristics' : 'Provider API'}`,
        };

        return {
          nodes: updatedNodes,
          edges: updatedEdges,
          simulationStatus: 'COMPLETED',
          simulationState: 'COMPLETED',
          simulationProgress: 100,
          riskScore: scanResult.risk_score || 0,
          activePatch: activeTemplate.patch,
          logs: [...state.logs, resultLog],
          eventLogs: [...state.eventLogs, resultLog],
        };
      });
    },

    runSimulation: () => {
      get().runValidation();
    },

    applyRemediation: async (edgeId?: string) => {
      const { activePatch, nodes, edges } = get();
      if (!activePatch) return;

      const targetEdge = edgeId || activePatch.targetEdgeId;
      const targetNode = nodes.find((n) => n.id === activePatch.targetNodeId);

      const patchData = await getAiRemediation(
        targetNode?.cve || 'Generic Vulnerability',
        `Node: ${targetNode?.label || 'Unknown'} IP: ${targetNode?.ipAddress || '0.0.0.0'}`
      );

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
        message: `[AI_REMEDIATION] Applying patch (Source: ${patchData.source}):\n${patchData.patch}\nEdge [${targetEdge}] closed.`,
      };

      const patchLog2: TelemetryEvent = {
        id: `patch-${Date.now()}-2`,
        timestamp: getTimestamp(),
        step: 'EXPLOIT_VERIFIED',
        severity: 'SUCCESS',
        targetNodeId: activePatch.targetNodeId,
        targetIp: '0.0.0.0',
        message: `[SUCCESS] Lateral path severed. Autonomous verification re-test passed. Node status: PATCHED.`,
      };

      set((state) => ({
        nodes: updatedNodes,
        edges: updatedEdges,
        isPatchApplied: true,
        remediationStatus: 'VERIFIED_SAFE',
        riskScore: 0,
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
