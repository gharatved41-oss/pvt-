import { create } from 'zustand';
import { TEMPLATES, TemplateArchitecture, TwinNode, TwinEdge, NodeStatus, RemediationPatch } from '@/lib/mockData';

export type SimulationStatus = 'STOPPED' | 'RUNNING' | 'COMPLETED';

export interface LogEntry {
  id: string;
  timestamp: string;
  text: string;
  level: 'info' | 'warn' | 'crit' | 'success';
}

interface TwinStoreState {
  // Active template & topology
  activeTemplate: TemplateArchitecture;
  nodes: TwinNode[];
  edges: TwinEdge[];
  selectedNode: TwinNode | null;

  // Simulation execution engine
  simulationState: SimulationStatus;
  eventLogs: LogEntry[];
  activePatch: RemediationPatch | null;
  isPatchApplied: boolean;
  simulationProgress: number; // 0 - 100

  // Actions
  loadTemplate: (templateId: string) => void;
  runSimulation: () => void;
  resetSimulation: () => void;
  applyPatch: () => void;
  selectNode: (nodeId: string | null) => void;

  // Developer Admin Overrides
  injectNode: (customNode?: Partial<TwinNode>) => void;
  clearLogs: () => void;
  forceAllStatus: (status: NodeStatus) => void;
}

// Active timeout references for clean cancellation
let activeTimerIds: NodeJS.Timeout[] = [];

const clearTimers = () => {
  activeTimerIds.forEach(id => clearTimeout(id));
  activeTimerIds = [];
};

const getTimestamp = () => {
  const now = new Date();
  return now.toTimeString().split(' ')[0] + '.' + String(now.getMilliseconds()).padStart(3, '0');
};

export const useTwinStore = create<TwinStoreState>((set, get) => {
  const initialTemplate = TEMPLATES.ecommerce;

  return {
    activeTemplate: initialTemplate,
    nodes: JSON.parse(JSON.stringify(initialTemplate.initialNodes)),
    edges: JSON.parse(JSON.stringify(initialTemplate.edges)),
    selectedNode: initialTemplate.initialNodes[0],
    simulationState: 'STOPPED',
    eventLogs: [
      {
        id: 'init-1',
        timestamp: getTimestamp(),
        text: `[SYSTEM] Digital Twin loaded: ${initialTemplate.name}. Environment topology verified (4 nodes, 4 network edges).`,
        level: 'info',
      },
      {
        id: 'init-2',
        timestamp: getTimestamp(),
        text: '[READY] CTEM Autonomous Security Validation Engine initialized. Ready for graph traversal.',
        level: 'info',
      },
    ],
    activePatch: null,
    isPatchApplied: false,
    simulationProgress: 0,

    selectNode: (nodeId: string | null) => {
      if (!nodeId) {
        set({ selectedNode: null });
        return;
      }
      const found = get().nodes.find(n => n.id === nodeId) || null;
      set({ selectedNode: found });
    },

    loadTemplate: (templateId: string) => {
      clearTimers();
      const target = TEMPLATES[templateId] || TEMPLATES.ecommerce;
      const cleanNodes: TwinNode[] = JSON.parse(JSON.stringify(target.initialNodes));
      const cleanEdges: TwinEdge[] = JSON.parse(JSON.stringify(target.edges));

      set({
        activeTemplate: target,
        nodes: cleanNodes,
        edges: cleanEdges,
        selectedNode: cleanNodes[0] || null,
        simulationState: 'STOPPED',
        activePatch: null,
        isPatchApplied: false,
        simulationProgress: 0,
        eventLogs: [
          {
            id: `load-${Date.now()}-1`,
            timestamp: getTimestamp(),
            text: `[SYSTEM] Switched architecture template to "${target.name}".`,
            level: 'info',
          },
          {
            id: `load-${Date.now()}-2`,
            timestamp: getTimestamp(),
            text: `[TOPOLOGY] Ingested ${cleanNodes.length} infrastructure assets and ${cleanEdges.length} active interconnects.`,
            level: 'info',
          },
        ],
      });
    },

    resetSimulation: () => {
      clearTimers();
      const template = get().activeTemplate;
      const cleanNodes: TwinNode[] = JSON.parse(JSON.stringify(template.initialNodes));

      set({
        nodes: cleanNodes,
        simulationState: 'STOPPED',
        activePatch: null,
        isPatchApplied: false,
        simulationProgress: 0,
        eventLogs: [
          {
            id: `reset-${Date.now()}`,
            timestamp: getTimestamp(),
            text: `[RESET] Simulation reset to idle baseline. All node states restored to idle.`,
            level: 'info',
          },
        ],
      });
    },

    runSimulation: () => {
      const { activeTemplate, simulationState } = get();
      if (simulationState === 'RUNNING') return;

      clearTimers();

      // Reset nodes to idle
      const cleanNodes: TwinNode[] = JSON.parse(JSON.stringify(activeTemplate.initialNodes));

      set({
        nodes: cleanNodes,
        simulationState: 'RUNNING',
        activePatch: null,
        isPatchApplied: false,
        simulationProgress: 5,
        eventLogs: [
          {
            id: `sim-start-${Date.now()}`,
            timestamp: getTimestamp(),
            text: `[INIT] Starting CTEM Adversarial Validation on "${activeTemplate.name}" twin...`,
            level: 'info',
          },
        ],
      });

      // Execute programmed simulation steps using setTimeout
      activeTemplate.steps.forEach((step, index) => {
        const timer = setTimeout(() => {
          set(state => {
            // Update node status
            const updatedNodes = state.nodes.map(node => {
              if (node.id === step.targetNodeId) {
                return { ...node, status: step.targetStatus };
              }
              return node;
            });

            // Calculate progress percentage
            const progress = Math.min(
              100,
              Math.round(((index + 1) / activeTemplate.steps.length) * 100)
            );

            const isLast = index === activeTemplate.steps.length - 1;

            return {
              nodes: updatedNodes,
              simulationProgress: progress,
              simulationState: isLast ? 'COMPLETED' : 'RUNNING',
              activePatch: isLast ? activeTemplate.patch : state.activePatch,
              eventLogs: [
                ...state.eventLogs,
                {
                  id: `step-${Date.now()}-${index}`,
                  timestamp: getTimestamp(),
                  text: step.log,
                  level: step.logLevel,
                },
              ],
            };
          });
        }, step.delayMs);

        activeTimerIds.push(timer);
      });
    },

    applyPatch: () => {
      const { activePatch, nodes, activeTemplate } = get();
      if (!activePatch) return;

      // Update the compromised target node to 'patched'
      const updatedNodes = nodes.map(node => {
        if (node.id === activePatch.targetNodeId || node.status === 'compromised') {
          return { ...node, status: 'patched' as NodeStatus };
        }
        return node;
      });

      set(state => ({
        nodes: updatedNodes,
        isPatchApplied: true,
        eventLogs: [
          ...state.eventLogs,
          {
            id: `patch-${Date.now()}-1`,
            timestamp: getTimestamp(),
            text: `[AEV REMEDIATION] Applying machine patch "${activePatch.machineAction}" to digital twin sandbox...`,
            level: 'info',
          },
          {
            id: `patch-${Date.now()}-2`,
            timestamp: getTimestamp(),
            text: `[AEV VERIFICATION] Re-testing traversal path: Target port restricted. Blast radius neutralized. Node status: PATCHED.`,
            level: 'success',
          },
        ],
      }));
    },

    // Developer Admin Overrides
    injectNode: (customNode) => {
      const existing = get().nodes;
      const count = existing.length + 1;
      const newNode: TwinNode = {
        id: customNode?.id || `Kube-Worker-0${count}`,
        name: customNode?.name || `Kube-Worker-0${count}`,
        type: customNode?.type || 'server',
        status: customNode?.status || 'idle',
        ip: customNode?.ip || `10.0.9.${10 + count}`,
        port: customNode?.port || 6443,
        cve: customNode?.cve || 'CVE-2024-10221',
        cvss: customNode?.cvss || 8.8,
        description: customNode?.description || 'Developer Injected Micro-Container Node',
        position: customNode?.position || { x: 320 + (count * 20), y: 40 + (count * 30) },
      };

      const newEdge: TwinEdge = {
        id: `dev-edge-${Date.now()}`,
        source: existing[0]?.id || 'Load-Balancer',
        target: newNode.id,
        label: 'Debug Bridge :6443',
        protocol: 'TCP',
      };

      set(state => ({
        nodes: [...state.nodes, newNode],
        edges: [...state.edges, newEdge],
        eventLogs: [
          ...state.eventLogs,
          {
            id: `inject-${Date.now()}`,
            timestamp: getTimestamp(),
            text: `[ADMIN OVERRIDE] Injected synthetic asset "${newNode.name}" (${newNode.ip}:${newNode.port}) into active graph topology.`,
            level: 'warn',
          },
        ],
      }));
    },

    clearLogs: () => {
      set({
        eventLogs: [
          {
            id: `clear-${Date.now()}`,
            timestamp: getTimestamp(),
            text: `[ADMIN] Execution audit logs cleared by Developer clearance session.`,
            level: 'info',
          },
        ],
      });
    },

    forceAllStatus: (status: NodeStatus) => {
      set(state => ({
        nodes: state.nodes.map(n => ({ ...n, status })),
        eventLogs: [
          ...state.eventLogs,
          {
            id: `force-${Date.now()}`,
            timestamp: getTimestamp(),
            text: `[ADMIN OVERRIDE] Forced all topology node statuses to "${status.toUpperCase()}".`,
            level: status === 'compromised' ? 'crit' : 'info',
          },
        ],
      }));
    },
  };
});
