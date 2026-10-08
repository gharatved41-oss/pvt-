import { create } from 'zustand';
import { runThreatScan, getAiRemediation } from '@/lib/apiClient';
import { TEMPLATES, ecommerceTemplate, healthcareTemplate, TwinNodeData, TwinEdgeData, NodeStatus } from '@/lib/mockData';
import { useAuthStore } from './useAuthStore';

export type SimulationStatus = 'IDLE' | 'SCANNING' | 'COMPROMISED' | 'PATCHED' | 'RUNNING' | 'COMPLETED';

interface TwinStoreState {
  // New exact properties per directive
  nodes: TwinNodeData[];
  edges: TwinEdgeData[];
  selectedNode: string | null;
  simulationStatus: SimulationStatus;
  terminalLogs: string[];
  remediationPatch: string | null;
  selectedTemplate: string;
  
  // Kept for backward compatibility with other components
  logs: any[];
  eventLogs: any[];
  riskScore: number;
  activePatch: any | null;
  activeTemplate: any;
  simulationState: SimulationStatus;
  simulationProgress: number;
  isPatchApplied: boolean;
  remediationStatus: string;
  
  // Actions
  setSelectedNode: (id: string | null) => void;
  selectNode: (id: string | null) => void; // alias
  runValidation: (targetUrl: string) => Promise<void>;
  runSimulation: () => void;
  resetSimulation: () => void;
  applyRemediation: () => void;
  applyPatch: () => void;
  loadTemplate: (templateKey: string) => void;
  isolateNode: (nodeId: string) => void;
  clearLogs: () => void;
  injectNode: () => void;
  forceAllStatus: (status: NodeStatus) => void;
}

const getTimestamp = () => new Date().toISOString().split('T')[1].slice(0, 12);

export const useTwinStore = create<TwinStoreState>((set, get) => ({
  nodes: ecommerceTemplate.nodes as TwinNodeData[],
  edges: ecommerceTemplate.edges as TwinEdgeData[],
  selectedNode: null,
  simulationStatus: 'IDLE',
  terminalLogs: [`[${getTimestamp()}] [SYSTEM] Engine initialized. Awaiting commands.`],
  remediationPatch: null,
  selectedTemplate: 'ecommerce',
  
  logs: [],
  eventLogs: [],
  riskScore: 0,
  activePatch: null,
  activeTemplate: ecommerceTemplate,
  simulationState: 'IDLE',
  simulationProgress: 0,
  isPatchApplied: false,
  remediationStatus: 'IDLE',

  setSelectedNode: (id: string | null) => set({ selectedNode: id }),
  selectNode: (id: string | null) => set({ selectedNode: id }),

  runValidation: async (targetUrl: string) => {
    // Check quota
    const authStore = useAuthStore.getState();
    if (authStore.role === 'user' && authStore.scansUsed >= authStore.maxScans) {
      set(state => ({
        terminalLogs: [...state.terminalLogs, `[${getTimestamp()}] [CRIT] Quota Exceeded. Standard Tier execution limit reached. Upgrade to Developer Clearance for unlimited simulations.`]
      }));
      return;
    }

    if (authStore.role === 'user' && authStore.incrementScan) {
      authStore.incrementScan();
    }

    const startLog = `[${getTimestamp()}] [INFO] Initiating deterministic traversal against ${targetUrl}...`;
    set((state) => ({
      simulationStatus: 'SCANNING',
      simulationState: 'RUNNING',
      terminalLogs: [...state.terminalLogs, startLog],
      remediationPatch: null
    }));

    try {
      const scanResult = await runThreatScan(targetUrl);
      
      const isCompromised = scanResult.verdict === 'MALICIOUS' || scanResult.risk_score >= 75;
      
      if (isCompromised) {
        const rootNodeId = get().nodes[0]?.id;
        // Let's assume the traversal hits the next node
        const targetNodeIndex = 1;
        const targetNodeId = get().nodes[targetNodeIndex]?.id;

        const updatedEdges = get().edges.map((e) => 
          e.source === rootNodeId || e.target === targetNodeId ? { ...e, isTraversed: true } : e
        );
        
        const updatedNodes = get().nodes.map((n, idx) => 
          idx === targetNodeIndex ? { ...n, status: 'compromised' as NodeStatus } : n
        );
        
        const critLog = `[${getTimestamp()}] [CRIT] Target compromised! Score: ${scanResult.risk_score}. Fetching AI remediation...`;

        set((state) => ({
          nodes: updatedNodes,
          edges: updatedEdges,
          simulationStatus: 'COMPROMISED',
          simulationState: 'COMPROMISED',
          riskScore: scanResult.risk_score,
          terminalLogs: [...state.terminalLogs, critLog],
          activePatch: { targetNodeId: targetNodeId, targetEdgeId: updatedEdges[0]?.id } // backward compatibility
        }));

        const targetNode = updatedNodes[targetNodeIndex];
        const patchData = await getAiRemediation(
          targetNode?.cve || 'Generic Vulnerability', 
          `Node: ${targetNode?.label} IP: ${targetNode?.ipAddress}`
        );

        set((state) => ({
          remediationPatch: patchData.patch,
          terminalLogs: [...state.terminalLogs, `[${getTimestamp()}] [INFO] AI Remediation synthesis complete.`]
        }));
      } else {
        const safeLog = `[${getTimestamp()}] [SUCCESS] Target secure. Verdict: ${scanResult.verdict}`;
        set((state) => ({
          simulationStatus: 'IDLE',
          riskScore: scanResult.risk_score,
          terminalLogs: [...state.terminalLogs, safeLog]
        }));
      }
    } catch (err: any) {
      set((state) => ({
        simulationStatus: 'IDLE',
        terminalLogs: [...state.terminalLogs, `[${getTimestamp()}] [ERROR] Scan failed: ${err.message}`]
      }));
    }
  },

  runSimulation: () => {
    const rootNode = get().nodes[0];
    const targetUrl = `http://${rootNode?.ipAddress || '127.0.0.1'}`;
    get().runValidation(targetUrl);
  },

  applyRemediation: () => {
    const { remediationPatch, nodes, edges } = get();
    if (!remediationPatch) return;

    const updatedEdges = edges.map((e) => 
      e.isTraversed ? { ...e, isTraversed: false, accessState: 'blocked' as const } : e
    );

    const updatedNodes = nodes.map((n) => 
      n.status === 'compromised' ? { ...n, status: 'patched' as NodeStatus } : n
    );

    const patchLog = `[${getTimestamp()}] [SUCCESS] Remediation applied. Lateral pivot blocked.`;

    set((state) => ({
      nodes: updatedNodes,
      edges: updatedEdges,
      simulationStatus: 'PATCHED',
      riskScore: 0,
      terminalLogs: [...state.terminalLogs, patchLog],
      remediationPatch: null
    }));
  },

  applyPatch: () => {
    get().applyRemediation();
  },

  resetSimulation: () => {
    const template = TEMPLATES[get().selectedTemplate] || ecommerceTemplate;
    get().loadTemplate(template.id);
  },

  loadTemplate: (templateKey: string) => {
    const target = TEMPLATES[templateKey] || (templateKey === 'healthcare' ? healthcareTemplate : ecommerceTemplate);
    const cleanNodes = JSON.parse(JSON.stringify(target.nodes));
    const cleanEdges = JSON.parse(JSON.stringify(target.edges));
    set({
      nodes: cleanNodes,
      edges: cleanEdges,
      selectedNode: null,
      simulationStatus: 'IDLE',
      remediationPatch: null,
      selectedTemplate: target.id,
      riskScore: 0,
      terminalLogs: [`[${getTimestamp()}] [SYSTEM] Switched architecture template to "${target.name}".`]
    });
  },

  isolateNode: (nodeId: string) => {
    const updatedNodes = get().nodes.map((node) => 
      node.id === nodeId ? { ...node, status: 'patched' as NodeStatus } : node
    );
    const updatedEdges = get().edges.map((e) =>
      e.target === nodeId ? { ...e, accessState: 'blocked' as const, isTraversed: false } : e
    );

    set((state) => ({
      nodes: updatedNodes,
      edges: updatedEdges,
      terminalLogs: [...state.terminalLogs, `[${getTimestamp()}] [SUCCESS] Node ${nodeId} manually isolated.`]
    }));
  },

  clearLogs: () => set({ terminalLogs: [] }),
  injectNode: () => {},
  forceAllStatus: (status: NodeStatus) => {}
}));
