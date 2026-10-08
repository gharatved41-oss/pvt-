'use client';

import React, { useMemo, useCallback } from 'react';
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  Node,
  Edge,
  useNodesState,
  useEdgesState,
  BackgroundVariant,
  MarkerType,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';

import { AssetNode, AssetNodeData } from './AssetNode';
import { useDigitalTwinGraph } from '@/hooks/useDigitalTwinGraph';
import { TwinNode, TwinEdge } from '@/types';

const nodeTypes = {
  assetNode: AssetNode,
};

export interface AttackGraphProps {
  twinId: string | null;
  activePathNodeIds?: string[];
  activeTraversedEdgeIds?: string[];
  onNodeClick?: (nodeId: string) => void;
  className?: string;
}

// Automatic tiered layout computation for cloud infrastructure graphs
function computeLayoutPositions(nodes: TwinNode[]): Map<string, { x: number; y: number }> {
  const positions = new Map<string, { x: number; y: number }>();

  // Partition into logical tiers
  const ingressTier: TwinNode[] = [];
  const computeTier: TwinNode[] = [];
  const databaseTier: TwinNode[] = [];

  for (const node of nodes) {
    if (node.type === 'firewall' || node.type === 'load_balancer') {
      ingressTier.push(node);
    } else if (node.type === 'database') {
      databaseTier.push(node);
    } else {
      computeTier.push(node);
    }
  }

  // Column X coordinates: Ingress (80), Compute (440), Database (800)
  const xTiers = [80, 440, 800];
  const tiers = [ingressTier, computeTier, databaseTier];

  tiers.forEach((tierNodes, tierIdx) => {
    const x = xTiers[tierIdx];
    const total = tierNodes.length;
    const spacingY = 160;
    const startY = Math.max(60, 260 - ((total * spacingY) / 2));

    tierNodes.forEach((node, nodeIdx) => {
      positions.set(node.id, {
        x,
        y: startY + nodeIdx * spacingY,
      });
    });
  });

  return positions;
}

export function AttackGraph({
  twinId,
  activePathNodeIds = [],
  activeTraversedEdgeIds = [],
  onNodeClick,
  className,
}: AttackGraphProps) {
  // Live reactive data from Module 3 Firestore listener hook
  const { nodes: liveNodes, edges: liveEdges, loading, error } = useDigitalTwinGraph(twinId);

  // Compute node coordinates
  const positions = useMemo(() => computeLayoutPositions(liveNodes), [liveNodes]);

  // Transform Firestore nodes into React Flow Node objects
  const flowNodes: Node[] = useMemo(() => {
    return liveNodes.map((node) => {
      const pos = positions.get(node.id) || { x: 250, y: 150 };
      const isTargeted = activePathNodeIds.includes(node.id);
      let runtimeStatus = node.status;
      if (node.status === 'healthy' && isTargeted) {
        runtimeStatus = 'targeted' as typeof node.status;
      }

      const nodeData: AssetNodeData = {
        id: node.id,
        name: node.name,
        type: node.type,
        status: runtimeStatus as AssetNodeData['status'],
        ipAddress: node.properties.ipAddress,
        hostname: node.properties.hostname,
        openPorts: node.properties.openPorts,
        softwareStack: node.properties.softwareStack,
        cveExposures: node.properties.cveExposures,
        syntheticRecordsCount: node.properties.syntheticRecordsCount,
      };

      return {
        id: node.id,
        type: 'assetNode',
        position: pos,
        data: nodeData,
      };
    });
  }, [liveNodes, positions, activePathNodeIds]);

  // Transform Firestore edges into React Flow Edge objects
  const flowEdges: Edge[] = useMemo(() => {
    return liveEdges.map((edge) => {
      const isTraversed = activeTraversedEdgeIds.includes(edge.id) || (
        activePathNodeIds.includes(edge.sourceNodeId) &&
        activePathNodeIds.includes(edge.targetNodeId)
      );

      const label = `${edge.protocol} ${edge.port}`;

      if (isTraversed) {
        return {
          id: edge.id,
          source: edge.sourceNodeId,
          target: edge.targetNodeId,
          animated: true,
          label,
          labelStyle: { fill: '#f87171', fontFamily: 'monospace', fontSize: 10, fontWeight: 700 },
          labelBgStyle: { fill: '#450a0a', stroke: '#ef4444', strokeWidth: 1 },
          labelBgPadding: [4, 2] as [number, number],
          labelBgBorderRadius: 2,
          style: {
            stroke: '#ef4444', // Crimson active attack stroke
            strokeWidth: 2,
            strokeDasharray: '5,5',
          },
          markerEnd: {
            type: MarkerType.ArrowClosed,
            color: '#ef4444',
            width: 16,
            height: 16,
          },
        };
      }

      // Base non-traversed enterprise state
      return {
        id: edge.id,
        source: edge.sourceNodeId,
        target: edge.targetNodeId,
        label,
        labelStyle: { fill: '#a1a1aa', fontFamily: 'monospace', fontSize: 10 },
        labelBgStyle: { fill: '#18181b', stroke: '#27272a', strokeWidth: 1 },
        labelBgPadding: [4, 2] as [number, number],
        labelBgBorderRadius: 2,
        style: {
          stroke: '#3f3f46', // Zinc-700 1px solid stroke
          strokeWidth: 1.5,
        },
        markerEnd: {
          type: MarkerType.ArrowClosed,
          color: '#71717a',
          width: 14,
          height: 14,
        },
      };
    });
  }, [liveEdges, activeTraversedEdgeIds, activePathNodeIds]);

  const [nodes, setNodes, onNodesChange] = useNodesState(flowNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(flowEdges);

  // Sync internal state when Firestore snapshot arrives
  React.useEffect(() => {
    setNodes(flowNodes);
  }, [flowNodes, setNodes]);

  React.useEffect(() => {
    setEdges(flowEdges);
  }, [flowEdges, setEdges]);

  const handleNodeClick = useCallback(
    (_: React.MouseEvent, node: Node) => {
      if (onNodeClick) onNodeClick(node.id);
    },
    [onNodeClick]
  );

  if (loading && flowNodes.length === 0) {
    return (
      <div className="w-full h-full min-h-[460px] rounded-md border border-zinc-800 bg-zinc-950 flex items-center justify-center font-mono text-xs text-zinc-500">
        Loading Digital Twin Graph Topology...
      </div>
    );
  }

  if (error) {
    return (
      <div className="w-full h-full min-h-[460px] rounded-md border border-red-900/60 bg-zinc-950 flex items-center justify-center font-mono text-xs text-red-400">
        Error loading twin topology: {error}
      </div>
    );
  }

  return (
    <div className={`w-full h-full min-h-[480px] rounded-md border border-zinc-800 bg-zinc-950 relative overflow-hidden ${className || ''}`}>
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onNodeClick={handleNodeClick}
        nodeTypes={nodeTypes}
        fitView
        fitViewOptions={{ padding: 0.2 }}
        minZoom={0.4}
        maxZoom={1.5}
        proOptions={{ hideAttribution: true }}
      >
        <Background 
          color="#27272a" 
          gap={20} 
          size={1} 
          variant={BackgroundVariant.Dots} 
        />
        <Controls 
          className="!bg-zinc-900 !border-zinc-800 !rounded-md [&>button]:!bg-zinc-900 [&>button]:!border-zinc-800 [&>button]:!text-zinc-300 [&>button:hover]:!bg-zinc-800"
        />
        <MiniMap 
          className="!bg-zinc-950 !border-zinc-800 !rounded-md"
          nodeColor={(n) => {
            const status = (n.data as unknown as AssetNodeData)?.status;
            if (status === 'compromised') return '#ef4444';
            if (status === 'targeted') return '#f59e0b';
            if (status === 'patched') return '#10b981';
            return '#3f3f46';
          }}
          maskColor="rgba(9, 9, 11, 0.7)"
        />
      </ReactFlow>

      {/* Canvas Top Bar Overlay */}
      <div className="absolute top-3 left-3 z-10 pointer-events-none">
        <div className="flex items-center gap-2 px-2.5 py-1 rounded-sm border border-zinc-800 bg-zinc-950/90 text-[11px] font-mono text-zinc-300">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
          <span>Interactive Attack Graph: {liveNodes.length} Assets | {liveEdges.length} Edges</span>
        </div>
      </div>
    </div>
  );
}
