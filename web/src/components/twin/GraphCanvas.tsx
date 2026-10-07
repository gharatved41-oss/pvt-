'use client';

import React, { useMemo, memo } from 'react';
import {
  ReactFlow,
  Background,
  Controls,
  MarkerType,
  Node as FlowNode,
  Edge as FlowEdge,
  Handle,
  Position,
  NodeProps,
  ConnectionMode,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { useTwinEngine, Node as EngineNode, NodeStatus } from '@/store/useTwinEngine';

interface AustereNodeData {
  node: EngineNode;
  [key: string]: unknown;
}

/**
 * Austere Node Component
 * - Pure dark mode: bg-zinc-950, border-zinc-800
 * - If compromised: border-red-500
 * - If patched: border-emerald-500
 * - If probing: border-amber-500
 */
const AustereNode = memo(({ data, selected }: NodeProps) => {
  const node = (data as unknown as AustereNodeData).node;

  const getBorderColor = (status: NodeStatus) => {
    switch (status) {
      case 'compromised':
        return 'border-red-500 text-red-400';
      case 'patched':
        return 'border-emerald-500 text-emerald-400';
      case 'probing':
        return 'border-amber-500 text-amber-400';
      case 'healthy':
      default:
        return 'border-zinc-800 text-zinc-300';
    }
  };

  const getStatusBadge = (status: NodeStatus) => {
    switch (status) {
      case 'compromised':
        return <span className="text-red-500 font-bold">[COMPROMISED]</span>;
      case 'patched':
        return <span className="text-emerald-400 font-bold">[PATCHED]</span>;
      case 'probing':
        return <span className="text-amber-400 font-bold animate-pulse">[PROBING]</span>;
      case 'healthy':
      default:
        return <span className="text-zinc-500">[HEALTHY]</span>;
    }
  };

  const statusClass = getBorderColor(node.status);

  return (
    <div
      className={`w-64 bg-zinc-950 border ${statusClass} rounded-none p-3.5 font-mono select-none transition-colors duration-150 ${
        selected ? 'ring-1 ring-zinc-400' : ''
      }`}
    >
      <Handle
        type="target"
        position={Position.Top}
        className="w-2 h-2 !bg-zinc-700 !border !border-zinc-950 rounded-none"
      />
      <Handle
        type="source"
        position={Position.Bottom}
        className="w-2 h-2 !bg-zinc-700 !border !border-zinc-950 rounded-none"
      />

      <div className="flex items-center justify-between pb-2 mb-2 border-b border-zinc-900 text-[10px]">
        <span className="text-zinc-500 uppercase tracking-widest">{node.type}</span>
        {getStatusBadge(node.status)}
      </div>

      <div className="text-xs font-bold text-zinc-100 uppercase tracking-tight mb-2">
        {node.label}
      </div>

      <div className="space-y-1 text-[11px] text-zinc-400">
        <div className="flex justify-between">
          <span className="text-zinc-600">IP:</span>
          <span className="text-zinc-200">{node.ip}</span>
        </div>
        <div className="flex justify-between">
          <span className="text-zinc-600">CRITICALITY:</span>
          <span className="text-amber-400 font-bold">{node.criticality}/10</span>
        </div>
        {node.cve && (
          <div className="flex justify-between">
            <span className="text-zinc-600">VULN:</span>
            <span className="text-red-400 font-bold">{node.cve}</span>
          </div>
        )}
      </div>
    </div>
  );
});

AustereNode.displayName = 'AustereNode';

const nodeTypes = {
  austereNode: AustereNode,
};

export function GraphCanvas() {
  const { nodes: engineNodes, edges: engineEdges, selectNode } = useTwinEngine();

  // Map Zustand nodes into React Flow format
  const flowNodes: FlowNode[] = useMemo(() => {
    return engineNodes.map((node) => ({
      id: node.id,
      type: 'austereNode',
      position: node.position || { x: 100, y: 100 },
      data: { node } as AustereNodeData,
    }));
  }, [engineNodes]);

  // Map Zustand edges into React Flow format
  const flowEdges: FlowEdge[] = useMemo(() => {
    return engineEdges.map((edge) => {
      const isBlocked = edge.accessState === 'blocked';
      const isTraversed = edge.isTraversed;

      let strokeColor = '#27272a'; // zinc-800
      if (isBlocked) strokeColor = '#52525b'; // zinc-600
      else if (isTraversed) strokeColor = '#ef4444'; // red-500

      return {
        id: edge.id,
        source: edge.source,
        target: edge.target,
        animated: isTraversed && !isBlocked,
        label: isBlocked ? `BLOCKED :${edge.port}` : `:${edge.port}`,
        labelStyle: {
          fill: isBlocked ? '#71717a' : isTraversed ? '#f87171' : '#a1a1aa',
          fontWeight: 700,
          fontSize: '10px',
          fontFamily: 'monospace',
        },
        labelBgStyle: {
          fill: '#09090b',
          stroke: isBlocked ? '#3f3f46' : isTraversed ? '#7f1d1d' : '#27272a',
          strokeWidth: 1,
        },
        style: {
          stroke: strokeColor,
          strokeWidth: isTraversed ? 2 : 1.5,
          strokeDasharray: isBlocked ? '4 4' : undefined,
        },
        markerEnd: {
          type: MarkerType.ArrowClosed,
          color: strokeColor,
          width: 12,
          height: 12,
        },
      };
    });
  }, [engineEdges]);

  return (
    <div className="w-full h-full relative bg-zinc-950 flex flex-col min-h-0 select-none">
      <ReactFlow
        nodes={flowNodes}
        edges={flowEdges}
        nodeTypes={nodeTypes}
        onNodeClick={(_, node) => selectNode(node.id)}
        onPaneClick={() => selectNode(null)}
        connectionMode={ConnectionMode.Loose}
        fitView
        fitViewOptions={{ padding: 0.25 }}
        minZoom={0.4}
        maxZoom={1.5}
        proOptions={{ hideAttribution: true }}
        className="bg-zinc-950"
      >
        <Background color="#18181b" gap={20} size={1} />
        <Controls
          showInteractive={false}
          className="!bg-zinc-950 !border-zinc-800 !rounded-none !text-zinc-400 [&>button]:!border-zinc-800 [&>button]:!bg-zinc-950 [&>button:hover]:!bg-zinc-900"
        />
      </ReactFlow>
    </div>
  );
}
