'use client';

import React, { useMemo } from 'react';
import {
  ReactFlow,
  Background,
  Controls,
  MarkerType,
  Node,
  Edge,
  ConnectionMode,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { useTwinStore } from '@/store/useTwinStore';
import { CTEMNode } from './CTEMNode';

const nodeTypes = {
  ctemNode: CTEMNode,
};

export function CTEMGraph() {
  const { nodes: twinNodes, edges: twinEdges, selectNode } = useTwinStore();

  // Convert Zustand nodes into XYFlow Node format
  const flowNodes: Node[] = useMemo(() => {
    return twinNodes.map((node) => ({
      id: node.id,
      type: 'ctemNode',
      position: node.position || { x: 100, y: 100 },
      data: { ...node },
    }));
  }, [twinNodes]);

  // Convert Zustand edges into XYFlow Edge format with high-density enterprise styles
  const flowEdges: Edge[] = useMemo(() => {
    return twinEdges.map((edge) => {
      // Find source & target nodes to see if edge is active traversal path
      const srcNode = twinNodes.find((n) => n.id === edge.source);
      const tgtNode = twinNodes.find((n) => n.id === edge.target);

      const isCompromisedPath =
        (srcNode?.status === 'compromised' && tgtNode?.status === 'compromised') ||
        (srcNode?.status === 'compromised' && tgtNode?.status === 'scanning');

      const isPatchedPath = srcNode?.status === 'patched' || tgtNode?.status === 'patched';

      let strokeColor = '#3f3f46'; // zinc-700
      if (isCompromisedPath) strokeColor = '#ef4444'; // red-500
      else if (isPatchedPath) strokeColor = '#10b981'; // emerald-500

      return {
        id: edge.id,
        source: edge.source,
        target: edge.target,
        animated: isCompromisedPath || tgtNode?.status === 'scanning',
        label: edge.label,
        labelStyle: {
          fill: '#a1a1aa', // zinc-400
          fontWeight: 500,
          fontSize: '10px',
          fontFamily: 'monospace',
        },
        labelBgStyle: {
          fill: '#09090b', // zinc-950
          stroke: '#27272a', // zinc-800
          strokeWidth: 1,
          rx: 4,
          ry: 4,
        },
        style: {
          stroke: strokeColor,
          strokeWidth: isCompromisedPath ? 2 : 1.5,
        },
        markerEnd: {
          type: MarkerType.ArrowClosed,
          color: strokeColor,
          width: 14,
          height: 14,
        },
      };
    });
  }, [twinEdges, twinNodes]);

  return (
    <div className="w-full h-full relative bg-zinc-950 flex flex-col min-h-0">
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
        <Background color="#27272a" gap={20} size={1} />
        <Controls
          showInteractive={false}
          className="!bg-zinc-900 !border-zinc-800 !shadow-none !fill-zinc-300 [&>button]:!border-zinc-800 [&>button]:!bg-zinc-900 hover:[&>button]:!bg-zinc-800"
        />
      </ReactFlow>

      {/* Floating Canvas Legend */}
      <div className="absolute top-3 right-3 bg-zinc-900/90 backdrop-blur-xs border border-zinc-800 p-2.5 rounded-md text-[10px] font-mono space-y-1.5 shadow-none pointer-events-none select-none">
        <div className="text-zinc-400 uppercase font-bold tracking-wider mb-1">
          State Legend
        </div>
        <div className="flex items-center gap-2 text-zinc-300">
          <span className="w-2 h-2 rounded-xs border border-zinc-700 bg-zinc-800" />
          <span>Idle / Baseline</span>
        </div>
        <div className="flex items-center gap-2 text-amber-400">
          <span className="w-2 h-2 rounded-xs border border-amber-500 bg-amber-950" />
          <span>Active Probing</span>
        </div>
        <div className="flex items-center gap-2 text-red-400">
          <span className="w-2 h-2 rounded-xs border border-red-500 bg-red-950" />
          <span>Compromised (Exploited)</span>
        </div>
        <div className="flex items-center gap-2 text-emerald-400">
          <span className="w-2 h-2 rounded-xs border border-emerald-500 bg-emerald-950" />
          <span>Patched & Verified</span>
        </div>
      </div>
    </div>
  );
}
