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
import { AssetNode } from './AssetNode';

const nodeTypes = {
  assetNode: AssetNode,
};

export function GraphCanvas() {
  const { nodes: twinNodes, edges: twinEdges, selectNode } = useTwinStore();

  // Convert Zustand nodes into XYFlow Node format
  const flowNodes: Node[] = useMemo(() => {
    return twinNodes.map((node) => ({
      id: node.id,
      type: 'assetNode',
      position: node.position || { x: 100, y: 100 },
      data: { ...node },
    }));
  }, [twinNodes]);

  // Convert Zustand edges into XYFlow Edge format with dynamic path states
  const flowEdges: Edge[] = useMemo(() => {
    return twinEdges.map((edge) => {
      const srcNode = twinNodes.find((n) => n.id === edge.source);
      const tgtNode = twinNodes.find((n) => n.id === edge.target);

      const isTraversed = edge.isTraversed;
      const isBlocked = edge.accessState === 'blocked';
      const isCompromised = tgtNode?.status === 'compromised';
      const isPatched = tgtNode?.status === 'patched';

      let strokeColor = '#3f3f46'; // zinc-700
      if (isBlocked) strokeColor = '#71717a'; // zinc-500
      else if (isPatched) strokeColor = '#10b981'; // emerald-500
      else if (isCompromised || isTraversed) strokeColor = '#ef4444'; // red-500
      else if (tgtNode?.status === 'probing') strokeColor = '#f59e0b'; // amber-500

      return {
        id: edge.id,
        source: edge.source,
        target: edge.target,
        animated: isTraversed && !isBlocked && !isPatched,
        label: isBlocked ? 'BLOCKED :5432' : edge.label,
        labelStyle: {
          fill: isBlocked ? '#71717a' : isTraversed ? '#fca5a5' : '#a1a1aa',
          fontWeight: 600,
          fontSize: '10px',
          fontFamily: 'monospace',
        },
        labelBgStyle: {
          fill: '#09090b',
          stroke: isBlocked ? '#3f3f46' : isTraversed ? '#7f1d1d' : '#27272a',
          strokeWidth: 1,
          rx: 4,
          ry: 4,
        },
        style: {
          stroke: strokeColor,
          strokeWidth: isTraversed ? 2.5 : 1.5,
          strokeDasharray: isBlocked ? '4 4' : undefined,
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
        fitViewOptions={{ padding: 0.2 }}
        minZoom={0.4}
        maxZoom={1.5}
        proOptions={{ hideAttribution: true }}
        className="bg-zinc-950"
      >
        <Background color="#27272a" gap={20} size={1} />
        <Controls
          showInteractive={false}
          className="!bg-zinc-900 !border-zinc-800 !rounded !text-zinc-300 [&>button]:!border-zinc-800 [&>button]:!bg-zinc-900 [&>button:hover]:!bg-zinc-800"
        />
      </ReactFlow>
    </div>
  );
}
