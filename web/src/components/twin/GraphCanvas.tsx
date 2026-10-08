"use client";

import React, { useMemo } from 'react';
import { ReactFlow, Background, Controls, NodeProps, Edge, Node, Handle, Position } from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { useTwinStore } from '@/store/useTwinStore';

// Custom Node Component
const CustomNode = ({ data }: NodeProps) => {
  const { label, type, ipAddress, status, services = [] } = data as any;

  let statusStyles = 'border-zinc-800 bg-zinc-900/60';
  if (status === 'probing') statusStyles = 'border-amber-500/80 bg-amber-950/20';
  else if (status === 'compromised') statusStyles = 'border-red-500 bg-red-950/30';
  else if (status === 'patched') statusStyles = 'border-emerald-500 bg-emerald-950/20';

  return (
    <div className={`p-3 min-w-[200px] border font-mono text-xs text-zinc-200 ${statusStyles} rounded-none`}>
      <Handle type="target" position={Position.Top} className="w-2 h-2 rounded-none bg-zinc-500 border-none" />
      <div className="flex justify-between items-center border-b border-zinc-800 pb-2 mb-2">
        <span className="font-bold tracking-wider uppercase">{label || type || 'UNKNOWN'}</span>
        <span className="text-[10px] uppercase px-1.5 py-0.5 bg-zinc-800 text-zinc-300">{status || 'healthy'}</span>
      </div>
      <div className="space-y-1">
        <div className="text-zinc-400">IP: <span className="text-zinc-200">{ipAddress || '0.0.0.0'}</span></div>
        <div className="text-zinc-400 mt-2">Services:</div>
        {services.length > 0 ? (
          <ul className="space-y-0.5">
            {services.map((svc: any, idx: number) => (
              <li key={idx} className="text-[10px] pl-2 border-l border-zinc-700">
                Port {svc.port}: {svc.serviceName}
              </li>
            ))}
          </ul>
        ) : (
          <div className="text-[10px] text-zinc-500 italic pl-2">No services detected</div>
        )}
      </div>
      <Handle type="source" position={Position.Bottom} className="w-2 h-2 rounded-none bg-zinc-500 border-none" />
    </div>
  );
};

const nodeTypes = {
  custom: CustomNode,
};

export default function GraphCanvas() {
  const { nodes, edges } = useTwinStore();

  const flowNodes: Node[] = useMemo(() => {
    return nodes.map((n) => ({
      id: n.id,
      position: n.position || { x: Math.random() * 200, y: Math.random() * 200 },
      data: n,
      type: 'custom',
    }));
  }, [nodes]);

  const flowEdges: Edge[] = useMemo(() => {
    return edges.map((e) => {
      let stroke = '#52525b'; // zinc-600
      let animated = false;
      let strokeDasharray = undefined;

      if (e.isTraversed) {
        stroke = '#ef4444'; // red-500
        animated = true;
      }
      
      if (e.accessState === 'blocked') {
        stroke = '#10b981'; // emerald-500
        animated = false;
        strokeDasharray = '5 5';
      }

      return {
        id: e.id,
        source: e.source,
        target: e.target,
        animated,
        style: { stroke, strokeWidth: 2, strokeDasharray },
      };
    });
  }, [edges]);

  return (
    <div className="w-full h-full min-h-[400px] bg-zinc-950 border border-zinc-800 rounded-none relative">
      <ReactFlow
        nodes={flowNodes}
        edges={flowEdges}
        nodeTypes={nodeTypes}
        fitView
        className="bg-zinc-950"
      >
        <Background color="#27272a" gap={16} />
        <Controls className="fill-zinc-400 border-zinc-800" showInteractive={false} />
      </ReactFlow>
    </div>
  );
}
