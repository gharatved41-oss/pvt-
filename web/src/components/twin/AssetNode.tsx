'use client';

import React, { memo } from 'react';
import { Handle, Position, NodeProps } from '@xyflow/react';
import { Server, Database, Shield, Cpu, Radio } from 'lucide-react';
import { TwinNodeData, NodeType, NodeStatus } from '@/lib/mockData';

export type AssetNodeData = TwinNodeData;

const ASSET_ICONS: Record<NodeType, React.ElementType> = {
  ingress: Radio,
  load_balancer: Cpu,
  compute: Server,
  server: Server,
  database: Database,
  iam_role: Shield,
  firewall: Shield,
};

export const AssetNode = memo(({ data, selected }: NodeProps) => {
  const node = data as unknown as TwinNodeData;
  const IconComponent = ASSET_ICONS[node.type] || Server;

  const getStatusConfig = (status: NodeStatus) => {
    switch (status) {
      case 'probing':
      case 'scanning':
        return {
          border: 'border-amber-500',
          bg: 'bg-amber-950/20',
          badgeText: 'PROBING',
          badgeClass: 'bg-amber-950 text-amber-400 border-amber-700/80',
          indicator: 'bg-amber-400 animate-pulse',
        };
      case 'compromised':
        return {
          border: 'border-red-500',
          bg: 'bg-red-950/20',
          badgeText: 'COMPROMISED',
          badgeClass: 'bg-red-950 text-red-400 border-red-700/80',
          indicator: 'bg-red-500 animate-ping',
        };
      case 'patched':
        return {
          border: 'border-emerald-500',
          bg: 'bg-emerald-950/20',
          badgeText: 'PATCHED',
          badgeClass: 'bg-emerald-950 text-emerald-400 border-emerald-700/80',
          indicator: 'bg-emerald-400',
        };
      case 'healthy':
      case 'safe':
      case 'idle':
      default:
        return {
          border: 'border-zinc-700',
          bg: 'bg-zinc-950',
          badgeText: 'HEALTHY',
          badgeClass: 'bg-zinc-900 text-zinc-400 border-zinc-700',
          indicator: 'bg-zinc-500',
        };
    }
  };

  const statusConfig = getStatusConfig(node.status);

  return (
    <div
      className={`w-64 rounded-md border text-zinc-100 p-3 select-none font-sans relative transition-all duration-200 ${
        statusConfig.border
      } ${statusConfig.bg} ${selected ? 'ring-1 ring-zinc-400' : ''}`}
    >
      {/* React Flow Handles */}
      <Handle
        type="target"
        position={Position.Top}
        className="w-2.5 h-2.5 !bg-zinc-600 border !border-zinc-950 rounded-full"
      />
      <Handle
        type="source"
        position={Position.Bottom}
        className="w-2.5 h-2.5 !bg-zinc-600 border !border-zinc-950 rounded-full"
      />

      {/* Header: Icon, Label & Status Badge */}
      <div className="flex items-start justify-between gap-2 mb-2">
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded bg-zinc-900 border border-zinc-800 text-zinc-200">
            <IconComponent className="w-4 h-4" />
          </div>
          <div>
            <div className="text-xs font-semibold text-zinc-100 tracking-tight leading-none">
              {node.label || node.name}
            </div>
            <div className="text-[10px] font-mono text-zinc-500 mt-0.5">
              ID: {node.id}
            </div>
          </div>
        </div>

        <span
          className={`px-1.5 py-0.5 text-[9px] font-mono font-bold rounded border uppercase tracking-wider flex items-center gap-1 ${statusConfig.badgeClass}`}
        >
          <span className={`w-1.5 h-1.5 rounded-full ${statusConfig.indicator}`} />
          {statusConfig.badgeText}
        </span>
      </div>

      {/* Node Metadata (IP, Criticality, Vulnerabilities) */}
      <div className="pt-2 border-t border-zinc-800/80 space-y-1 text-[11px] font-mono">
        <div className="flex items-center justify-between text-zinc-400">
          <span className="text-zinc-500">IP ADDRESS:</span>
          <span className="text-zinc-200">{node.ipAddress || node.ip || '0.0.0.0'}</span>
        </div>
        <div className="flex items-center justify-between text-zinc-400">
          <span className="text-zinc-500">CRITICALITY:</span>
          <span className="text-amber-400">{node.criticality || 5} / 10</span>
        </div>
        {node.services && node.services.length > 0 && (
          <div className="flex items-center justify-between text-zinc-400">
            <span className="text-zinc-500">SERVICE:</span>
            <span className="truncate max-w-[120px] text-zinc-300">
              {node.services[0].serviceName} :{node.services[0].port}
            </span>
          </div>
        )}
        {node.cve && (
          <div className="flex items-center justify-between text-zinc-400">
            <span className="text-zinc-500">EXPOSURE:</span>
            <span className="text-red-400 truncate max-w-[120px]">{node.cve}</span>
          </div>
        )}
      </div>
    </div>
  );
});

AssetNode.displayName = 'AssetNode';
