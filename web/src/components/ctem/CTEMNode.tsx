'use client';

import React, { memo } from 'react';
import { Handle, Position, NodeProps } from '@xyflow/react';
import { Server, Database, Shield, Cpu, AlertTriangle, CheckCircle2, ShieldCheck, Activity } from 'lucide-react';
import { TwinNode, NodeStatus } from '@/lib/mockData';

const NODE_ICONS: Record<string, React.ElementType> = {
  server: Server,
  compute: Server,
  database: Database,
  firewall: Shield,
  iam_role: Shield,
  load_balancer: Cpu,
  ingress: Cpu,
};

export const CTEMNode = memo(({ data }: NodeProps) => {
  const node = data as unknown as TwinNode;
  const IconComponent = NODE_ICONS[node.type] || Server;

  // Status Styling according to Non-Vibecoded Manifesto
  const getStatusStyles = (status: NodeStatus) => {
    switch (status) {
      case 'compromised':
        return {
          cardBorder: 'border-red-500 bg-red-950/20 ring-1 ring-red-500/50',
          badgeClass: 'bg-red-950 border-red-800 text-red-400 font-bold',
          badgeText: 'COMPROMISED',
          indicator: 'bg-red-500 animate-pulse',
        };
      case 'patched':
        return {
          cardBorder: 'border-emerald-500 bg-emerald-950/20 ring-1 ring-emerald-500/50',
          badgeClass: 'bg-emerald-950 border-emerald-800 text-emerald-400 font-bold',
          badgeText: 'PATCHED',
          indicator: 'bg-emerald-500',
        };
      case 'scanning':
        return {
          cardBorder: 'border-amber-500 bg-amber-950/20 ring-1 ring-amber-500/50 animate-pulse',
          badgeClass: 'bg-amber-950 border-amber-800 text-amber-400 font-bold',
          badgeText: 'PROBING',
          indicator: 'bg-amber-400 animate-ping',
        };
      case 'safe':
        return {
          cardBorder: 'border-emerald-500/60 bg-zinc-900',
          badgeClass: 'bg-zinc-800 border-zinc-700 text-emerald-400',
          badgeText: 'ISOLATED',
          indicator: 'bg-emerald-500',
        };
      default:
        return {
          cardBorder: 'border-zinc-800 bg-zinc-900/95 hover:border-zinc-700',
          badgeClass: 'bg-zinc-800/80 border-zinc-700/80 text-zinc-400',
          badgeText: 'IDLE',
          indicator: 'bg-zinc-600',
        };
    }
  };

  const style = getStatusStyles(node.status);

  return (
    <div className={`w-56 rounded-md border p-3 transition-colors shadow-none ${style.cardBorder}`}>
      {/* Node Ingress Handle */}
      <Handle
        type="target"
        position={Position.Left}
        className="!w-2 !h-2 !bg-zinc-600 !border-zinc-800 rounded-none -left-1"
      />

      {/* Node Header */}
      <div className="flex items-start justify-between gap-2 mb-2">
        <div className="flex items-center gap-2 min-w-0">
          <div className="p-1 rounded bg-zinc-800/80 border border-zinc-700/80 text-zinc-300 shrink-0">
            <IconComponent className="w-3.5 h-3.5" />
          </div>
          <div className="min-w-0">
            <div className="text-xs font-semibold text-zinc-100 truncate" title={node.name}>
              {node.name}
            </div>
            <div className="text-[10px] font-mono text-zinc-500 uppercase tracking-wider">
              {node.type}
            </div>
          </div>
        </div>

        {/* Status Badge */}
        <div className={`px-1.5 py-0.5 text-[9px] font-mono border rounded tracking-wider shrink-0 flex items-center gap-1 ${style.badgeClass}`}>
          <span className={`w-1.5 h-1.5 rounded-full ${style.indicator}`} />
          {style.badgeText}
        </div>
      </div>

      {/* Network Attributes */}
      <div className="border-t border-zinc-800/80 pt-2 space-y-1 text-[11px] font-mono">
        <div className="flex justify-between text-zinc-400">
          <span>IP:</span>
          <span className="text-zinc-200">{node.ip}</span>
        </div>
        <div className="flex justify-between text-zinc-400">
          <span>Port:</span>
          <span className="text-zinc-200">:{node.port}</span>
        </div>

        {node.cve && node.cve !== 'N/A' && (
          <div className="flex justify-between items-center text-[10px] pt-1 border-t border-zinc-800/50">
            <span className="text-red-400 truncate max-w-[130px] font-semibold" title={node.cve}>
              {node.cve}
            </span>
            <span className="text-[9px] px-1 rounded bg-red-950/80 text-red-300 border border-red-800/60">
              CVSS {node.cvss != null ? node.cvss.toFixed(1) : '8.5'}
            </span>
          </div>
        )}
      </div>

      {/* Node Egress Handle */}
      <Handle
        type="source"
        position={Position.Right}
        className="!w-2 !h-2 !bg-zinc-600 !border-zinc-800 rounded-none -right-1"
      />
    </div>
  );
});

CTEMNode.displayName = 'CTEMNode';
