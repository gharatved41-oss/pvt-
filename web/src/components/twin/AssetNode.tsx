'use client';

import React, { memo } from 'react';
import { Handle, Position, NodeProps } from '@xyflow/react';
import { 
  Server, 
  Database, 
  Shield, 
  Cpu, 
  AlertOctagon, 
  CheckCircle2, 
  Radio, 
  Lock 
} from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { cn } from '@/lib/utils';
import { NodeType, NodeStatus } from '@/types';

export interface AssetNodeData {
  id: string;
  name?: string;
  type: NodeType;
  status: NodeStatus | 'targeted' | 'patched';
  ipAddress?: string;
  hostname?: string;
  openPorts?: number[];
  softwareStack?: string[];
  cveExposures?: string[];
  syntheticRecordsCount?: number;
  [key: string]: unknown;
}

const ASSET_ICONS: Record<NodeType, React.ElementType> = {
  server: Server,
  database: Database,
  firewall: Shield,
  load_balancer: Cpu,
};

export const AssetNode = memo(({ data, selected }: NodeProps) => {
  const nodeData = data as unknown as AssetNodeData;
  const IconComponent = ASSET_ICONS[nodeData.type] || Server;

  // Status Styling according to Non-Vibecoded Manifesto
  const getStatusStyles = () => {
    switch (nodeData.status) {
      case 'compromised':
        return {
          containerBorder: 'border-red-500/90 bg-red-950/20 shadow-none',
          indicator: 'bg-red-500 animate-pulse',
          badgeText: 'COMPROMISED',
          badgeVariant: 'destructive' as const,
          badgeColor: 'text-red-400 border-red-800/80 bg-red-950/80',
        };
      case 'targeted':
        return {
          containerBorder: 'border-amber-500/90 bg-amber-950/20 shadow-none',
          indicator: 'bg-amber-400 animate-pulse',
          badgeText: 'TARGETED',
          badgeVariant: 'amber' as const,
          badgeColor: 'text-amber-400 border-amber-800/80 bg-amber-950/80',
        };
      case 'patched':
        return {
          containerBorder: 'border-emerald-500/90 bg-emerald-950/20 shadow-none',
          indicator: 'bg-emerald-400',
          badgeText: 'PATCHED',
          badgeVariant: 'emerald' as const,
          badgeColor: 'text-emerald-400 border-emerald-800/80 bg-emerald-950/80',
        };
      case 'healthy':
      default:
        return {
          containerBorder: 'border-zinc-800 bg-zinc-950/90 shadow-none',
          indicator: 'bg-zinc-500',
          badgeText: 'HEALTHY',
          badgeVariant: 'secondary' as const,
          badgeColor: 'text-zinc-400 border-zinc-700 bg-zinc-900',
        };
    }
  };

  const statusStyle = getStatusStyles();

  return (
    <div
      className={cn(
        "w-60 rounded-md border text-zinc-100 transition-all select-none p-3 space-y-2 relative font-sans",
        statusStyle.containerBorder,
        selected && "ring-1 ring-zinc-400 border-zinc-400"
      )}
    >
      {/* React Flow Handles */}
      <Handle
        type="target"
        position={Position.Top}
        className="w-2 h-2 !bg-zinc-600 border !border-zinc-950 rounded-full"
      />
      <Handle
        type="source"
        position={Position.Bottom}
        className="w-2 h-2 !bg-zinc-600 border !border-zinc-950 rounded-full"
      />

      {/* Header: Icon, Node ID & Status Badge */}
      <div className="flex items-center justify-between gap-1.5">
        <div className="flex items-center gap-2 min-w-0">
          <div className="w-6 h-6 rounded-sm bg-zinc-900 border border-zinc-800 flex items-center justify-center shrink-0">
            <IconComponent className="w-3.5 h-3.5 text-zinc-300" />
          </div>
          <span className="font-mono text-xs font-semibold tracking-tight text-zinc-100 truncate" title={nodeData.id}>
            {nodeData.id}
          </span>
        </div>

        <div className="flex items-center gap-1.5 shrink-0">
          <span className={cn("w-1.5 h-1.5 rounded-full", statusStyle.indicator)} />
          <Badge 
            variant={statusStyle.badgeVariant}
            className={cn("text-[9px] font-mono px-1 py-0 h-4 uppercase tracking-wider font-semibold", statusStyle.badgeColor)}
          >
            {statusStyle.badgeText}
          </Badge>
        </div>
      </div>

      {/* Network Metadata & Specs */}
      <div className="border-t border-zinc-800/80 pt-2 space-y-1 text-[11px] font-mono text-zinc-400">
        <div className="flex items-center justify-between">
          <span className="text-zinc-500">IP:</span>
          <span className="text-zinc-300">{nodeData.ipAddress || '10.0.0.0/24'}</span>
        </div>

        {nodeData.openPorts && nodeData.openPorts.length > 0 && (
          <div className="flex items-center justify-between">
            <span className="text-zinc-500">Ports:</span>
            <span className="text-zinc-300">[{nodeData.openPorts.join(', ')}]</span>
          </div>
        )}

        {nodeData.syntheticRecordsCount !== undefined && nodeData.syntheticRecordsCount > 0 && (
          <div className="flex items-center justify-between text-zinc-300">
            <span className="text-zinc-500">Records:</span>
            <span className="text-emerald-400 font-semibold">{nodeData.syntheticRecordsCount.toLocaleString()} fake</span>
          </div>
        )}
      </div>

      {/* CVE / Vulnerability Alert Pill if Compromised */}
      {nodeData.status === 'compromised' && nodeData.cveExposures && nodeData.cveExposures.length > 0 && (
        <div className="pt-1">
          <div className="text-[10px] font-mono text-red-400 bg-red-950/60 border border-red-900/40 rounded px-1.5 py-0.5 flex items-center gap-1 truncate">
            <AlertOctagon className="w-3 h-3 shrink-0" />
            <span className="truncate">{nodeData.cveExposures.join(', ')}</span>
          </div>
        </div>
      )}

      {/* Patched Protection Confirmation Pill */}
      {nodeData.status === 'patched' && (
        <div className="pt-1">
          <div className="text-[10px] font-mono text-emerald-400 bg-emerald-950/60 border border-emerald-900/40 rounded px-1.5 py-0.5 flex items-center gap-1">
            <CheckCircle2 className="w-3 h-3 shrink-0" />
            <span>AEV Verified Secure</span>
          </div>
        </div>
      )}
    </div>
  );
});

AssetNode.displayName = 'AssetNode';
