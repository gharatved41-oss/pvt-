import { z } from 'zod';
import { FieldValue, Timestamp } from 'firebase-admin/firestore';

// =============================================================================
// 1. ZOD SCHEMAS FOR DIGITAL TWIN GRAPH TOPOLOGY
// =============================================================================

export const NodeTypeSchema = z.enum([
  'server',
  'database',
  'firewall',
  'load_balancer'
]);
export type NodeType = z.infer<typeof NodeTypeSchema>;

export const NodeStatusSchema = z.enum([
  'healthy',
  'compromised',
  'offline'
]);
export type NodeStatus = z.infer<typeof NodeStatusSchema>;

export const NodePropertiesSchema = z.object({
  hostname: z.string().optional(),
  ipAddress: z.string().optional(),
  osVersion: z.string().optional(),
  openPorts: z.array(z.number()).default([]),
  softwareStack: z.array(z.string()).default([]),
  cveExposures: z.array(z.string()).optional(),
  syntheticRecordsCount: z.number().optional(),
  syntheticDataRef: z.string().optional(),
}).passthrough();
export type NodeProperties = z.infer<typeof NodePropertiesSchema>;

export const TwinNodeSchema = z.object({
  id: z.string().min(1),
  name: z.string().optional(),
  type: NodeTypeSchema,
  properties: NodePropertiesSchema,
  status: NodeStatusSchema.default('healthy'),
  compromiseTimestamp: z.any().optional(),
  compromiseVector: z.string().optional(),
  updatedAt: z.any().optional(),
});
export type TwinNode = z.infer<typeof TwinNodeSchema>;

export const EdgeProtocolSchema = z.enum([
  'TCP',
  'UDP',
  'HTTP'
]);
export type EdgeProtocol = z.infer<typeof EdgeProtocolSchema>;

export const EdgeAccessStateSchema = z.enum([
  'open',
  'restricted',
  'blocked'
]);
export type EdgeAccessState = z.infer<typeof EdgeAccessStateSchema>;

export const TwinEdgeSchema = z.object({
  id: z.string().min(1),
  sourceNodeId: z.string().min(1),
  targetNodeId: z.string().min(1),
  protocol: EdgeProtocolSchema,
  port: z.number().int().min(1).max(65535),
  accessState: EdgeAccessStateSchema.default('open'),
  ruleDescription: z.string().optional(),
  updatedAt: z.any().optional(),
});
export type TwinEdge = z.infer<typeof TwinEdgeSchema>;

export const DigitalTwinStatusSchema = z.enum([
  'cloning',
  'synthesizing',
  'ready',
  'simulating',
  'failed'
]);
export type DigitalTwinStatus = z.infer<typeof DigitalTwinStatusSchema>;

export interface DigitalTwinDocument {
  id: string;
  envId: string;
  name?: string;
  targetDomain?: string;
  status: DigitalTwinStatus;
  nodeCount: number;
  edgeCount: number;
  syntheticRecordsGenerated: number;
  createdAt: Timestamp | FieldValue;
  updatedAt: Timestamp | FieldValue;
  lastSimulatedAt?: Timestamp | FieldValue;
}
