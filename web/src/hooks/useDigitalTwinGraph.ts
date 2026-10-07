'use client';

import { useState, useEffect, useMemo, useCallback } from 'react';
import { 
  collection, 
  doc, 
  onSnapshot, 
  DocumentData, 
  QuerySnapshot 
} from 'firebase/firestore';
import { httpsCallable } from 'firebase/functions';
import { db, functions } from '@/lib/firebase';
import { 
  TwinNode, 
  TwinEdge, 
  DigitalTwinDocument, 
  NodeStatus 
} from '@/types';

export interface DigitalTwinGraphMetrics {
  totalNodes: number;
  totalEdges: number;
  healthyCount: number;
  compromisedCount: number;
  offlineCount: number;
  blastRadiusPercentage: number;
}

export interface UseDigitalTwinGraphResult {
  twin: DigitalTwinDocument | null;
  nodes: TwinNode[];
  edges: TwinEdge[];
  metrics: DigitalTwinGraphMetrics;
  loading: boolean;
  error: string | null;
  updateNodeStatus: (nodeId: string, status: NodeStatus, compromiseVector?: string) => Promise<void>;
}

/**
 * useDigitalTwinGraph
 * Real-time Reactive Hook for the VulnTwin Digital Twin Infrastructure Sandbox.
 * 
 * Attaches real-time `onSnapshot` websocket listeners to the `/nodes` and `/edges`
 * graph sub-collections in Cloud Firestore. When the AI Attack Agent or backend
 * modifies a node state (e.g. from 'healthy' to 'compromised'), this hook triggers
 * an immediate re-render across the UI with zero latency and no page refresh.
 */
export function useDigitalTwinGraph(twinId: string | null): UseDigitalTwinGraphResult {
  const [twin, setTwin] = useState<DigitalTwinDocument | null>(null);
  const [nodes, setNodes] = useState<TwinNode[]>([]);
  const [edges, setEdges] = useState<TwinEdge[]>([]);
  const [loading, setLoading] = useState<boolean>(Boolean(twinId));
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!twinId) {
      setTwin(null);
      setNodes([]);
      setEdges([]);
      setLoading(false);
      return;
    }

    setLoading(true);
    setError(null);

    // 1. Listen to the parent Twin document for overall status
    const twinDocRef = doc(db, 'digital_twins', twinId);
    const unsubTwin = onSnapshot(
      twinDocRef,
      (docSnap) => {
        if (docSnap.exists()) {
          setTwin({ id: docSnap.id, ...docSnap.data() } as DigitalTwinDocument);
        } else {
          setTwin(null);
        }
      },
      (err) => {
        console.error(`[VulnTwin Graph] Error listening to twin doc ${twinId}:`, err);
        setError(err.message);
      }
    );

    // 2. Real-Time Snapshot Listener for Graph Nodes (Assets)
    const nodesCollectionRef = collection(db, 'digital_twins', twinId, 'nodes');
    const unsubNodes = onSnapshot(
      nodesCollectionRef,
      (snapshot: QuerySnapshot<DocumentData>) => {
        const loadedNodes: TwinNode[] = [];
        snapshot.forEach((docSnap) => {
          loadedNodes.push({
            id: docSnap.id,
            ...(docSnap.data() as Omit<TwinNode, 'id'>)
          });
        });
        setNodes(loadedNodes);
        setLoading(false);
      },
      (err) => {
        console.error(`[VulnTwin Graph] Error listening to nodes in ${twinId}:`, err);
        setError(err.message);
        setLoading(false);
      }
    );

    // 3. Real-Time Snapshot Listener for Graph Edges (Network Rules)
    const edgesCollectionRef = collection(db, 'digital_twins', twinId, 'edges');
    const unsubEdges = onSnapshot(
      edgesCollectionRef,
      (snapshot: QuerySnapshot<DocumentData>) => {
        const loadedEdges: TwinEdge[] = [];
        snapshot.forEach((docSnap) => {
          loadedEdges.push({
            id: docSnap.id,
            ...(docSnap.data() as Omit<TwinEdge, 'id'>)
          });
        });
        setEdges(loadedEdges);
      },
      (err) => {
        console.error(`[VulnTwin Graph] Error listening to edges in ${twinId}:`, err);
        setError(err.message);
      }
    );

    // Cleanup listeners on unmount or twinId change
    return () => {
      unsubTwin();
      unsubNodes();
      unsubEdges();
    };
  }, [twinId]);

  // Derived Real-Time Blast Radius Metrics
  const metrics = useMemo<DigitalTwinGraphMetrics>(() => {
    const totalNodes = nodes.length;
    const totalEdges = edges.length;
    let compromisedCount = 0;
    let healthyCount = 0;
    let offlineCount = 0;

    for (const node of nodes) {
      if (node.status === 'compromised') compromisedCount++;
      else if (node.status === 'offline') offlineCount++;
      else healthyCount++;
    }

    const blastRadiusPercentage = totalNodes > 0 
      ? Math.round((compromisedCount / totalNodes) * 100) 
      : 0;

    return {
      totalNodes,
      totalEdges,
      healthyCount,
      compromisedCount,
      offlineCount,
      blastRadiusPercentage,
    };
  }, [nodes, edges]);

  // Real-time Mutation Trigger
  const updateNodeStatus = useCallback(
    async (nodeId: string, status: NodeStatus, compromiseVector?: string) => {
      if (!twinId) throw new Error('Cannot update node status without an active twinId.');
      const callable = httpsCallable<
        { twinId: string; nodeId: string; status: NodeStatus; compromiseVector?: string },
        { success: boolean }
      >(functions, 'updateTwinState');

      await callable({ twinId, nodeId, status, compromiseVector });
    },
    [twinId]
  );

  return {
    twin,
    nodes,
    edges,
    metrics,
    loading,
    error,
    updateNodeStatus,
  };
}
