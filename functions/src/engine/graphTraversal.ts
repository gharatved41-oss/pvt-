import { TwinNode, TwinEdge } from '../models/graph';

// =============================================================================
// GRAPH TRAVERSAL & ATTACK PATH ANALYSIS ENGINE
// =============================================================================

export interface AttackPath {
  ingressNodeId: string;
  targetNodeId: string;
  pathNodeIds: string[];
  edgesTraversed: TwinEdge[];
  pathLength: number;
  isChokePointTraversed: boolean;
  chokePointNodeIds: string[];
}

export interface GraphTopologyAnalysis {
  ingressNodeIds: string[];
  highValueTargetIds: string[];
  reachableNodeIds: string[];
  shortestAttackPaths: AttackPath[];
  chokePoints: string[];
}

/**
 * DigitalTwinGraph
 * In-memory adjacency representation for deterministic breach and attack simulation.
 */
export class DigitalTwinGraph {
  private nodesMap: Map<string, TwinNode> = new Map();
  private edgesMap: Map<string, TwinEdge> = new Map();
  private outgoingEdges: Map<string, TwinEdge[]> = new Map();
  private incomingEdges: Map<string, TwinEdge[]> = new Map();

  constructor(nodes: TwinNode[], edges: TwinEdge[]) {
    for (const node of nodes) {
      this.nodesMap.set(node.id, node);
      this.outgoingEdges.set(node.id, []);
      this.incomingEdges.set(node.id, []);
    }

    for (const edge of edges) {
      this.edgesMap.set(edge.id, edge);
      if (this.outgoingEdges.has(edge.sourceNodeId)) {
        this.outgoingEdges.get(edge.sourceNodeId)!.push(edge);
      }
      if (this.incomingEdges.has(edge.targetNodeId)) {
        this.incomingEdges.get(edge.targetNodeId)!.push(edge);
      }
    }
  }

  public getNode(nodeId: string): TwinNode | undefined {
    return this.nodesMap.get(nodeId);
  }

  public getAllNodes(): TwinNode[] {
    return Array.from(this.nodesMap.values());
  }

  public getAllEdges(): TwinEdge[] {
    return Array.from(this.edgesMap.values());
  }

  /**
   * 1. Ingress Identification
   * Identifies all nodes with internet-facing access (nodes connected to external
   * ingress edges or edge firewalls with open public ports like 80, 443, 22).
   */
  public identifyIngressNodes(): string[] {
    const ingressNodes: string[] = [];

    for (const node of this.nodesMap.values()) {
      // Direct ingress if type is firewall or load_balancer with open web ports
      const hasPublicPort = node.properties.openPorts?.some((p) => [80, 443, 22, 8080].includes(p));
      const isPerimeterType = node.type === 'firewall' || node.type === 'load_balancer';
      
      // Node has no incoming edge from another internal node (root of traffic)
      const incoming = this.incomingEdges.get(node.id) || [];
      const hasNoInternalIngress = incoming.length === 0;

      if ((isPerimeterType && hasPublicPort) || (hasNoInternalIngress && hasPublicPort)) {
        ingressNodes.push(node.id);
      }
    }

    // Fallback: If no explicit perimeter is detected, select first node with public ports
    if (ingressNodes.length === 0) {
      for (const node of this.nodesMap.values()) {
        if (node.properties.openPorts?.some((p) => [80, 443].includes(p))) {
          ingressNodes.push(node.id);
          break;
        }
      }
    }

    return ingressNodes;
  }

  /**
   * Identifies high-value assets (Crown Jewels): databases containing synthetic
   * PII/records, or authentication microservices issuing credentials.
   */
  public identifyHighValueTargets(): string[] {
    const targets: string[] = [];

    for (const node of this.nodesMap.values()) {
      if (node.type === 'database') {
        targets.push(node.id);
      } else if (
        node.type === 'server' && 
        (node.properties.softwareStack?.some((s) => s.toLowerCase().includes('auth') || s.toLowerCase().includes('jwt')) ||
         node.id.toLowerCase().includes('auth'))
      ) {
        targets.push(node.id);
      }
    }

    return targets;
  }

  /**
   * 2. Pivoting & Reachability Analysis (BFS Shortest Path)
   * Calculates the shortest path between startNodeId and targetNodeId
   * considering only edges with accessState !== 'blocked'.
   */
  public findShortestPath(startNodeId: string, targetNodeId: string): AttackPath | null {
    if (startNodeId === targetNodeId) {
      return {
        ingressNodeId: startNodeId,
        targetNodeId,
        pathNodeIds: [startNodeId],
        edgesTraversed: [],
        pathLength: 0,
        isChokePointTraversed: false,
        chokePointNodeIds: [],
      };
    }

    const queue: Array<{ nodeId: string; path: string[]; edges: TwinEdge[] }> = [
      { nodeId: startNodeId, path: [startNodeId], edges: [] }
    ];
    const visited = new Set<string>([startNodeId]);

    while (queue.length > 0) {
      const current = queue.shift()!;
      const outgoing = this.outgoingEdges.get(current.nodeId) || [];

      for (const edge of outgoing) {
        // Lateral access filter: Blocked rules stop lateral movement
        if (edge.accessState === 'blocked') continue;

        const nextNodeId = edge.targetNodeId;

        if (nextNodeId === targetNodeId) {
          const finalPath = [...current.path, nextNodeId];
          const finalEdges = [...current.edges, edge];
          return {
            ingressNodeId: startNodeId,
            targetNodeId,
            pathNodeIds: finalPath,
            edgesTraversed: finalEdges,
            pathLength: finalEdges.length,
            isChokePointTraversed: false,
            chokePointNodeIds: [],
          };
        }

        if (!visited.has(nextNodeId)) {
          visited.add(nextNodeId);
          queue.push({
            nodeId: nextNodeId,
            path: [...current.path, nextNodeId],
            edges: [...current.edges, edge],
          });
        }
      }
    }

    return null;
  }

  /**
   * 3. Choke Point Detection
   * Evaluates single points of failure in the network topology: intermediate nodes
   * whose removal disconnects the ingress nodes from the high-value databases.
   */
  public detectChokePoints(ingressNodes: string[], targets: string[]): string[] {
    const chokePoints: Set<string> = new Set();
    const candidateNodes = Array.from(this.nodesMap.keys()).filter(
      (id) => !ingressNodes.includes(id) && !targets.includes(id)
    );

    for (const candidateId of candidateNodes) {
      // Simulate removal of candidate node and check if ANY target becomes unreachable from ALL ingress nodes
      let pathsBroken = false;

      for (const ingressId of ingressNodes) {
        for (const targetId of targets) {
          const path = this.findPathExcludingNode(ingressId, targetId, candidateId);
          // If a path previously existed, but is now null, this candidate is a critical bridge/choke point
          const originalPath = this.findShortestPath(ingressId, targetId);
          if (originalPath && !path) {
            pathsBroken = true;
            break;
          }
        }
        if (pathsBroken) break;
      }

      if (pathsBroken) {
        chokePoints.add(candidateId);
      }
    }

    return Array.from(chokePoints);
  }

  private findPathExcludingNode(
    startNodeId: string, 
    targetNodeId: string, 
    excludedNodeId: string
  ): boolean {
    const queue = [startNodeId];
    const visited = new Set<string>([startNodeId, excludedNodeId]);

    while (queue.length > 0) {
      const current = queue.shift()!;
      if (current === targetNodeId) return true;

      const outgoing = this.outgoingEdges.get(current) || [];
      for (const edge of outgoing) {
        if (edge.accessState === 'blocked') continue;
        if (!visited.has(edge.targetNodeId)) {
          visited.add(edge.targetNodeId);
          queue.push(edge.targetNodeId);
        }
      }
    }

    return false;
  }

  /**
   * Runs comprehensive graph topology traversal analysis.
   */
  public analyzeTopology(): GraphTopologyAnalysis {
    const ingressNodes = this.identifyIngressNodes();
    const targets = this.identifyHighValueTargets();
    const chokePoints = this.detectChokePoints(ingressNodes, targets);
    const reachableNodes = new Set<string>();
    const attackPaths: AttackPath[] = [];

    for (const ingressId of ingressNodes) {
      for (const targetId of targets) {
        const path = this.findShortestPath(ingressId, targetId);
        if (path) {
          path.pathNodeIds.forEach((id) => reachableNodes.add(id));
          
          // Annotate choke points traversed in this attack path
          const pathChokes = path.pathNodeIds.filter((id) => chokePoints.includes(id));
          path.chokePointNodeIds = pathChokes;
          path.isChokePointTraversed = pathChokes.length > 0;

          attackPaths.push(path);
        }
      }
    }

    // Sort attack paths by shortest hop length (most accessible lateral route)
    attackPaths.sort((a, b) => a.pathLength - b.pathLength);

    return {
      ingressNodeIds: ingressNodes,
      highValueTargetIds: targets,
      reachableNodeIds: Array.from(reachableNodes),
      shortestAttackPaths: attackPaths,
      chokePoints,
    };
  }
}
