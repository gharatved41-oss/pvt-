import { getFirestore, FieldValue } from 'firebase-admin/firestore';
import { DigitalTwinGraph } from './graphTraversal';
import { NonDestructiveValidator, PathValidationReport } from './validator';
import { BlastRadiusCalculator, BlastRadiusAssessment } from './blastRadius';
import { TwinNode, TwinEdge } from '../models/graph';

// =============================================================================
// AUTONOMOUS VALIDATION & ATTACK PATH SIMULATION RUNNER
// =============================================================================

export interface SimulationEvent {
  step: string;
  targetNodeId: string;
  severity: 'info' | 'warning' | 'critical';
  message: string;
}

export interface SimulationExecutionResult {
  simId: string;
  twinId: string;
  status: 'completed' | 'failed';
  assessment: BlastRadiusAssessment;
  eventsEmitted: number;
  durationMs: number;
}

export class SimulationRunner {
  private db = getFirestore();
  private validator = new NonDestructiveValidator();
  private calculator = new BlastRadiusCalculator();

  /**
   * Streams a single telemetry event directly into /simulations/{simId}/events.
   */
  private async emitEvent(simId: string, event: SimulationEvent): Promise<void> {
    try {
      const eventRef = this.db.collection('simulations').doc(simId).collection('events').doc();
      await eventRef.set({
        ...event,
        timestamp: FieldValue.serverTimestamp(),
      });
    } catch (err) {
      console.warn(`[Telemetry Warning] Failed to stream event to /simulations/${simId}/events:`, err);
    }
  }

  /**
   * Executes the full automated validation lifecycle for an active Digital Twin.
   */
  public async executeSimulation(simId: string, twinId: string): Promise<SimulationExecutionResult> {
    const startTime = Date.now();
    let eventsCount = 0;

    const logAndEmit = async (event: SimulationEvent) => {
      eventsCount++;
      await this.emitEvent(simId, event);
    };

    // 1. Mark simulation as running
    const simRef = this.db.collection('simulations').doc(simId);
    await simRef.update({
      status: 'running',
      updatedAt: FieldValue.serverTimestamp(),
    });

    await logAndEmit({
      step: 'INITIALIZE_SIMULATION',
      targetNodeId: twinId,
      severity: 'info',
      message: `Starting Autonomous Security Validation on Digital Twin sandbox [${twinId}].`,
    });

    try {
      // 2. Fetch Twin Graph Nodes and Edges from Firestore
      const twinRef = this.db.collection('digital_twins').doc(twinId);
      const [nodesSnap, edgesSnap] = await Promise.all([
        twinRef.collection('nodes').get(),
        twinRef.collection('edges').get(),
      ]);

      if (nodesSnap.empty) {
        throw new Error(`Digital Twin [${twinId}] contains no nodes.`);
      }

      const nodes: TwinNode[] = [];
      const nodesMap = new Map<string, TwinNode>();
      nodesSnap.forEach((doc) => {
        const node = { id: doc.id, ...(doc.data() as Omit<TwinNode, 'id'>) };
        nodes.push(node);
        nodesMap.set(node.id, node);
      });

      const edges: TwinEdge[] = [];
      edgesSnap.forEach((doc) => {
        edges.push({ id: doc.id, ...(doc.data() as Omit<TwinEdge, 'id'>) });
      });

      await logAndEmit({
        step: 'GRAPH_INGESTION',
        targetNodeId: twinId,
        severity: 'info',
        message: `Ingested topology model: ${nodes.length} nodes (assets) and ${edges.length} edges (firewall routing rules).`,
      });

      // 3. Build In-Memory Graph and Traverse Topology
      const graph = new DigitalTwinGraph(nodes, edges);
      const topology = graph.analyzeTopology();

      await logAndEmit({
        step: 'MAPPING_INGRESS',
        targetNodeId: topology.ingressNodeIds.join(', ') || 'none',
        severity: 'info',
        message: `Identified ${topology.ingressNodeIds.length} perimeter ingress point(s): [${topology.ingressNodeIds.join(', ')}]. High-value assets: [${topology.highValueTargetIds.join(', ')}].`,
      });

      if (topology.chokePoints.length > 0) {
        await logAndEmit({
          step: 'CHOKE_POINT_DETECTION',
          targetNodeId: topology.chokePoints.join(', '),
          severity: 'warning',
          message: `Identified single points of lateral failure (choke points): [${topology.chokePoints.join(', ')}].`,
        });
      }

      // 4. Validate Each Attack Path Non-Destructively
      const validationReports: PathValidationReport[] = [];
      let exploitsAttempted = 0;
      let provenExploitable = 0;

      for (const attackPath of topology.shortestAttackPaths) {
        exploitsAttempted++;
        await logAndEmit({
          step: 'EVALUATING_LATERAL_EDGE',
          targetNodeId: attackPath.pathNodeIds[1] || attackPath.targetNodeId,
          severity: 'info',
          message: `Evaluating attack trajectory: ${attackPath.pathNodeIds.join(' -> ')} (Hop depth: ${attackPath.pathLength}).`,
        });

        const report = this.validator.validateAttackPath(attackPath, (id) => nodesMap.get(id));
        validationReports.push(report);

        if (report.overallVerdict === 'EXPLOITABLE') {
          provenExploitable++;
          await logAndEmit({
            step: 'EXPLOIT_PATH_VALIDATED',
            targetNodeId: report.path.targetNodeId,
            severity: 'critical',
            message: `Deterministic validation SUCCESSFUL: Path to Crown Jewel ${report.path.targetNodeId} is EXPLOITABLE. Lateral chain: [${report.lateralPivotSequence.join(' -> ')}].`,
          });
        } else if (report.overallVerdict === 'THEORETICAL_ONLY') {
          await logAndEmit({
            step: 'DEFENSE_ASSERTION',
            targetNodeId: report.path.targetNodeId,
            severity: 'info',
            message: `Network route accessible to ${report.path.targetNodeId}, but target service configuration is hardened (THEORETICAL_ONLY).`,
          });
        } else {
          await logAndEmit({
            step: 'BOUNDARY_ISOLATION_VERIFIED',
            targetNodeId: report.path.targetNodeId,
            severity: 'info',
            message: `Firewall boundary strictly enforced on attack path to ${report.path.targetNodeId}. Lateral pivot blocked.`,
          });
        }
      }

      // 5. Blast Radius & Compound Risk Calculation
      await logAndEmit({
        step: 'CALCULATING_IMPACT',
        targetNodeId: twinId,
        severity: 'info',
        message: 'Aggregating asset criticality weights and calculating compound blast radius.',
      });

      const assessment = this.calculator.calculateAssessment(validationReports, nodesMap);

      await logAndEmit({
        step: 'BLAST_RADIUS_COMPUTED',
        targetNodeId: twinId,
        severity: assessment.riskScore >= 60 ? 'critical' : 'warning',
        message: `Compound Risk Score: ${assessment.riskScore}/100 (${assessment.compoundRiskLevel}). ${assessment.totalSyntheticRecordsExposed.toLocaleString()} synthetic records exposed across ${assessment.compromisedNodeIds.length} compromised node(s).`,
      });

      // 6. Update Twin Nodes in Firestore to reflect compromised state
      const batch = this.db.batch();
      for (const compromisedId of assessment.compromisedNodeIds) {
        const nodeRef = twinRef.collection('nodes').doc(compromisedId);
        batch.update(nodeRef, {
          status: 'compromised',
          compromiseTimestamp: FieldValue.serverTimestamp(),
          compromiseVector: 'Validated Lateral Traversal via BAS Engine',
          updatedAt: FieldValue.serverTimestamp(),
        });
      }

      // 7. Complete Simulation Document in Firestore
      batch.update(simRef, {
        status: 'completed',
        riskScore: assessment.riskScore,
        compoundRiskLevel: assessment.compoundRiskLevel,
        validatedPaths: assessment.validatedPaths,
        compromisedNodeIds: assessment.compromisedNodeIds,
        totalSyntheticRecordsExposed: assessment.totalSyntheticRecordsExposed,
        chokePointsBreached: assessment.chokePointsBreached,
        exploitsAttempted,
        provenExploitable,
        summary: assessment.summary,
        completedAt: FieldValue.serverTimestamp(),
        updatedAt: FieldValue.serverTimestamp(),
      });

      // Update parent Digital Twin summary status
      batch.update(twinRef, {
        status: 'ready',
        lastSimulatedAt: FieldValue.serverTimestamp(),
        updatedAt: FieldValue.serverTimestamp(),
      });

      await batch.commit();

      const durationMs = Date.now() - startTime;
      await logAndEmit({
        step: 'SIMULATION_COMPLETED',
        targetNodeId: twinId,
        severity: 'info',
        message: `Autonomous validation finished in ${durationMs}ms. Status: COMPLETED.`,
      });

      return {
        simId,
        twinId,
        status: 'completed',
        assessment,
        eventsEmitted: eventsCount,
        durationMs,
      };
    } catch (error: any) {
      console.error(`[Simulation Failure] Error running simulation ${simId}:`, error);

      await logAndEmit({
        step: 'SIMULATION_FAILED',
        targetNodeId: twinId,
        severity: 'critical',
        message: `Simulation halted with error: ${error.message || String(error)}`,
      });

      await simRef.update({
        status: 'failed',
        error: error.message || String(error),
        updatedAt: FieldValue.serverTimestamp(),
      });

      throw error;
    }
  }
}
