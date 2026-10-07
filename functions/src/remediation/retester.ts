import { getFirestore, FieldValue } from 'firebase-admin/firestore';
import { PatchGenerator, GeneratedPatch, PatchContextPayload } from './patchGenerator';
import { SandboxApplier, TwinStateSnapshot } from './sandboxApplier';
import { SimulationRunner } from '../engine/runner';
import { TwinNode, TwinEdge } from '../models/graph';

// =============================================================================
// ADVERSARIAL EXPOSURE VALIDATION (AEV) VERIFICATION RE-TEST LOOP
// =============================================================================

export interface AevVerificationResult {
  simId: string;
  twinId: string;
  status: 'verified_fixed' | 'remediation_failed';
  totalAttempts: number;
  initialRiskScore: number;
  finalRiskScore: number;
  verifiedPatch?: GeneratedPatch;
  verificationEvidence: {
    attackBlocked: boolean;
    blastRadiusReduced: boolean;
    verificationTimestamp: string;
    iacSnippet: string;
    humanExplanation: string;
  };
}

export class AevRetestLoop {
  private db = getFirestore();
  private patchGenerator = new PatchGenerator();
  private sandboxApplier = new SandboxApplier();
  private runner = new SimulationRunner();

  /**
   * Helper to write structured telemetry into /simulations/{simId}/events.
   */
  private async emitEvent(
    simId: string, 
    step: string, 
    severity: 'info' | 'warning' | 'critical', 
    message: string,
    targetNodeId?: string
  ): Promise<void> {
    try {
      await this.db.collection('simulations').doc(simId).collection('events').add({
        step,
        severity,
        message,
        targetNodeId: targetNodeId || 'aev-engine',
        timestamp: FieldValue.serverTimestamp(),
      });
    } catch (err) {
      console.warn(`[Telemetry Warning] Failed to log ${step}:`, err);
    }
  }

  /**
   * Executes the full automated AEV Remediation & Verification Re-Test Loop.
   */
  public async executeRemediationLoop(
    simId: string,
    twinId: string,
    maxAttempts: number = 3
  ): Promise<AevVerificationResult> {
    const simRef = this.db.collection('simulations').doc(simId);
    const simSnap = await simRef.get();

    if (!simSnap.exists) {
      throw new Error(`Simulation [${simId}] not found.`);
    }

    const simData = simSnap.data() || {};
    const initialRiskScore = simData.riskScore || 0;

    await this.emitEvent(
      simId,
      'AEV_LOOP_INITIATED',
      'info',
      `Initializing AEV Verification Loop. Baseline Risk Score: ${initialRiskScore}/100.`
    );

    // 1. Fetch current Twin Graph to assemble exposure context
    const twinRef = this.db.collection('digital_twins').doc(twinId);
    const [nodesSnap, edgesSnap] = await Promise.all([
      twinRef.collection('nodes').get(),
      twinRef.collection('edges').get(),
    ]);

    const nodesMap = new Map<string, TwinNode>();
    nodesSnap.forEach((doc) => {
      nodesMap.set(doc.id, { id: doc.id, ...(doc.data() as Omit<TwinNode, 'id'>) });
    });

    const edges: TwinEdge[] = [];
    edgesSnap.forEach((doc) => {
      edges.push({ id: doc.id, ...(doc.data() as Omit<TwinEdge, 'id'>) });
    });

    // Determine the vulnerable path and the critical choke edge
    const validatedPaths: string[][] = simData.validatedPaths || [];

    // Find the vulnerable lateral edge that connects to the compromised crown jewel
    let vulnerableEdge: TwinEdge | undefined;
    let compromisedNode: TwinNode | undefined;
    let fullTrajectory: string[] = validatedPaths[0] || [];

    if (fullTrajectory.length >= 2) {
      const sourceId = fullTrajectory[fullTrajectory.length - 2];
      const targetId = fullTrajectory[fullTrajectory.length - 1];
      vulnerableEdge = edges.find((e) => e.sourceNodeId === sourceId && e.targetNodeId === targetId);
      compromisedNode = nodesMap.get(targetId);
    }

    // Fallback: Pick any edge connected to a database or compromised node
    if (!vulnerableEdge) {
      vulnerableEdge = edges.find((e) => e.accessState === 'open' || e.accessState === 'restricted') || edges[0];
      compromisedNode = nodesMap.get(vulnerableEdge?.targetNodeId || '') || Array.from(nodesMap.values())[0];
      fullTrajectory = [vulnerableEdge.sourceNodeId, vulnerableEdge.targetNodeId];
    }

    const contextPayload: PatchContextPayload = {
      simId,
      twinId,
      compromisedNode: compromisedNode!,
      vulnerableEdge: vulnerableEdge!,
      fullAttackTrajectory: fullTrajectory,
      exposedRecordsCount: simData.totalSyntheticRecordsExposed || 1000,
    };

    let successfulPatch: GeneratedPatch | undefined;
    let finalRiskScore = initialRiskScore;

    // 2. Iterative Re-Test Loop (Up to maxAttempts)
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      await this.emitEvent(
        simId,
        'AEV_GENERATING_PATCH',
        'info',
        `Attempt ${attempt}/${maxAttempts}: Querying Cloud Security Architect AI for candidate patch...`
      );

      // A. Generate candidate patch
      const patch = await this.patchGenerator.generatePatch(contextPayload, attempt);

      await this.emitEvent(
        simId,
        'AEV_APPLYING_PATCH',
        'info',
        `Attempt ${attempt}/${maxAttempts}: Applying patch [${patch.machineAction.actionType}] to twin sandbox.`
      );

      // B. Apply patch to Sandbox (with pre-mutation snapshot)
      let snapshot: TwinStateSnapshot | null = null;
      try {
        snapshot = await this.sandboxApplier.applyPatch(twinId, patch);

        await this.emitEvent(
          simId,
          'AEV_RETEST_EXECUTING',
          'info',
          `Attempt ${attempt}/${maxAttempts}: Re-running Adversarial Validation Engine against patched twin...`
        );

        // C. Re-execute Simulation Engine on patched twin
        const retestResult = await this.runner.executeSimulation(simId, twinId);
        const retestRiskScore = retestResult.assessment.riskScore;
        const retestCompromised = retestResult.assessment.compromisedNodeIds;

        // D. Evaluate Outcome: Attack BLOCKED if target is no longer reached or risk score significantly dropped
        const crownJewelProtected = !retestCompromised.includes(contextPayload.compromisedNode.id);
        const attackBlocked = crownJewelProtected || retestRiskScore <= 20;

        if (attackBlocked) {
          // SUCCESS! The patch is verified safe.
          successfulPatch = patch;
          finalRiskScore = retestRiskScore;

          await this.emitEvent(
            simId,
            'AEV_PATCH_VERIFIED',
            'info',
            `AEV Verification SUCCESS: Lateral attack blocked on attempt ${attempt}. Risk score reduced from ${initialRiskScore} to ${finalRiskScore}.`
          );
          break;
        } else {
          // Attack succeeded again -> Rollback sandbox state and retry
          await this.emitEvent(
            simId,
            'AEV_RETEST_UNSUCCESSFUL',
            'warning',
            `Attempt ${attempt}/${maxAttempts} failed: Attack path still traversable. Rolling back twin sandbox...`
          );

          if (snapshot) {
            await this.sandboxApplier.rollback(snapshot);
          }
        }
      } catch (loopErr: any) {
        console.error(`[AEV Loop Error] Error in attempt ${attempt}:`, loopErr);
        if (snapshot) {
          await this.sandboxApplier.rollback(snapshot);
        }
      }
    }

    // 3. Finalize Status & Green Light Verification Payload
    if (successfulPatch) {
      const verificationEvidence = {
        attackBlocked: true,
        blastRadiusReduced: true,
        verificationTimestamp: new Date().toISOString(),
        iacSnippet: successfulPatch.machineAction.iacSnippet,
        humanExplanation: successfulPatch.humanExplanation.summary,
      };

      await simRef.update({
        status: 'verified_fixed',
        verifiedPatch: successfulPatch,
        initialRiskScore,
        finalRiskScore,
        retestAttempts: successfulPatch.attemptNumber,
        verificationEvidence,
        verifiedAt: FieldValue.serverTimestamp(),
        updatedAt: FieldValue.serverTimestamp(),
      });

      // Update parent Digital Twin status back to ready
      await twinRef.update({
        status: 'ready',
        activePatchId: successfulPatch.patchId,
        updatedAt: FieldValue.serverTimestamp(),
      });

      return {
        simId,
        twinId,
        status: 'verified_fixed',
        totalAttempts: successfulPatch.attemptNumber,
        initialRiskScore,
        finalRiskScore,
        verifiedPatch: successfulPatch,
        verificationEvidence,
      };
    } else {
      await this.emitEvent(
        simId,
        'AEV_REMEDIATION_FAILED',
        'critical',
        `AEV Remediation failed after ${maxAttempts} automated attempts. Human intervention required.`
      );

      await simRef.update({
        status: 'remediation_failed',
        initialRiskScore,
        finalRiskScore,
        retestAttempts: maxAttempts,
        updatedAt: FieldValue.serverTimestamp(),
      });

      await twinRef.update({
        status: 'ready',
        updatedAt: FieldValue.serverTimestamp(),
      });

      return {
        simId,
        twinId,
        status: 'remediation_failed',
        totalAttempts: maxAttempts,
        initialRiskScore,
        finalRiskScore,
        verificationEvidence: {
          attackBlocked: false,
          blastRadiusReduced: false,
          verificationTimestamp: new Date().toISOString(),
          iacSnippet: '',
          humanExplanation: 'Automated remediation could not resolve exposure without architectural changes.',
        },
      };
    }
  }
}
