import { getFirestore, FieldValue } from 'firebase-admin/firestore';
import { GeneratedPatch } from './patchGenerator';

// =============================================================================
// TWIN SANDBOX APPLIER & STATE SNAPSHOT ENGINE
// =============================================================================

export interface TwinStateSnapshot {
  snapshotId: string;
  twinId: string;
  createdAt: string;
  previousTwinStatus: string;
  targetType: 'edge' | 'node';
  targetId: string;
  previousData: Record<string, any>;
}

export class SandboxApplier {
  private db = getFirestore();

  /**
   * 1. State Snapshot
   * Backs up the pre-patch state of the affected asset or network edge.
   */
  public async createStateSnapshot(
    twinId: string, 
    targetType: 'edge' | 'node', 
    targetId: string
  ): Promise<TwinStateSnapshot> {
    const twinRef = this.db.collection('digital_twins').doc(twinId);
    const twinSnap = await twinRef.get();
    const previousTwinStatus = twinSnap.exists ? twinSnap.data()?.status || 'ready' : 'ready';

    let targetDocRef = targetType === 'edge'
      ? twinRef.collection('edges').doc(targetId)
      : twinRef.collection('nodes').doc(targetId);

    const docSnap = await targetDocRef.get();
    if (!docSnap.exists) {
      throw new Error(`Target ${targetType} [${targetId}] does not exist in twin [${twinId}].`);
    }

    const snapshotId = `snap_${targetId}_${Date.now()}`;
    const previousData = docSnap.data() || {};

    const snapshot: TwinStateSnapshot = {
      snapshotId,
      twinId,
      createdAt: new Date().toISOString(),
      previousTwinStatus,
      targetType,
      targetId,
      previousData,
    };

    // Store snapshot in Firestore for persistence across distributed worker restarts
    await twinRef.collection('snapshots').doc(snapshotId).set({
      ...snapshot,
      timestamp: FieldValue.serverTimestamp(),
    });

    return snapshot;
  }

  /**
   * 2. Apply Patch to Digital Twin
   * Mutates the digital twin graph based on the machineAction and sets status
   * to 'remediation_testing'.
   */
  public async applyPatch(
    twinId: string,
    patch: GeneratedPatch
  ): Promise<TwinStateSnapshot> {
    const { targetType, targetId, modifications } = patch.machineAction;

    // Capture pre-patch snapshot
    const snapshot = await this.createStateSnapshot(twinId, targetType, targetId);

    const twinRef = this.db.collection('digital_twins').doc(twinId);
    const batch = this.db.batch();

    if (targetType === 'edge') {
      const edgeRef = twinRef.collection('edges').doc(targetId);
      const updates: Record<string, any> = {
        updatedAt: FieldValue.serverTimestamp(),
        lastAppliedPatchId: patch.patchId,
      };

      if (modifications.accessState) {
        updates.accessState = modifications.accessState;
      }
      if (modifications.closedPorts && modifications.closedPorts.length > 0) {
        updates.ruleDescription = `AEV Remediation Applied: Port ${modifications.closedPorts.join(', ')} blocked.`;
      }

      batch.update(edgeRef, updates);
    } else {
      const nodeRef = twinRef.collection('nodes').doc(targetId);
      const updates: Record<string, any> = {
        updatedAt: FieldValue.serverTimestamp(),
        lastAppliedPatchId: patch.patchId,
      };

      if (modifications.closedPorts) {
        const prevPorts: number[] = snapshot.previousData.properties?.openPorts || [];
        updates['properties.openPorts'] = prevPorts.filter(
          (p) => !modifications.closedPorts!.includes(p)
        );
      }

      if (modifications.removedCves) {
        const prevCves: string[] = snapshot.previousData.properties?.cveExposures || [];
        updates['properties.cveExposures'] = prevCves.filter(
          (c) => !modifications.removedCves!.includes(c)
        );
      }

      batch.update(nodeRef, updates);
    }

    // 3. Flag Twin state to 'remediation_testing'
    batch.update(twinRef, {
      status: 'remediation_testing',
      activePatchId: patch.patchId,
      updatedAt: FieldValue.serverTimestamp(),
    });

    await batch.commit();

    return snapshot;
  }

  /**
   * Rollback State Snapshot
   * Restores original pre-patch state if verification fails.
   */
  public async rollback(snapshot: TwinStateSnapshot): Promise<void> {
    const twinRef = this.db.collection('digital_twins').doc(snapshot.twinId);
    const targetRef = snapshot.targetType === 'edge'
      ? twinRef.collection('edges').doc(snapshot.targetId)
      : twinRef.collection('nodes').doc(snapshot.targetId);

    const batch = this.db.batch();

    // Revert target document to original content
    batch.set(targetRef, snapshot.previousData);

    // Revert twin status
    batch.update(twinRef, {
      status: snapshot.previousTwinStatus || 'ready',
      activePatchId: FieldValue.delete(),
      updatedAt: FieldValue.serverTimestamp(),
    });

    await batch.commit();
  }
}
