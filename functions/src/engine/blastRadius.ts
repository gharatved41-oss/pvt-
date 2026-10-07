import { TwinNode } from '../models/graph';
import { PathValidationReport } from './validator';

// =============================================================================
// BLAST RADIUS & COMPOUND RISK SCORING ENGINE
// =============================================================================

export interface AssetCriticalityDetail {
  nodeId: string;
  nodeType: string;
  criticalityScore: number;
  syntheticRecordsExposed: number;
  exposureMultiplier: number;
}

export interface BlastRadiusAssessment {
  riskScore: number; // 0 to 100
  compoundRiskLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  compromisedNodeIds: string[];
  validatedPaths: string[][]; // Array of node ID sequences tracing exposure
  totalSyntheticRecordsExposed: number;
  assetCriticalities: AssetCriticalityDetail[];
  chokePointsBreached: string[];
  summary: string;
}

/**
 * BlastRadiusCalculator
 * Computes deterministic business impact and compound risk scores for validated attack paths.
 */
export class BlastRadiusCalculator {
  /**
   * 1. Asset Criticality Weighting
   * Maps asset functional classifications to strict severity weights (1-10).
   */
  public getAssetCriticality(node: TwinNode): number {
    if (node.type === 'database') {
      return 10; // Crown Jewel: Confidential persistence
    }
    if (
      node.type === 'server' && 
      (node.properties.softwareStack?.some((s) => s.toLowerCase().includes('auth') || s.toLowerCase().includes('jwt')) ||
       node.id.toLowerCase().includes('auth'))
    ) {
      return 9; // Core Identity & Access Control
    }
    if (node.type === 'server') {
      return 6; // Application runtime & Business logic
    }
    if (node.type === 'firewall' || node.type === 'load_balancer') {
      return 4; // Perimeter ingress / routing
    }
    return 3;
  }

  /**
   * 2. Exposure Multiplier
   * Amplifies risk based on volume of synthetic records exposed and credential availability.
   */
  public getExposureMultiplier(node: TwinNode): number {
    const records = node.properties.syntheticRecordsCount || 0;
    if (records >= 1000) return 2.5;
    if (records >= 100) return 1.8;
    if (records > 0) return 1.4;
    return 1.0;
  }

  /**
   * 3. Compound Risk Score Calculation
   * Formula:
   *   Risk Score = min(100, (Sum(Asset Criticality * Exposure Multiplier) / Path Length))
   */
  public calculateAssessment(
    reports: PathValidationReport[],
    allNodesMap: Map<string, TwinNode>
  ): BlastRadiusAssessment {
    const compromisedNodeSet = new Set<string>();
    const validatedPaths: string[][] = [];
    const chokePointsBreached = new Set<string>();
    let totalSyntheticRecords = 0;

    // Filter to validated paths that are EXPLOITABLE
    const exploitableReports = reports.filter((r) => r.overallVerdict === 'EXPLOITABLE');

    for (const report of reports) {
      if (report.overallVerdict === 'EXPLOITABLE' || report.overallVerdict === 'THEORETICAL_ONLY') {
        report.path.pathNodeIds.forEach((id) => compromisedNodeSet.add(id));
        validatedPaths.push(report.path.pathNodeIds);
        report.path.chokePointNodeIds.forEach((cp) => chokePointsBreached.add(cp));
      }
    }

    const assetCriticalities: AssetCriticalityDetail[] = [];
    let weightedImpactSum = 0;

    for (const nodeId of compromisedNodeSet) {
      const node = allNodesMap.get(nodeId);
      if (!node) continue;

      const criticality = this.getAssetCriticality(node);
      const records = node.properties.syntheticRecordsCount || 0;
      totalSyntheticRecords += records;

      const exposureMultiplier = this.getExposureMultiplier(node);
      weightedImpactSum += criticality * exposureMultiplier;

      assetCriticalities.push({
        nodeId,
        nodeType: node.type,
        criticalityScore: criticality,
        syntheticRecordsExposed: records,
        exposureMultiplier,
      });
    }

    // Determine representative path length (shortest validated attack path from ingress)
    const shortestPathLength = exploitableReports.length > 0 
      ? Math.max(1, Math.min(...exploitableReports.map((r) => r.path.pathLength)))
      : Math.max(1, reports.length > 0 ? Math.min(...reports.map((r) => r.path.pathLength)) : 1);

    // Apply scaling factor to normalize across typical enterprise graph depth
    // Compound score: (weightedImpactSum / pathLength) * scaling constant
    const rawScore = (weightedImpactSum / shortestPathLength) * 5.5;
    const boundedScore = Math.min(100, Math.max(0, Math.round(rawScore)));

    // Categorize risk band
    let compoundRiskLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
    if (boundedScore >= 80) compoundRiskLevel = 'CRITICAL';
    else if (boundedScore >= 60) compoundRiskLevel = 'HIGH';
    else if (boundedScore >= 35) compoundRiskLevel = 'MEDIUM';
    else compoundRiskLevel = 'LOW';

    // Generate executive summary
    const summary = exploitableReports.length > 0
      ? `Validated ${exploitableReports.length} exploit path(s) reaching protected database infrastructure. ${compromisedNodeSet.size} asset(s) compromised with ${totalSyntheticRecords.toLocaleString()} synthetic records exposed. Choke point(s) identified: [${Array.from(chokePointsBreached).join(', ') || 'None'}].`
      : `No immediate weaponizable exploit path reached crown-jewel storage. Network policies enforce perimeter boundary defense.`;

    return {
      riskScore: boundedScore,
      compoundRiskLevel,
      compromisedNodeIds: Array.from(compromisedNodeSet),
      validatedPaths,
      totalSyntheticRecordsExposed: totalSyntheticRecords,
      assetCriticalities,
      chokePointsBreached: Array.from(chokePointsBreached),
      summary,
    };
  }
}
