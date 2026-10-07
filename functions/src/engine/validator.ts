import { TwinNode, TwinEdge } from '../models/graph';
import { AttackPath } from './graphTraversal';

// =============================================================================
// NON-DESTRUCTIVE VALIDATION & CONDITION MATCHING ENGINE
// =============================================================================

export type ValidationVerdict = 'EXPLOITABLE' | 'THEORETICAL_ONLY' | 'DEFENDED';

export interface HopValidationResult {
  sourceNodeId: string;
  targetNodeId: string;
  edgeId: string;
  testedPort: number;
  testedProtocol: string;
  edgePolicyResult: 'VALIDATED_LEAK' | 'STRICT_ISOLATION' | 'UNPROTECTED_OPEN';
  serviceProbeResult: {
    serviceName: string;
    cveExposures: string[];
    misconfigurations: string[];
    isVulnerable: boolean;
  };
  verdict: ValidationVerdict;
  rationale: string;
}

export interface PathValidationReport {
  path: AttackPath;
  hopResults: HopValidationResult[];
  overallVerdict: ValidationVerdict;
  weakestLinkNodeId: string | null;
  targetCompromised: boolean;
  lateralPivotSequence: string[];
  evidenceLog: string[];
}

/**
 * NonDestructiveValidator
 * Evaluates software configuration states and firewall rules without sending
 * malicious payloads. Replaces speculative scanning with deterministic assertion.
 */
export class NonDestructiveValidator {
  /**
   * 1. Service State Probing
   * Inspects declared software stacks, listening ports, and exposed CVEs for each node.
   */
  public probeServiceState(node: TwinNode): {
    serviceName: string;
    cveExposures: string[];
    misconfigurations: string[];
    isVulnerable: boolean;
  } {
    const misconfigurations: string[] = [];
    const softwareStack = node.properties.softwareStack || [];
    const openPorts = node.properties.openPorts || [];
    const cves = node.properties.cveExposures || [];

    // Benign rule: Unencrypted plaintext ports exposed
    if (openPorts.includes(80) && !openPorts.includes(443)) {
      misconfigurations.push('Unencrypted HTTP communication (Cleartext transport)');
    }
    if (openPorts.includes(6379)) {
      misconfigurations.push('Redis port 6379 exposed without mandatory TLS wrapper');
    }
    if (openPorts.includes(3000) || openPorts.includes(8080)) {
      misconfigurations.push('Alternative web application port exposed directly without perimeter WAF filtering');
    }

    // Check for vulnerable software patterns
    const hasKnownVulnerabilities = cves.length > 0;
    const isVulnerable = hasKnownVulnerabilities || misconfigurations.length > 0;

    return {
      serviceName: softwareStack[0] || node.type,
      cveExposures: cves,
      misconfigurations,
      isVulnerable,
    };
  }

  /**
   * 2. Edge Rule Verification
   * Evaluates if connecting network edge enforces intended boundary isolation.
   */
  public verifyEdgeRule(edge: TwinEdge, sourceNode: TwinNode, targetNode: TwinNode): {
    edgePolicyResult: 'VALIDATED_LEAK' | 'STRICT_ISOLATION' | 'UNPROTECTED_OPEN';
    isPermitted: boolean;
    ruleDescription: string;
  } {
    if (edge.accessState === 'blocked') {
      return {
        edgePolicyResult: 'STRICT_ISOLATION',
        isPermitted: false,
        ruleDescription: `Traffic to ${targetNode.id} on port ${edge.port} is blocked by firewall policy.`,
      };
    }

    // Edge claims 'restricted' (e.g. database port 5432) but source is a general web tier
    if (edge.accessState === 'restricted') {
      const isSourceWebTier = sourceNode.type === 'server' || sourceNode.type === 'load_balancer';
      const isTargetDatabase = targetNode.type === 'database';

      if (isSourceWebTier && isTargetDatabase) {
        // Deterministic condition check: unrestricted web-to-DB connection without mTLS or query proxy
        return {
          edgePolicyResult: 'VALIDATED_LEAK',
          isPermitted: true,
          ruleDescription: `Edge rule on port ${edge.port} lacks network token isolation; lateral SQL access permitted from ${sourceNode.id}.`,
        };
      }
    }

    // Fully open rule
    return {
      edgePolicyResult: 'UNPROTECTED_OPEN',
      isPermitted: true,
      ruleDescription: `Open route: ${sourceNode.id} -> ${targetNode.id} over ${edge.protocol}/${edge.port}.`,
    };
  }

  /**
   * 3. Deterministic Outcome Determination
   * Evaluates each hop along an identified attack path.
   */
  public validateAttackPath(
    path: AttackPath,
    getNode: (id: string) => TwinNode | undefined
  ): PathValidationReport {
    const hopResults: HopValidationResult[] = [];
    const evidenceLog: string[] = [];
    let pathBroken = false;
    let weakestLinkNodeId: string | null = null;

    evidenceLog.push(`[VALIDATION_START] Evaluating Attack Path: ${path.pathNodeIds.join(' -> ')}`);

    for (let i = 0; i < path.edgesTraversed.length; i++) {
      const edge = path.edgesTraversed[i];
      const sourceNode = getNode(edge.sourceNodeId);
      const targetNode = getNode(edge.targetNodeId);

      if (!sourceNode || !targetNode) {
        pathBroken = true;
        evidenceLog.push(`[ERROR] Missing node definition for hop: ${edge.sourceNodeId} -> ${edge.targetNodeId}`);
        break;
      }

      // 1. Probe target node configuration
      const probe = this.probeServiceState(targetNode);
      // 2. Verify edge isolation rule
      const edgeCheck = this.verifyEdgeRule(edge, sourceNode, targetNode);

      let hopVerdict: ValidationVerdict;
      let rationale: string;

      if (!edgeCheck.isPermitted) {
        hopVerdict = 'DEFENDED';
        rationale = `Perimeter defense active: ${edgeCheck.ruleDescription}`;
        pathBroken = true;
      } else if (probe.isVulnerable) {
        hopVerdict = 'EXPLOITABLE';
        rationale = `Lateral exploit verified: ${edgeCheck.ruleDescription} Service on ${targetNode.id} exhibits vulnerabilities (${probe.cveExposures.concat(probe.misconfigurations).join(', ')}).`;
        if (!weakestLinkNodeId) weakestLinkNodeId = targetNode.id;
      } else {
        // Path is physically open, but software is hardened (no CVE, no misconfiguration)
        hopVerdict = 'THEORETICAL_ONLY';
        rationale = `Network route is open, but target service on ${targetNode.id} enforces hardened configuration with zero exposed CVEs.`;
      }

      evidenceLog.push(`[HOP_${i + 1}] ${sourceNode.id} -> ${targetNode.id} (${edge.protocol}/${edge.port}) => ${hopVerdict}: ${rationale}`);

      hopResults.push({
        sourceNodeId: sourceNode.id,
        targetNodeId: targetNode.id,
        edgeId: edge.id,
        testedPort: edge.port,
        testedProtocol: edge.protocol,
        edgePolicyResult: edgeCheck.edgePolicyResult,
        serviceProbeResult: probe,
        verdict: hopVerdict,
        rationale,
      });

      if (pathBroken) break;
    }

    // Calculate final overall verdict
    const targetCompromised = !pathBroken && hopResults.every((h) => h.verdict === 'EXPLOITABLE' || h.verdict === 'THEORETICAL_ONLY');
    const hasExploitableHop = hopResults.some((h) => h.verdict === 'EXPLOITABLE');

    let overallVerdict: ValidationVerdict;
    if (targetCompromised && hasExploitableHop) {
      overallVerdict = 'EXPLOITABLE';
      evidenceLog.push(`[VALIDATION_RESULT] Path confirmed EXPLOITABLE. Crown jewel target ${path.targetNodeId} reached.`);
    } else if (targetCompromised) {
      overallVerdict = 'THEORETICAL_ONLY';
      evidenceLog.push(`[VALIDATION_RESULT] Path is reach-accessible but lacks weaponizable exploit preconditions (THEORETICAL_ONLY).`);
    } else {
      overallVerdict = 'DEFENDED';
      evidenceLog.push(`[VALIDATION_RESULT] Attack path DEFENDED. Network policy prevented lateral movement.`);
    }

    return {
      path,
      hopResults,
      overallVerdict,
      weakestLinkNodeId,
      targetCompromised,
      lateralPivotSequence: path.pathNodeIds,
      evidenceLog,
    };
  }
}
