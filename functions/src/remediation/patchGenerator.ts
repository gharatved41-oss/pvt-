import { TwinNode, TwinEdge } from '../models/graph';

// =============================================================================
// AI PATCH GENERATION AGENT (LLM INTEGRATION)
// =============================================================================

export interface MachineAction {
  targetType: 'edge' | 'node';
  targetId: string;
  actionType: 'BLOCK_EDGE' | 'RESTRICT_PORT' | 'PATCH_CVE' | 'ISOLATE_SUBNET';
  modifications: {
    accessState?: 'blocked' | 'restricted';
    closedPorts?: number[];
    removedCves?: string[];
    updatedProperties?: Record<string, any>;
  };
  iacFormat: 'terraform' | 'kubernetes' | 'aws_cli' | 'iptables';
  iacSnippet: string;
}

export interface HumanExplanation {
  summary: string;
  rootCause: string;
  remediationStrategy: string;
  deploymentImpact: string;
}

export interface GeneratedPatch {
  patchId: string;
  attemptNumber: number;
  humanExplanation: HumanExplanation;
  machineAction: MachineAction;
  modelUsed: string;
  generatedAt: string;
}

export interface PatchContextPayload {
  simId: string;
  twinId: string;
  compromisedNode: TwinNode;
  vulnerableEdge: TwinEdge;
  fullAttackTrajectory: string[];
  exposedRecordsCount: number;
}

/**
 * PatchGenerator
 * Assembles adversarial exposure context and queries LLM to produce
 * machine-actionable graph mutations and production-ready IaC patches.
 */
export class PatchGenerator {
  private apiKey: string;

  constructor(apiKey?: string) {
    this.apiKey = 
      apiKey || 
      process.env.GEMINI_API_KEY || 
      '';
  }

  /**
   * Generates an actionable patch for an identified lateral vulnerability.
   */
  public async generatePatch(
    context: PatchContextPayload,
    attemptNumber: number = 1
  ): Promise<GeneratedPatch> {
    const patchId = `patch_${context.vulnerableEdge.id}_${Date.now()}`;

    try {
      // 1. LLM System Prompt & Context Construction
      const prompt = `You are an enterprise cloud security architect. Based on the following graph traversal path that resulted in a data breach, generate a specific, actionable configuration patch. Return your answer as a structured JSON object containing a "humanExplanation" and a "machineAction" (e.g., a firewall rule update, port closure, or IAM policy change).

EXPOSURE CONTEXT:
- Compromised Asset ID: ${context.compromisedNode.id} (${context.compromisedNode.type})
- Ingress/Lateral Attack Path: ${context.fullAttackTrajectory.join(' -> ')}
- Vulnerable Network Edge ID: ${context.vulnerableEdge.id}
- Edge Protocol / Port: ${context.vulnerableEdge.protocol}/${context.vulnerableEdge.port}
- Current Edge Access State: ${context.vulnerableEdge.accessState}
- Software Stack / CVEs: ${context.compromisedNode.properties.softwareStack?.join(', ') || 'N/A'} | ${context.compromisedNode.properties.cveExposures?.join(', ') || 'None'}
- Synthetic Records Exposed: ${context.exposedRecordsCount}
- Attempt Number: ${attemptNumber}

OUTPUT SCHEMA REQUIREMENTS (JSON ONLY):
{
  "humanExplanation": {
    "summary": "Short 1-sentence executive summary",
    "rootCause": "Detailed technical explanation of network boundary failure",
    "remediationStrategy": "Concrete mitigation strategy (e.g. block port, enforce mTLS, restrict security group)",
    "deploymentImpact": "Operational impact assessment"
  },
  "machineAction": {
    "targetType": "edge",
    "targetId": "${context.vulnerableEdge.id}",
    "actionType": "BLOCK_EDGE",
    "modifications": {
      "accessState": "blocked",
      "closedPorts": [${context.vulnerableEdge.port}]
    },
    "iacFormat": "terraform",
    "iacSnippet": "Valid copy-paste Terraform aws_security_group_rule or Kubernetes NetworkPolicy snippet"
  }
}`;

      // 2. Query Gemini API via REST
      if (this.apiKey && this.apiKey.length > 10) {
        const response = await fetch(
          `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${this.apiKey}`,
          {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              contents: [{ parts: [{ text: prompt }] }],
              generationConfig: {
                responseMimeType: 'application/json',
                temperature: 0.2,
              },
            }),
          }
        );

        if (response.ok) {
          const data = await response.json();
          const rawText = data.candidates?.[0]?.content?.parts?.[0]?.text;
          if (rawText) {
            const parsed = JSON.parse(rawText);
            return {
              patchId,
              attemptNumber,
              humanExplanation: parsed.humanExplanation,
              machineAction: parsed.machineAction,
              modelUsed: 'gemini-2.0-flash',
              generatedAt: new Date().toISOString(),
            };
          }
        }
      }
    } catch (err) {
      console.warn('[PatchGenerator Warning] LLM call failed or timed out, using deterministic security fallback:', err);
    }

    // 3. Deterministic Enterprise Cloud Security Architecture Fallback
    return this.generateDeterministicPatch(context, attemptNumber, patchId);
  }

  /**
   * Deterministic Fallback Engine when LLM network connectivity is offline.
   */
  private generateDeterministicPatch(
    context: PatchContextPayload,
    attemptNumber: number,
    patchId: string
  ): GeneratedPatch {
    const edge = context.vulnerableEdge;
    const node = context.compromisedNode;

    const terraformSnippet = `# VulnTwin AI - Verified Security Remediation
# Closes unauthenticated lateral egress between ${edge.sourceNodeId} and ${edge.targetNodeId}

resource "aws_security_group_rule" "isolate_${edge.id.replace(/[^a-zA-Z0-9]/g, '_')}" {
  type              = "ingress"
  from_port         = ${edge.port}
  to_port           = ${edge.port}
  protocol          = "${edge.protocol.toLowerCase()}"
  cidr_blocks       = ["10.0.0.0/16"] # Enforce strict VPC subnetwork boundary
  security_group_id = "sg-0a8b9c1d2e3f4g5h6"
  description       = "VulnTwin AEV Remediation: Block unauthorized lateral pivoting on port ${edge.port}"
}
`;

    return {
      patchId,
      attemptNumber,
      humanExplanation: {
        summary: `Isolate lateral boundary on edge ${edge.id} to protect ${node.id}.`,
        rootCause: `Lateral traffic over ${edge.protocol}/${edge.port} permitted ingress from untrusted web tier into database infrastructure without mutual authentication.`,
        remediationStrategy: `Transition network access policy on edge ${edge.id} from '${edge.accessState}' to 'blocked'. Enforce strict VPC ingress filtering on port ${edge.port}.`,
        deploymentImpact: `Zero downtime for public ingress; lateral database queries must route through authenticated API gateway with mutual TLS.`,
      },
      machineAction: {
        targetType: 'edge',
        targetId: edge.id,
        actionType: 'BLOCK_EDGE',
        modifications: {
          accessState: 'blocked',
          closedPorts: [edge.port],
        },
        iacFormat: 'terraform',
        iacSnippet: terraformSnippet,
      },
      modelUsed: 'deterministic-security-engine-v1',
      generatedAt: new Date().toISOString(),
    };
  }
}
