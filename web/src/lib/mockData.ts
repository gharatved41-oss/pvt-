export type NodeStatus = 'idle' | 'scanning' | 'safe' | 'compromised' | 'patched';

export interface TwinNode {
  id: string;
  name: string;
  type: 'server' | 'database' | 'firewall' | 'load_balancer';
  status: NodeStatus;
  ip: string;
  port: number;
  cve: string;
  cvss: number;
  description: string;
  position: { x: number; y: number };
}

export interface TwinEdge {
  id: string;
  source: string;
  target: string;
  label?: string;
  protocol?: string;
  accessState?: 'open' | 'restricted' | 'blocked';
}

export interface RemediationPatch {
  title: string;
  cve: string;
  targetNodeId: string;
  humanExplanation: string;
  machineAction: string;
  diffSnippet: string;
}

export interface SimulationStep {
  delayMs: number;
  targetNodeId: string;
  targetStatus: NodeStatus;
  log: string;
  logLevel: 'info' | 'warn' | 'crit' | 'success';
}

export interface TemplateArchitecture {
  id: string;
  name: string;
  category: string;
  description: string;
  initialNodes: TwinNode[];
  edges: TwinEdge[];
  steps: SimulationStep[];
  patch: RemediationPatch;
}

export const TEMPLATES: Record<string, TemplateArchitecture> = {
  ecommerce: {
    id: 'ecommerce',
    name: 'E-Commerce Cloud',
    category: 'Retail & Multi-Tier Web Architecture',
    description: 'Public-facing load balanced web store with isolated internal microservices and relational customer database.',
    initialNodes: [
      {
        id: 'Load-Balancer',
        name: 'Load-Balancer',
        type: 'load_balancer',
        status: 'idle',
        ip: '198.51.100.12',
        port: 443,
        cve: 'N/A',
        cvss: 0.0,
        description: 'AWS ALB with Cloud Armor WAF and SSL Termination',
        position: { x: 50, y: 140 },
      },
      {
        id: 'Web-Frontend',
        name: 'Web-Frontend',
        type: 'server',
        status: 'idle',
        ip: '10.0.1.24',
        port: 3000,
        cve: 'CVE-2024-21338',
        cvss: 9.8,
        description: 'Next.js / Node.js 18 SSR application container',
        position: { x: 280, y: 80 },
      },
      {
        id: 'Auth-Service',
        name: 'Auth-Service',
        type: 'server',
        status: 'idle',
        ip: '10.0.2.15',
        port: 8080,
        cve: 'CVE-2023-44487',
        cvss: 7.5,
        description: 'OAuth2 / JWT Token Authority service',
        position: { x: 280, y: 220 },
      },
      {
        id: 'Postgres-DB',
        name: 'Postgres-DB',
        type: 'database',
        status: 'idle',
        ip: '10.0.3.50',
        port: 5432,
        cve: 'CWE-89 (SQLi Traversal)',
        cvss: 9.1,
        description: 'Primary customer orders and credentials database',
        position: { x: 540, y: 150 },
      },
    ],
    edges: [
      { id: 'e1', source: 'Load-Balancer', target: 'Web-Frontend', label: 'HTTP/2 :3000', protocol: 'TCP' },
      { id: 'e2', source: 'Load-Balancer', target: 'Auth-Service', label: 'gRPC :8080', protocol: 'TCP' },
      { id: 'e3', source: 'Web-Frontend', target: 'Postgres-DB', label: 'SQL :5432 (Unsegmented)', protocol: 'TCP' },
      { id: 'e4', source: 'Auth-Service', target: 'Postgres-DB', label: 'SQL :5432', protocol: 'TCP' },
    ],
    steps: [
      {
        delayMs: 1000,
        targetNodeId: 'Web-Frontend',
        targetStatus: 'scanning',
        log: '[INFO] Traversing edge to Web-Frontend via ALB perimeter ingress (:443 -> :3000)...',
        logLevel: 'info',
      },
      {
        delayMs: 3000,
        targetNodeId: 'Web-Frontend',
        targetStatus: 'compromised',
        log: '[CRIT] CVE-2024-21338 exploited on Web-Frontend. Remote Code Execution verified. Blast radius: High.',
        logLevel: 'crit',
      },
      {
        delayMs: 4500,
        targetNodeId: 'Postgres-DB',
        targetStatus: 'scanning',
        log: '[WARN] Lateral pivot validated: Ingress subnet route to Postgres-DB (10.0.3.50:5432) lacks Network Security Group isolation.',
        logLevel: 'warn',
      },
      {
        delayMs: 5500,
        targetNodeId: 'Postgres-DB',
        targetStatus: 'compromised',
        log: '[CRIT] Unauthenticated database query succeeded on Postgres-DB. 15,000 synthetic customer records reachable.',
        logLevel: 'crit',
      },
      {
        delayMs: 6500,
        targetNodeId: 'Load-Balancer',
        targetStatus: 'safe',
        log: '[SUCCESS] Exposure validation complete. Target blast radius confirmed. Synthesizing immutable remediation patch...',
        logLevel: 'success',
      },
    ],
    patch: {
      title: 'Enforce VPC Subnet Network ACL & Restrict DB Ingress',
      cve: 'CVE-2024-21338 / Lateral Pivoting',
      targetNodeId: 'Web-Frontend',
      humanExplanation: 'Restricts direct database connections from the public web frontend subnet. Forces authentication through an isolated internal API proxy and updates Node.js runtime container dependencies.',
      machineAction: 'APPLY_FIREWALL_RULE_AND_CONTAINER_PATCH',
      diffSnippet: `--- a/infra/security_groups.tf
+++ b/infra/security_groups.tf
@@ -14,6 +14,8 @@ resource "aws_security_group_rule" "db_ingress" {
-  cidr_blocks = ["10.0.0.0/16"]  # Overly permissive ingress
+  cidr_blocks = ["10.0.2.0/24"]  # Auth-Service subnet only
+  security_group_id = aws_security_group.db.id
+  from_port         = 5432
+  to_port           = 5432
+  protocol          = "tcp"
 }`,
    },
  },

  healthcare: {
    id: 'healthcare',
    name: 'Healthcare PACS',
    category: 'HIPAA Regulated Clinical Imaging Network',
    description: 'Enterprise Picture Archiving and Communication System containing sensitive DICOM imaging and patient PHI.',
    initialNodes: [
      {
        id: 'VPN-Gateway',
        name: 'VPN-Gateway',
        type: 'firewall',
        status: 'idle',
        ip: '203.0.113.88',
        port: 1194,
        cve: 'CVE-2023-46805',
        cvss: 8.2,
        description: 'Perimeter SSL-VPN Gateway for remote radiologist workstations',
        position: { x: 50, y: 150 },
      },
      {
        id: 'Internal-API',
        name: 'Internal-API',
        type: 'server',
        status: 'idle',
        ip: '172.16.4.10',
        port: 8443,
        cve: 'CVE-2024-27198',
        cvss: 9.8,
        description: 'Internal DICOM Router & Patient Routing Service',
        position: { x: 300, y: 150 },
      },
      {
        id: 'Patient-Records-DB',
        name: 'Patient-Records-DB',
        type: 'database',
        status: 'idle',
        ip: '172.16.5.99',
        port: 27017,
        cve: 'CWE-284 (Improper Access Control)',
        cvss: 9.4,
        description: 'Encrypted MongoDB cluster storing 85,000 synthetic patient records',
        position: { x: 560, y: 150 },
      },
    ],
    edges: [
      { id: 'h1', source: 'VPN-Gateway', target: 'Internal-API', label: 'TLS :8443 (Direct Tunnel)', protocol: 'TCP' },
      { id: 'h2', source: 'Internal-API', target: 'Patient-Records-DB', label: 'Mongo Wire :27017', protocol: 'TCP' },
      { id: 'h3', source: 'VPN-Gateway', target: 'Patient-Records-DB', label: 'Lateral Route (Unchecked)', protocol: 'TCP' },
    ],
    steps: [
      {
        delayMs: 1000,
        targetNodeId: 'VPN-Gateway',
        targetStatus: 'scanning',
        log: '[INFO] Traversing edge to VPN-Gateway perimeter (203.0.113.88:1194)...',
        logLevel: 'info',
      },
      {
        delayMs: 3000,
        targetNodeId: 'VPN-Gateway',
        targetStatus: 'compromised',
        log: '[CRIT] CVE-2023-46805 authentication bypass verified on VPN-Gateway. Internal routing session established.',
        logLevel: 'crit',
      },
      {
        delayMs: 4500,
        targetNodeId: 'Internal-API',
        targetStatus: 'compromised',
        log: '[CRIT] Lateral hop executed: Internal-API breached via administrative token replay. DICOM proxy hijacked.',
        logLevel: 'crit',
      },
      {
        delayMs: 5500,
        targetNodeId: 'Patient-Records-DB',
        targetStatus: 'compromised',
        log: '[CRIT] PHI Exfiltration Path Confirmed: Direct access to Patient-Records-DB (172.16.5.99:27017). Blast Radius: CRITICAL (HIPAA Impact).',
        logLevel: 'crit',
      },
      {
        delayMs: 6500,
        targetNodeId: 'VPN-Gateway',
        targetStatus: 'compromised',
        log: '[SUCCESS] Exposure validation complete. Automated remediation policy generated.',
        logLevel: 'success',
      },
    ],
    patch: {
      title: 'Patch Perimeter SSL-VPN & Enforce Zero-Trust Microsegmentation',
      cve: 'CVE-2023-46805 / DICOM Pipeline',
      targetNodeId: 'VPN-Gateway',
      humanExplanation: 'Updates the SSL-VPN gateway firmware to mitigate authentication bypass and isolates the clinical imaging database inside an egress-locked subnet accessible strictly via mutual TLS.',
      machineAction: 'APPLY_FIRMWARE_UPGRADE_AND_MTLS',
      diffSnippet: `--- a/network/firewall_rules.json
+++ b/network/firewall_rules.json
@@ -8,7 +8,11 @@
-  "allow_vpn_to_db": true,
+  "allow_vpn_to_db": false,
+  "require_mtls_client_cert": true,
+  "isolate_phi_subnet": {
+    "subnet": "172.16.5.0/24",
+    "permitted_sources": ["172.16.4.10/32"]
+  }
 }`,
    },
  },
};
