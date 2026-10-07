export type NodeType = 'ingress' | 'load_balancer' | 'compute' | 'database' | 'iam_role' | 'server' | 'firewall';
export type NodeStatus = 'healthy' | 'probing' | 'compromised' | 'patched' | 'targeted' | 'idle' | 'scanning' | 'safe';

export interface NodeService {
  port: number;
  protocol: 'TCP' | 'UDP';
  serviceName: string;
  version: string;
  cve?: string;
  vulnerable: boolean;
}

export interface TwinNodeData {
  id: string;
  label?: string;
  name?: string;
  type: NodeType;
  ipAddress?: string;
  ip?: string;
  port?: number;
  subnet?: string;
  os?: string;
  services?: NodeService[];
  criticality?: number; // 1 (Edge) to 10 (Core Database)
  status: NodeStatus;
  syntheticRecordsCount?: number;
  cve?: string;
  cvss?: number;
  description?: string;
  position?: { x: number; y: number };
  [key: string]: unknown;
}

export interface TwinEdgeData {
  id: string;
  source: string;
  target: string;
  allowedPorts: number[];
  protocol: 'TCP' | 'UDP' | 'ANY';
  accessState: 'open' | 'restricted' | 'blocked';
  isTraversed: boolean;
  label?: string;
}

export interface TelemetryEvent {
  id: string;
  timestamp: string; // HH:mm:ss.SSS
  step: 'INGRESS_DISCOVERY' | 'PORT_EVALUATION' | 'EXPLOIT_VERIFIED' | 'LATERAL_PIVOT' | 'BLAST_RADIUS_ESTABLISHED';
  severity: 'INFO' | 'WARN' | 'CRIT' | 'SUCCESS';
  targetNodeId: string;
  targetIp: string;
  message: string;
}

export interface RemediationPatch {
  title: string;
  cve: string;
  targetEdgeId: string;
  targetNodeId: string;
  humanExplanation: string;
  machineAction: string;
  diffSnippet: string;
}

export interface ArchitectureTemplate {
  id: string;
  name: string;
  category: string;
  description: string;
  nodes: TwinNodeData[];
  edges: TwinEdgeData[];
  patch: RemediationPatch;
}

// 1. E-COMMERCE CLOUD VPC TEMPLATE
export const ecommerceTemplate: ArchitectureTemplate = {
  id: 'ecommerce',
  name: 'Enterprise Cloud VPC (E-Commerce Stack)',
  category: 'Retail & Multi-Tier Cloud VPC',
  description: 'Public AWS ALB ingress routing to Node.js compute, which possesses unrestricted lateral access to the primary customer PostgreSQL database.',
  nodes: [
    {
      id: 'node-ingress-alb',
      label: 'AWS ALB Ingress',
      name: 'AWS ALB Ingress',
      type: 'load_balancer',
      ipAddress: '198.51.100.12',
      ip: '198.51.100.12',
      port: 443,
      subnet: '0.0.0.0/0 (Internet Ingress)',
      os: 'AWS Managed ALB',
      services: [
        {
          port: 443,
          protocol: 'TCP',
          serviceName: 'HTTPS Reverse Proxy',
          version: 'AWS ALB v2',
          vulnerable: false,
        },
      ],
      criticality: 4,
      status: 'healthy',
      position: { x: 40, y: 140 },
      description: 'Public Internet Gateway with TLS termination and AWS WAF rule enforcement.',
    },
    {
      id: 'node-web-api',
      label: 'Node.js API Gateway',
      name: 'Node.js API Gateway',
      type: 'compute',
      ipAddress: '10.0.1.15',
      ip: '10.0.1.15',
      port: 3000,
      subnet: '10.0.1.0/24 (Public DMZ)',
      os: 'Debian Linux 12 (Kernel 6.1)',
      services: [
        {
          port: 3000,
          protocol: 'TCP',
          serviceName: 'Reverse Proxy API',
          version: 'Express 4.18.2',
          cve: 'CVE-2024-21338',
          vulnerable: true,
        },
      ],
      criticality: 7,
      status: 'healthy',
      cve: 'CVE-2024-21338',
      cvss: 9.8,
      position: { x: 290, y: 80 },
      description: 'API gateway serving public endpoints with misconfigured reverse-proxy path evaluation.',
    },
    {
      id: 'node-auth-svc',
      label: 'Auth Microservice',
      name: 'Auth Microservice',
      type: 'compute',
      ipAddress: '10.0.2.40',
      ip: '10.0.2.40',
      port: 8080,
      subnet: '10.0.2.0/24 (Internal Core)',
      os: 'Alpine Linux 3.19',
      services: [
        {
          port: 8080,
          protocol: 'TCP',
          serviceName: 'OAuth2 Token Authority',
          version: 'Go-OAuth v1.4',
          cve: 'CVE-2023-44487',
          vulnerable: false,
        },
      ],
      criticality: 6,
      status: 'healthy',
      position: { x: 290, y: 220 },
      description: 'Internal authentication server providing ephemeral JWT and machine-to-machine tokens.',
    },
    {
      id: 'node-postgres-db',
      label: 'PostgreSQL Main DB',
      name: 'PostgreSQL Main DB',
      type: 'database',
      ipAddress: '10.0.3.100',
      ip: '10.0.3.100',
      port: 5432,
      subnet: '10.0.3.0/24 (Restricted DB Tier)',
      os: 'Ubuntu 22.04 LTS (RDS)',
      services: [
        {
          port: 5432,
          protocol: 'TCP',
          serviceName: 'PostgreSQL Relational Engine',
          version: '15.4',
          cve: 'CVE-2023-39417',
          vulnerable: true,
        },
      ],
      criticality: 10,
      status: 'healthy',
      syntheticRecordsCount: 50000,
      cve: 'CVE-2023-39417',
      cvss: 8.8,
      position: { x: 550, y: 150 },
      description: 'Core customer transactional database containing 50,000 synthetic PII and payment records.',
    },
  ],
  edges: [
    {
      id: 'edge-alb-web',
      source: 'node-ingress-alb',
      target: 'node-web-api',
      allowedPorts: [443, 3000],
      protocol: 'TCP',
      accessState: 'open',
      isTraversed: false,
      label: 'TCP :443 -> :3000',
    },
    {
      id: 'edge-web-db',
      source: 'node-web-api',
      target: 'node-postgres-db',
      allowedPorts: [5432],
      protocol: 'TCP',
      accessState: 'open',
      isTraversed: false,
      label: 'TCP :5432 (Unsegmented)',
    },
    {
      id: 'edge-alb-auth',
      source: 'node-ingress-alb',
      target: 'node-auth-svc',
      allowedPorts: [443, 8080],
      protocol: 'TCP',
      accessState: 'restricted',
      isTraversed: false,
      label: 'TCP :8080 (Restricted)',
    },
  ],
  patch: {
    title: 'Postgres Subnet Firewall Hardening',
    cve: 'CWE-284 (Permissive Internal Exposure)',
    targetEdgeId: 'edge-web-db',
    targetNodeId: 'node-postgres-db',
    humanExplanation:
      'The web server subnet (10.0.1.0/24) maintains direct unsegmented access to the database port (5432). Applying a security group rule restricts Port 5432 exclusively to backend authenticated worker pools, neutralizing lateral pivot.',
    machineAction: 'aws ec2 authorize-security-group-egress --group-id sg-web --protocol tcp --port 5432 --cidr 10.0.3.100/32',
    diffSnippet: `--- a/terraform/security_groups.tf
+++ b/terraform/security_groups.tf
@@ -14,7 +14,8 @@ resource "aws_security_group_rule" "db_ingress" {
   type              = "ingress"
   from_port         = 5432
   to_port           = 5432
   protocol          = "tcp"
-  cidr_blocks       = ["10.0.0.0/16"] # Flaw: Permissive VPC wide access
+  cidr_blocks       = ["10.0.2.0/24"] # Patched: Internal App Tier Only
+  security_group_id = aws_security_group.db.id
 }`,
  },
};

// 2. HEALTHCARE PACS NETWORK TEMPLATE
export const healthcareTemplate: ArchitectureTemplate = {
  id: 'healthcare',
  name: 'Healthcare PACS Network (HIPAA Regulated)',
  category: 'Healthcare & Medical Devices',
  description: 'External VPN Gateway connecting to DICOM Medical Imaging Server, with direct unencrypted communication into the Patient Health Information (PHI) archive.',
  nodes: [
    {
      id: 'node-vpn-gateway',
      label: 'External VPN Gateway',
      name: 'External VPN Gateway',
      type: 'ingress',
      ipAddress: '192.0.2.55',
      ip: '192.0.2.55',
      port: 1194,
      subnet: '0.0.0.0/0 (Perimeter Gateway)',
      os: 'OpenVPN Access Server 2.11',
      services: [
        {
          port: 1194,
          protocol: 'UDP',
          serviceName: 'OpenVPN Daemon',
          version: '2.11.0',
          vulnerable: false,
        },
      ],
      criticality: 5,
      status: 'healthy',
      position: { x: 40, y: 140 },
      description: 'Perimeter tunnel gateway for clinical staff tele-radiology remote access.',
    },
    {
      id: 'node-dicom-viewer',
      label: 'DICOM Imaging Server',
      name: 'DICOM Imaging Server',
      type: 'compute',
      ipAddress: '172.16.4.12',
      ip: '172.16.4.12',
      port: 8042,
      subnet: '172.16.4.0/24 (Radiology VLAN)',
      os: 'Red Hat Enterprise Linux 8.8',
      services: [
        {
          port: 8042,
          protocol: 'TCP',
          serviceName: 'Orthanc DICOM Web API',
          version: '1.9.7',
          cve: 'CVE-2023-33476',
          vulnerable: true,
        },
      ],
      criticality: 8,
      status: 'healthy',
      cve: 'CVE-2023-33476',
      cvss: 9.1,
      position: { x: 290, y: 140 },
      description: 'Web-accessible picture archiving and communication system (PACS) viewer with unauthenticated REST endpoint.',
    },
    {
      id: 'node-phi-db',
      label: 'Patient PHI Archive',
      name: 'Patient PHI Archive',
      type: 'database',
      ipAddress: '172.16.10.88',
      ip: '172.16.10.88',
      port: 27017,
      subnet: '172.16.10.0/24 (HIPAA Vault)',
      os: 'RHEL 9 Hardened Storage Node',
      services: [
        {
          port: 27017,
          protocol: 'TCP',
          serviceName: 'MongoDB PHI Store',
          version: '6.0.4',
          cve: 'CVE-2023-1408',
          vulnerable: true,
        },
      ],
      criticality: 10,
      status: 'healthy',
      syntheticRecordsCount: 120000,
      cve: 'CVE-2023-1408',
      cvss: 9.4,
      position: { x: 550, y: 140 },
      description: 'Protected Health Information database containing 120,000 synthetic patient health records.',
    },
  ],
  edges: [
    {
      id: 'edge-vpn-dicom',
      source: 'node-vpn-gateway',
      target: 'node-dicom-viewer',
      allowedPorts: [1194, 8042],
      protocol: 'TCP',
      accessState: 'open',
      isTraversed: false,
      label: 'TCP :8042 (Permissive)',
    },
    {
      id: 'edge-dicom-phi',
      source: 'node-dicom-viewer',
      target: 'node-phi-db',
      allowedPorts: [27017],
      protocol: 'TCP',
      accessState: 'open',
      isTraversed: false,
      label: 'TCP :27017 (Unencrypted)',
    },
  ],
  patch: {
    title: 'HIPAA Microsegmentation & Port Lockdown',
    cve: 'HIPAA Security Rule § 164.312(a)(1)',
    targetEdgeId: 'edge-dicom-phi',
    targetNodeId: 'node-phi-db',
    humanExplanation:
      'The DICOM viewer possesses unrestricted routing to the database port 27017 across VLAN boundaries. Applying an explicit host-based iptables filter blocks the port from unverified viewer processes and terminates the lateral pivot.',
    machineAction: 'iptables -A INPUT -p tcp -s 172.16.4.12 --dport 27017 -j DROP; systemctl restart netfilter-persistent',
    diffSnippet: `--- a/firewall/rules.v4
+++ b/firewall/rules.v4
@@ -10,6 +10,7 @@
 # HIPAA Vault Isolation Rules
 -A INPUT -p tcp -s 172.16.4.0/24 --dport 27017 -j ACCEPT
+-A INPUT -p tcp --dport 27017 -m conntrack --ctstate NEW -j DROP
+# Dropped unauthenticated DICOM pivoting vector
 COMMIT`,
  },
};

export const TEMPLATES: Record<string, ArchitectureTemplate> = {
  ecommerce: ecommerceTemplate,
  healthcare: healthcareTemplate,
};

// Aliases for backwards compatibility with any legacy imports
export type TwinNode = TwinNodeData;
export type TwinEdge = TwinEdgeData;
export type TemplateArchitecture = ArchitectureTemplate;
