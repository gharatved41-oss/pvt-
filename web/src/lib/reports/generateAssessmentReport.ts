import { jsPDF } from 'jspdf';
import autoTable from 'jspdf-autotable';

// =============================================================================
// EXECUTIVE SECURITY ASSESSMENT REPORT GENERATOR (PDF EXPORTER)
// =============================================================================

export interface ReportVulnerabilityItem {
  assetId: string;
  weaknessOrCve: string;
  pathLength: number;
  status: 'EXPLOITABLE' | 'VERIFIED_FIXED' | 'THEORETICAL_ONLY';
}

export interface ReportAssessmentData {
  organizationName?: string;
  environmentId: string;
  targetDomain: string;
  assessmentDate?: string;
  riskScore: number;
  compoundRiskLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  totalAssets: number;
  totalEdges: number;
  validatedPathsCount: number;
  theoreticalFilteredCount: number;
  syntheticRecordsExposed: number;
  vulnerabilities: ReportVulnerabilityItem[];
  remediationSummary?: string;
  remediationSnippet?: string;
  verificationEvidence?: {
    attackBlocked: boolean;
    blastRadiusReduced: boolean;
    verificationTimestamp: string;
  };
}

/**
 * generateExecutivePdf
 * Produces an audit-ready, formal white-paper executive PDF document using jsPDF.
 */
export function generateExecutivePdf(data: ReportAssessmentData): jsPDF {
  const doc = new jsPDF({
    orientation: 'portrait',
    unit: 'mm',
    format: 'a4',
  });

  const pageWidth = doc.internal.pageSize.getWidth();
  const dateStr = data.assessmentDate || new Date().toISOString().split('T')[0];

  // 1. Formal Dark Header Banner (Dark Slate / Charcoal)
  doc.setFillColor(9, 9, 11); // #09090b
  doc.rect(0, 0, pageWidth, 28, 'F');

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(14);
  doc.setTextColor(250, 250, 250);
  doc.text('VULNTWIN AI', 14, 12);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8);
  doc.setTextColor(161, 161, 170);
  doc.text('CONTINUOUS ADVERSARIAL EXPOSURE VALIDATION (AEV) REPORT', 14, 18);
  doc.text('AUDIT-READY EXECUTIVE ASSESSMENT', 14, 23);

  // Date and Scope in Top Right
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8);
  doc.setTextColor(212, 212, 216);
  doc.text(`Date: ${dateStr}`, pageWidth - 14, 12, { align: 'right' });
  doc.text(`Scope: ${data.targetDomain}`, pageWidth - 14, 18, { align: 'right' });
  doc.text(`Env ID: ${data.environmentId}`, pageWidth - 14, 23, { align: 'right' });

  // 2. Metadata & Risk Score KPI Callout
  let currentY = 36;

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(12);
  doc.setTextColor(24, 24, 27);
  doc.text('1. Executive Overview & Risk Posture', 14, currentY);

  currentY += 6;

  // Draw Risk KPI Box
  const riskBoxWidth = 85;
  const riskBoxHeight = 22;

  // Border and Fill
  doc.setFillColor(244, 244, 245);
  doc.setDrawColor(212, 212, 216);
  doc.rect(14, currentY, riskBoxWidth, riskBoxHeight, 'FD');

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(8);
  doc.setTextColor(82, 82, 91);
  doc.text('COMPOUND RISK SCORE', 18, currentY + 6);

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(16);
  if (data.riskScore >= 60) {
    doc.setTextColor(220, 38, 38); // Crimson Red
  } else if (data.riskScore >= 30) {
    doc.setTextColor(217, 119, 6); // Amber
  } else {
    doc.setTextColor(16, 185, 129); // Emerald Green
  }
  doc.text(`${data.riskScore} / 100`, 18, currentY + 15);

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(9);
  doc.text(`[${data.compoundRiskLevel}]`, 56, currentY + 15);

  // Secondary Metadata Box
  const metaBoxX = 104;
  const metaBoxWidth = pageWidth - 14 - metaBoxX;
  doc.setFillColor(244, 244, 245);
  doc.rect(metaBoxX, currentY, metaBoxWidth, riskBoxHeight, 'FD');

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(8);
  doc.setTextColor(82, 82, 91);
  doc.text('ORGANIZATION & TENANT', metaBoxX + 4, currentY + 6);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(9);
  doc.setTextColor(24, 24, 27);
  doc.text(data.organizationName || 'VulnTwin Enterprise Client', metaBoxX + 4, currentY + 12);
  doc.setFontSize(8);
  doc.setTextColor(113, 113, 122);
  doc.text(`Digital Twin Nodes: ${data.totalAssets}  |  Network Rules: ${data.totalEdges}`, metaBoxX + 4, currentY + 17);

  currentY += 28;

  // 3. Executive Summary KPI Table (jspdf-autotable)
  autoTable(doc, {
    startY: currentY,
    theme: 'grid',
    head: [['Metric', 'Value', 'Methodology & Context']],
    body: [
      ['Total Cloud Assets Modeled', `${data.totalAssets} Nodes`, 'Ingested VPC topology, firewalls, and application microservices.'],
      ['Validated Exposure Paths', `${data.validatedPathsCount} Paths`, 'Multi-hop lateral attack trajectories mathematically proven traversable.'],
      ['Theoretical Warnings Filtered', `${data.theoreticalFilteredCount} CVEs`, 'False positives safely dropped due to verified network isolation.'],
      ['Proven Blast Radius', `${data.syntheticRecordsExposed.toLocaleString()} Records`, 'Synthetic data records exposed without exposing live production PII.'],
    ],
    styles: {
      font: 'helvetica',
      fontSize: 8,
      cellPadding: 3,
      textColor: [39, 39, 42],
    },
    headStyles: {
      fillColor: [24, 24, 27],
      textColor: [250, 250, 250],
      fontStyle: 'bold',
      fontSize: 8,
    },
    alternateRowStyles: {
      fillColor: [250, 250, 250],
    },
    margin: { left: 14, right: 14 },
  });

  currentY = (doc as unknown as { lastAutoTable: { finalY: number } }).lastAutoTable.finalY + 10;

  // 4. Validated Vulnerability Findings Details Table
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(12);
  doc.setTextColor(24, 24, 27);
  doc.text('2. Validated Vulnerabilities & Attack Chains', 14, currentY);

  currentY += 4;

  const vulnRows = data.vulnerabilities.map((v) => [
    v.assetId,
    v.weaknessOrCve,
    `${v.pathLength} hops`,
    v.status,
  ]);

  autoTable(doc, {
    startY: currentY,
    theme: 'grid',
    head: [['Target Asset ID', 'Identified Weakness / Vector', 'Lateral Depth', 'AEV Verdict']],
    body: vulnRows.length > 0 ? vulnRows : [['N/A', 'No critical exposure paths detected', '0 hops', 'DEFENDED']],
    styles: {
      font: 'helvetica',
      fontSize: 8,
      cellPadding: 3,
      textColor: [39, 39, 42],
    },
    headStyles: {
      fillColor: [39, 39, 42],
      textColor: [250, 250, 250],
      fontStyle: 'bold',
    },
    alternateRowStyles: {
      fillColor: [250, 250, 250],
    },
    columnStyles: {
      0: { font: 'courier', fontStyle: 'bold', cellWidth: 45 },
      1: { cellWidth: 80 },
      2: { cellWidth: 25 },
      3: { cellWidth: 32, fontStyle: 'bold' },
    },
    margin: { left: 14, right: 14 },
  });

  currentY = (doc as unknown as { lastAutoTable: { finalY: number } }).lastAutoTable.finalY + 10;

  // 5. Remediation & Proof of Fix Section
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(12);
  doc.setTextColor(24, 24, 27);
  doc.text('3. Remediation & Verified Proof of Fix (AEV Re-Test)', 14, currentY);

  currentY += 5;

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8);
  doc.setTextColor(82, 82, 91);
  const summaryText = data.remediationSummary || 
    'The automated remediation loop synthesized a targeted infrastructure patch, applied it to the digital twin sandbox, and executed regression tests to mathematically prove the lateral attack trajectory is defended.';
  const splitSummary = doc.splitTextToSize(summaryText, pageWidth - 28);
  doc.text(splitSummary, 14, currentY);

  currentY += splitSummary.length * 4 + 4;

  // Monospaced Configuration Snippet Box
  if (data.remediationSnippet) {
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8);
    doc.setTextColor(24, 24, 27);
    doc.text('Verified Infrastructure-as-Code Configuration (IaC):', 14, currentY);

    currentY += 3;

    const snippetLines = data.remediationSnippet.split('\n').slice(0, 10);
    const boxHeight = snippetLines.length * 3.5 + 6;

    doc.setFillColor(24, 24, 27);
    doc.rect(14, currentY, pageWidth - 28, boxHeight, 'F');

    doc.setFont('courier', 'normal');
    doc.setFontSize(7);
    doc.setTextColor(228, 228, 231);

    snippetLines.forEach((line, idx) => {
      doc.text(line, 18, currentY + 5 + idx * 3.5);
    });

    currentY += boxHeight + 8;
  }

  // 6. Formal Footer Sign-Off
  doc.setDrawColor(212, 212, 216);
  doc.line(14, 280, pageWidth - 14, 280);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(7);
  doc.setTextColor(113, 113, 122);
  doc.text('VulnTwin AI Continuous Security Validation Platform | Enterprise Kernel v3.0', 14, 285);
  doc.text('Confidential - For Designated Cybersecurity & Compliance Personnel Only', pageWidth - 14, 285, { align: 'right' });

  return doc;
}

/**
 * downloadExecutivePdf
 * Generates and triggers a browser file download of the assessment report.
 */
export function downloadExecutivePdf(data: ReportAssessmentData, filename?: string): void {
  const doc = generateExecutivePdf(data);
  const name = filename || `VulnTwin_Executive_Report_${data.environmentId}_${Date.now()}.pdf`;
  doc.save(name);
}
