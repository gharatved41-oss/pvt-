import io
import csv
import html
from datetime import datetime, timezone
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, KeepTogether
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from typing import Dict, Any, List

class ReportGenerator:
    @staticmethod
    def generate_csv(assessment: Any, findings: List[Any], asset: Any) -> str:
        """Generate comprehensive CSV security report."""
        output = io.StringIO()
        writer = csv.writer(output)

        # Header metadata
        writer.writerow(["Vuln TWin Security Assessment Report - CSV Export"])
        writer.writerow(["Report Date", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")])
        writer.writerow(["Assessment ID", assessment.id])
        writer.writerow(["Assessment Title", assessment.title])
        writer.writerow(["Asset Name", asset.name])
        writer.writerow(["Asset IP", asset.ip_address])
        writer.writerow(["Asset OS", f"{asset.os_type} ({asset.os_version})"])
        writer.writerow(["Environment", asset.environment])
        writer.writerow(["Criticality", asset.criticality])
        writer.writerow([])

        # Table header
        writer.writerow([
            "CVE ID",
            "Title",
            "Affected Component",
            "Installed Version",
            "Fixed Version",
            "Severity",
            "CVSS Score",
            "Risk Score (0-100)",
            "Risk Category",
            "Recommended Priority",
            "Detection Status",
            "Remediation Summary",
            "References"
        ])

        for f in findings:
            writer.writerow([
                f.cve_id,
                f.title,
                f.affected_component,
                f.installed_version,
                f.fixed_version,
                f.severity.capitalize(),
                f.cvss_v3_score,
                f.risk_score,
                f.risk_category,
                f.recommended_priority,
                f.detection_status,
                f.remediation_summary or (f.description[:100] + "..."),
                "; ".join(f.references or [])
            ])

        return output.getvalue()

    @staticmethod
    def generate_pdf(assessment: Any, findings: List[Any], asset: Any, retest_results: List[Any] = None) -> bytes:
        """Generate high-fidelity, styled PDF assessment report."""
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36
        )

        styles = getSampleStyleSheet()
        
        # Custom styles with dark cyber branding
        title_style = ParagraphStyle(
            'ReportTitle',
            parent=styles['Heading1'],
            fontName='Helvetica-Bold',
            fontSize=22,
            leading=26,
            textColor=colors.HexColor('#0f172a')
        )
        subtitle_style = ParagraphStyle(
            'ReportSubtitle',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=11,
            leading=15,
            textColor=colors.HexColor('#475569')
        )
        h2_style = ParagraphStyle(
            'SectionH2',
            parent=styles['Heading2'],
            fontName='Helvetica-Bold',
            fontSize=14,
            leading=18,
            textColor=colors.HexColor('#1e293b'),
            spaceBefore=14,
            spaceAfter=6
        )
        body_style = ParagraphStyle(
            'Body',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=9,
            leading=13,
            textColor=colors.HexColor('#334155')
        )
        callout_style = ParagraphStyle(
            'Callout',
            parent=styles['Normal'],
            fontName='Helvetica-Oblique',
            fontSize=8,
            leading=11,
            textColor=colors.HexColor('#64748b')
        )

        elements = []

        # Header Title
        elements.append(Paragraph("<b>VULN TWIN</b> | Comprehensive Security Assessment Report", title_style))
        elements.append(Paragraph(
            f"Generated: {datetime.now(timezone.utc).strftime('%B %d, %Y - %H:%M:%S UTC')} | Report ID: VT-{assessment.id[:8].upper()}",
            subtitle_style
        ))
        elements.append(Spacer(1, 12))
        elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0284c7"), spaceAfter=14))

        # Executive Summary
        elements.append(Paragraph("1. Executive Summary", h2_style))
        summary_text = (
            f"This security assessment evaluated asset <b>{html.escape(asset.name)}</b> ({html.escape(asset.ip_address)}) "
            f"running <b>{html.escape(asset.os_type.capitalize())} {html.escape(asset.os_version)}</b> in the "
            f"<b>{html.escape(asset.environment)}</b> tier. Vulnerabilities were analyzed using AI/ML risk scoring and "
            f"controlled digital twin sandbox verification to isolate actual exploitability without production risk. "
            f"A total of <b>{len(findings)}</b> vulnerability findings were discovered, with an average realized risk score of "
            f"<b>{assessment.average_risk_score}/100</b>."
        )
        elements.append(Paragraph(summary_text, body_style))
        elements.append(Spacer(1, 10))

        # Asset & Assessment Details Table
        meta_data = [
            [Paragraph("<b>Target Hostname:</b>", body_style), Paragraph(html.escape(asset.hostname), body_style),
             Paragraph("<b>Assessment Status:</b>", body_style), Paragraph(html.escape(assessment.status.upper()), body_style)],
            [Paragraph("<b>IP Address:</b>", body_style), Paragraph(html.escape(asset.ip_address), body_style),
             Paragraph("<b>Findings Total:</b>", body_style), Paragraph(str(len(findings)), body_style)],
            [Paragraph("<b>Critical Findings:</b>", body_style), Paragraph(f"<font color='#dc2626'><b>{assessment.critical_count}</b></font>", body_style),
             Paragraph("<b>High Findings:</b>", body_style), Paragraph(f"<font color='#ea580c'><b>{assessment.high_count}</b></font>", body_style)],
            [Paragraph("<b>Asset Criticality:</b>", body_style), Paragraph(html.escape(asset.criticality.upper()), body_style),
             Paragraph("<b>Lab Twin Tested:</b>", body_style), Paragraph("Isolated Sandbox Replica", body_style)]
        ]
        meta_table = Table(meta_data, colWidths=[110, 150, 110, 150])
        meta_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f8fafc')),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#cbd5e1')),
            ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('PADDING', (0,0), (-1,-1), 5),
        ]))
        elements.append(meta_table)
        elements.append(Spacer(1, 14))

        # Vulnerability Findings Table
        elements.append(Paragraph("2. Prioritized Vulnerability Findings", h2_style))
        findings_data = [
            [
                Paragraph("<b>CVE / Finding</b>", body_style),
                Paragraph("<b>Component</b>", body_style),
                Paragraph("<b>CVSS / Sev</b>", body_style),
                Paragraph("<b>ML Risk</b>", body_style),
                Paragraph("<b>Status</b>", body_style),
                Paragraph("<b>Recommended Action</b>", body_style),
            ]
        ]

        for f in findings:
            sev_color = "#dc2626" if f.severity == "critical" else ("#ea580c" if f.severity == "high" else "#0284c7")
            status_color = "#16a34a" if f.detection_status == "confirmed" else ("#0284c7" if f.detection_status == "detected" else "#64748b")
            findings_data.append([
                Paragraph(f"<b>{html.escape(f.cve_id)}</b><br/><font color='#64748b'>{html.escape(f.title[:38])}</font>", body_style),
                Paragraph(f"{html.escape(f.affected_component)}<br/><font color='#64748b'>{html.escape(f.installed_version)}</font>", body_style),
                Paragraph(f"<font color='{sev_color}'><b>{f.cvss_v3_score} ({f.severity.upper()})</b></font>", body_style),
                Paragraph(f"<b>{f.risk_score}</b><br/>{html.escape(f.recommended_priority[:2])}", body_style),
                Paragraph(f"<font color='{status_color}'><b>{html.escape(f.detection_status.upper())}</b></font>", body_style),
                Paragraph(html.escape(f.fixed_version or "Patch available"), body_style),
            ])

        findings_table = Table(findings_data, colWidths=[130, 95, 75, 55, 75, 90])
        findings_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0f172a')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#cbd5e1')),
            ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('PADDING', (0,0), (-1,-1), 4),
        ]))
        elements.append(findings_table)
        elements.append(Spacer(1, 14))

        # Before & After Retest Verification Summary (if available)
        if retest_results:
            elements.append(Paragraph("3. Twin Remediation & Retest Verification Results", h2_style))
            retest_data = [
                [
                    Paragraph("<b>CVE ID</b>", body_style),
                    Paragraph("<b>Pre-Fix Ver</b>", body_style),
                    Paragraph("<b>Post-Fix Ver</b>", body_style),
                    Paragraph("<b>Post-Fix Status</b>", body_style),
                    Paragraph("<b>Remaining Risk</b>", body_style),
                ]
            ]
            for r in retest_results:
                retest_data.append([
                    Paragraph(f"<b>{html.escape(r.finding.cve_id if hasattr(r, 'finding') else 'Target')}</b>", body_style),
                    Paragraph(html.escape(r.package_version_before), body_style),
                    Paragraph(html.escape(r.package_version_after), body_style),
                    Paragraph(f"<b><font color='#16a34a'>{html.escape(r.post_fix_status.upper())}</font></b>", body_style),
                    Paragraph(f"{r.remaining_risk_score}/100", body_style),
                ])
            retest_table = Table(retest_data, colWidths=[110, 100, 100, 100, 110])
            retest_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1e293b')),
                ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#cbd5e1')),
                ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
                ('PADDING', (0,0), (-1,-1), 4),
            ]))
            elements.append(retest_table)
            elements.append(Spacer(1, 14))

        # Assessment Limitations and Methodology
        elements.append(Paragraph("4. Assessment Methodology & Safe Twin Testing Disclaimer", h2_style))
        disclaimer = (
            "<b>Assessment Limitations:</b> All vulnerability reproduction and validation procedures were "
            "executed strictly against isolated Digital Twin replicas using certified, non-destructive test procedures. "
            "Production assets were never subjected to exploit payloads or service disruptions. "
            "Risk scores represent ML composite evaluation incorporating CVSS metrics, exploit maturity intelligence, "
            "asset criticality, and twin validation outcomes. Remediation verification requires both scanner clearance "
            "and successful validation retesting before production change approval."
        )
        elements.append(Paragraph(disclaimer, callout_style))

        doc.build(elements)
        pdf_bytes = buffer.getvalue()
        buffer.close()
        return pdf_bytes

report_generator = ReportGenerator()
