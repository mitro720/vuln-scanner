"""
Professional Report Generator
Generates PDF and HTML reports for scan results.
"""

import os
import json
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image
from reportlab.lib.units import inch

class ReportGenerator:
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = output_dir
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
    def generate_pdf(self, scan_data: dict, filename: str = None) -> str:
        """Generate Professional PDF Report"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"scan_report_{timestamp}.pdf"
            
        filepath = os.path.join(self.output_dir, filename)
        doc = SimpleDocTemplate(filepath, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []
        
        # Title Page
        title_style = ParagraphStyle(
            'Title',
            parent=styles['Heading1'],
            fontSize=24,
            alignment=1,
            spaceAfter=30
        )
        story.append(Spacer(1, 2*inch))
        story.append(Paragraph("Security Scan Report", title_style))
        story.append(Paragraph(f"Target: {scan_data.get('target_url')}", styles['Heading2']))
        story.append(Paragraph(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}", styles['Normal']))
        story.append(PageBreak())
        
        # Executive Summary
        story.append(Paragraph("Executive Summary", styles['Heading1']))
        summary_text = f"""
        This report contains the results of a security assessment performed on {scan_data.get('target_url')}.
        A total of {scan_data.get('findings_count', 0)} vulnerabilities were identified.
        """
        story.append(Paragraph(summary_text, styles['Normal']))
        story.append(Spacer(1, 0.2*inch))
        
        # Statistics Table
        findings = scan_data.get('findings', [])
        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
        
        for finding in findings:
            sev = finding.get('severity', 'Info').capitalize()
            if sev in severity_counts:
                severity_counts[sev] += 1
                
        data = [['Severity', 'Count']]
        for sev, count in severity_counts.items():
            data.append([sev, count])
            
        table = Table(data, colWidths=[4*inch, 2*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(table)
        story.append(PageBreak())
        
        # Detailed Findings
        story.append(Paragraph("Detailed Findings", styles['Heading1']))
        
        for i, finding in enumerate(findings, 1):
            # Finding Title
            story.append(Paragraph(f"{i}. {finding.get('name')}", styles['Heading2']))
            
            # Severity & URL
            meta_style = ParagraphStyle('Meta', parent=styles['Normal'], textColor=colors.gray)
            story.append(Paragraph(f"Severity: {finding.get('severity').upper()}", meta_style))
            story.append(Paragraph(f"URL: {finding.get('url')}", meta_style))
            story.append(Spacer(1, 0.1*inch))
            
            # Evidence
            story.append(Paragraph("Evidence:", styles['Heading3']))
            evidence = finding.get('evidence', {})
            if isinstance(evidence, dict):
                evidence_text = json.dumps(evidence, indent=2)
            else:
                evidence_text = str(evidence)
            
            # Simple code block style
            code_style = ParagraphStyle('Code', parent=styles['Code'], backColor=colors.lightgrey)
            story.append(Paragraph(evidence_text, code_style))
            story.append(Spacer(1, 0.2*inch))
            
            # Remediation
            story.append(Paragraph("Remediation:", styles['Heading3']))
            remedy = finding.get('remediation', 'No remediation provided.')
            if isinstance(remedy, list):
                for r in remedy:
                    story.append(Paragraph(f"• {r}", styles['Normal']))
            else:
                story.append(Paragraph(remedy, styles['Normal']))
                
            story.append(Spacer(1, 0.3*inch))
            
        doc.build(story)
        return filepath

    def generate_html(self, scan_data: dict, filename: str = None) -> str:
        """Generate HTML Report (Stub)"""
        # TODO: Implement HTML generation using Jinja2
        pass

if __name__ == "__main__":
    # Test
    sample_data = {
        "target_url": "http://example.com",
        "findings_count": 2,
        "findings": [
            {
                "name": "SQL Injection",
                "severity": "critical",
                "url": "http://example.com/id=1",
                "evidence": "Payload: ' OR 1=1",
                "remediation": "Use prepared statements"
            }
        ]
    }
    gen = ReportGenerator()
    print(f"Generated: {gen.generate_pdf(sample_data)}")
