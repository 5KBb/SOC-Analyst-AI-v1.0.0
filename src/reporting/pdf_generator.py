"""
PDF Report Generator for SOC Analysis
Creates professional security analysis reports
"""

from typing import List, Dict, Any, Optional
from datetime import datetime
from pathlib import Path
from loguru import logger

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.colors import HexColor, black, white
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, Image as RLImage
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY


class PDFReportGenerator:
    """Generates professional PDF security reports"""
    
    def __init__(self, output_path: str, title: str = "Security Analysis Report"):
        """
        Initialize PDF generator
        
        Args:
            output_path: Path where PDF will be saved
            title: Report title
        """
        self.output_path = output_path
        self.title = title
        self.doc = SimpleDocTemplate(
            output_path,
            pagesize=A4,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=36
        )
        self.story = []
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
        
        # Colors
        self.color_critical = HexColor('#dc3545')
        self.color_high = HexColor('#fd7e14')
        self.color_medium = HexColor('#ffc107')
        self.color_low = HexColor('#28a745')
        self.color_info = HexColor('#17a2b8')
        self.color_primary = HexColor('#0d6efd')
    
    def _setup_custom_styles(self) -> None:
        """Setup custom paragraph styles"""
        
        # Title style
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=HexColor('#2c3e50'),
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        ))
        
        # Heading 2
        self.styles.add(ParagraphStyle(
            name='Heading2Custom',
            parent=self.styles['Heading2'],
            fontSize=16,
            textColor=HexColor('#34495e'),
            spaceAfter=12,
            spaceBefore=12,
            fontName='Helvetica-Bold'
        ))
        
        # Severity badge style
        self.styles.add(ParagraphStyle(
            name='SeverityBadge',
            parent=self.styles['Normal'],
            fontSize=14,
            fontName='Helvetica-Bold',
            alignment=TA_CENTER
        ))
        
        # Executive summary
        self.styles.add(ParagraphStyle(
            name='Executive',
            parent=self.styles['Normal'],
            fontSize=11,
            textColor=HexColor('#2c3e50'),
            alignment=TA_JUSTIFY,
            spaceAfter=12
        ))
    
    def generate_report(
        self,
        analysis_data: Dict[str, Any],
        mitre_mappings: List[Dict[str, Any]],
        iocs: List[Dict[str, Any]],
        metadata: Optional[Dict[str, str]] = None
    ) -> bool:
        """
        Generate complete PDF report
        
        Args:
            analysis_data: Threat analysis results
            mitre_mappings: MITRE ATT&CK mappings
            iocs: Indicators of Compromise
            metadata: Additional metadata
            
        Returns:
            True if successful, False otherwise
        """
        try:
            logger.info(f"Generating PDF report: {self.output_path}")
            
            # Cover page
            self._add_cover_page(metadata)
            
            # Table of Contents (simplified)
            self._add_section_separator()
            
            # Executive Summary
            self._add_executive_summary(analysis_data)
            self._add_page_break()
            
            # Technical Analysis
            self._add_technical_analysis(analysis_data)
            self._add_page_break()
            
            # MITRE ATT&CK Mapping
            if mitre_mappings:
                self._add_mitre_section(mitre_mappings)
                self._add_page_break()
            
            # Indicators of Compromise
            if iocs:
                self._add_ioc_section(iocs)
                self._add_page_break()
            
            # Timeline
            if analysis_data.get('timeline'):
                self._add_timeline_section(analysis_data['timeline'])
                self._add_page_break()
            
            # Recommendations
            self._add_recommendations_section(analysis_data.get('recommendations', []))
            self._add_page_break()
            
            # Conclusion
            self._add_conclusion(analysis_data)
            
            # Build PDF
            self.doc.build(self.story)
            
            logger.info(f"PDF report generated successfully: {self.output_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error generating PDF report: {e}")
            return False
    
    def _add_cover_page(self, metadata: Optional[Dict[str, str]]) -> None:
        """Add cover page"""
        
        # Title
        self.story.append(Spacer(1, 2*inch))
        
        title = Paragraph(
            "🛡️ SOC ANALYST AI<br/>Security Analysis Report",
            self.styles['CustomTitle']
        )
        self.story.append(title)
        self.story.append(Spacer(1, 0.5*inch))
        
        # Date
        date_text = f"<b>Report Generated:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        self.story.append(Paragraph(date_text, self.styles['Normal']))
        self.story.append(Spacer(1, 0.3*inch))
        
        # Metadata if provided
        if metadata:
            for key, value in metadata.items():
                text = f"<b>{key}:</b> {value}"
                self.story.append(Paragraph(text, self.styles['Normal']))
                self.story.append(Spacer(1, 0.1*inch))
        
        self._add_page_break()
    
    def _add_executive_summary(self, analysis_data: Dict[str, Any]) -> None:
        """Add executive summary section"""
        
        self._add_section_title("📘 Executive Summary")
        
        # Severity badge
        severity = analysis_data.get('severity', 'low').upper()
        threat_score = analysis_data.get('threat_score', 0)
        
        severity_color = self._get_severity_color(severity.lower())
        
        severity_para = Paragraph(
            f'<para align="center" backColor="{severity_color}" textColor="white">'
            f'<b>SEVERITY: {severity} | Threat Score: {threat_score}/10</b></para>',
            self.styles['SeverityBadge']
        )
        self.story.append(severity_para)
        self.story.append(Spacer(1, 0.3*inch))
        
        # Summary text
        summary_text = self._generate_executive_summary_text(analysis_data)
        
        for para in summary_text:
            self.story.append(Paragraph(para, self.styles['Executive']))
            self.story.append(Spacer(1, 0.1*inch))
        
        # Key metrics table
        self._add_key_metrics_table(analysis_data)
    
    def _add_technical_analysis(self, analysis_data: Dict[str, Any]) -> None:
        """Add technical analysis section"""
        
        self._add_section_title("🔍 Technical Analysis")
        
        # Event statistics
        self.story.append(Paragraph("<b>Event Statistics:</b>", self.styles['Heading3']))
        
        stats_data = [
            ['Metric', 'Value'],
            ['Total Events Analyzed', str(analysis_data.get('total_events', 0))],
            ['Suspicious Events', str(analysis_data.get('suspicious_events', 0))],
            ['Unique Source IPs', str(len(analysis_data.get('source_ips', [])))],
            ['Affected Hosts', str(len(analysis_data.get('affected_hosts', [])))],
            ['Affected Users', str(len(analysis_data.get('affected_users', [])))]
        ]
        
        stats_table = Table(stats_data, colWidths=[3*inch, 2*inch])
        stats_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#34495e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), HexColor('#ecf0f1')),
            ('GRID', (0, 0), (-1, -1), 1, HexColor('#bdc3c7'))
        ]))
        
        self.story.append(stats_table)
        self.story.append(Spacer(1, 0.3*inch))
        
        # Attack patterns
        if analysis_data.get('attack_patterns'):
            self._add_attack_patterns(analysis_data['attack_patterns'])
    
    def _add_attack_patterns(self, patterns: List[Dict[str, Any]]) -> None:
        """Add attack patterns section"""
        
        self.story.append(Paragraph("<b>Detected Attack Patterns:</b>", self.styles['Heading3']))
        self.story.append(Spacer(1, 0.1*inch))
        
        for i, pattern in enumerate(patterns, 1):
            severity_color = self._get_severity_color(pattern.get('severity', 'medium'))
            
            pattern_text = f"""
            <para>
            <b>{i}. {pattern.get('type', 'Unknown').replace('_', ' ').title()}</b><br/>
            <font color="{severity_color}"><b>Severity: {pattern.get('severity', 'medium').upper()}</b></font><br/>
            {pattern.get('description', 'No description')}<br/>
            <i>MITRE Technique: {pattern.get('mitre_technique', 'N/A')}</i>
            </para>
            """
            
            self.story.append(Paragraph(pattern_text, self.styles['Normal']))
            self.story.append(Spacer(1, 0.15*inch))
    
    def _add_mitre_section(self, mitre_mappings: List[Dict[str, Any]]) -> None:
        """Add MITRE ATT&CK section"""
        
        self._add_section_title("🎯 MITRE ATT&CK Mapping")
        
        intro = """
        The following MITRE ATT&CK techniques were identified based on observed behaviors and patterns
        in the analyzed security events. This mapping helps understand the tactics and techniques
        potentially used by adversaries.
        """
        self.story.append(Paragraph(intro, self.styles['Normal']))
        self.story.append(Spacer(1, 0.2*inch))
        
        # MITRE table
        table_data = [['Technique ID', 'Name', 'Tactic', 'Occurrences']]
        
        for mapping in mitre_mappings[:15]:  # Top 15
            table_data.append([
                mapping['technique_id'],
                mapping['technique_name'],
                mapping['tactic'],
                str(mapping['occurrences'])
            ])
        
        mitre_table = Table(table_data, colWidths=[1.2*inch, 2*inch, 1.8*inch, 1*inch])
        mitre_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#e74c3c')),
            ('TEXTCOLOR', (0, 0), (-1, 0), white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), HexColor('#fadbd8')),
            ('GRID', (0, 0), (-1, -1), 1, HexColor('#c0392b'))
        ]))
        
        self.story.append(mitre_table)
    
    def _add_ioc_section(self, iocs: List[Dict[str, Any]]) -> None:
        """Add Indicators of Compromise section"""
        
        self._add_section_title("🚨 Indicators of Compromise (IoC)")
        
        intro = """
        The following Indicators of Compromise (IoCs) were extracted from the security events.
        These should be used for threat hunting and blocking at security controls.
        """
        self.story.append(Paragraph(intro, self.styles['Normal']))
        self.story.append(Spacer(1, 0.2*inch))
        
        # Group IOCs by type
        ioc_by_type = {}
        for ioc in iocs:
            ioc_type = ioc.get('type', 'unknown')
            if ioc_type not in ioc_by_type:
                ioc_by_type[ioc_type] = []
            ioc_by_type[ioc_type].append(ioc)
        
        # Display each type
        for ioc_type, ioc_list in ioc_by_type.items():
            self.story.append(Paragraph(
                f"<b>{ioc_type.upper()} Indicators:</b>",
                self.styles['Heading4']
            ))
            
            table_data = [['Value', 'Severity', 'Occurrences', 'First Seen']]
            
            for ioc in ioc_list[:20]:  # Limit to 20 per type
                table_data.append([
                    ioc.get('value', '')[:40],
                    ioc.get('severity', 'medium').upper(),
                    str(ioc.get('occurrences', 1)),
                    ioc.get('first_seen', 'N/A')[:19]
                ])
            
            ioc_table = Table(table_data, colWidths=[2.5*inch, 1*inch, 1*inch, 1.5*inch])
            ioc_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), HexColor('#34495e')),
                ('TEXTCOLOR', (0, 0), (-1, 0), white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('ALIGN', (1, 0), (1, -1), 'CENTER'),
                ('BACKGROUND', (0, 1), (-1, -1), HexColor('#ecf0f1')),
                ('GRID', (0, 0), (-1, -1), 1, HexColor('#bdc3c7'))
            ]))
            
            self.story.append(ioc_table)
            self.story.append(Spacer(1, 0.2*inch))
    
    def _add_timeline_section(self, timeline: List[Dict[str, Any]]) -> None:
        """Add event timeline section"""
        
        self._add_section_title("⏱️ Event Timeline")
        
        intro = "Chronological timeline of significant security events:"
        self.story.append(Paragraph(intro, self.styles['Normal']))
        self.story.append(Spacer(1, 0.2*inch))
        
        for event in timeline[:20]:  # Top 20 events
            timestamp = event.get('timestamp', 'N/A')[:19]
            event_type = event.get('event_type', 'unknown')
            severity = event.get('severity', 'info')
            description = event.get('description', '')
            
            severity_color = self._get_severity_color(severity)
            
            timeline_text = f"""
            <para>
            <b>{timestamp}</b> - <font color="{severity_color}">[{severity.upper()}]</font><br/>
            <b>Type:</b> {event_type}<br/>
            {description[:150]}
            </para>
            """
            
            self.story.append(Paragraph(timeline_text, self.styles['Normal']))
            self.story.append(Spacer(1, 0.1*inch))
    
    def _add_recommendations_section(self, recommendations: List[str]) -> None:
        """Add recommendations section"""
        
        self._add_section_title("✅ Recommended Actions")
        
        if not recommendations:
            self.story.append(Paragraph(
                "No specific recommendations at this time. Continue standard monitoring.",
                self.styles['Normal']
            ))
            return
        
        intro = """
        Based on the analysis, the following actions are recommended to mitigate identified threats
        and improve security posture:
        """
        self.story.append(Paragraph(intro, self.styles['Normal']))
        self.story.append(Spacer(1, 0.2*inch))
        
        for i, recommendation in enumerate(recommendations, 1):
            rec_text = f"{i}. {recommendation}"
            self.story.append(Paragraph(rec_text, self.styles['Normal']))
            self.story.append(Spacer(1, 0.1*inch))
    
    def _add_conclusion(self, analysis_data: Dict[str, Any]) -> None:
        """Add conclusion section"""
        
        self._add_section_title("📝 Conclusion")
        
        severity = analysis_data.get('severity', 'low')
        threat_score = analysis_data.get('threat_score', 0)
        
        if severity == 'critical':
            status = "🚨 <b>CRITICAL - Immediate Action Required</b>"
            conclusion = """
            Critical security threats have been identified that require immediate attention.
            Escalate to Tier 2 SOC team and initiate incident response procedures.
            """
        elif severity == 'high':
            status = "⚠️ <b>HIGH - Prompt Action Needed</b>"
            conclusion = """
            Significant security concerns identified. Address recommended actions within 24 hours
            and maintain heightened monitoring.
            """
        elif severity == 'medium':
            status = "⚡ <b>MEDIUM - Action Recommended</b>"
            conclusion = """
            Moderate security events detected. Review and address recommendations during
            normal business hours.
            """
        else:
            status = "✅ <b>LOW - Monitoring Status</b>"
            conclusion = """
            No significant threats detected. Continue standard security monitoring procedures.
            """
        
        self.story.append(Paragraph(status, self.styles['Heading3']))
        self.story.append(Spacer(1, 0.1*inch))
        self.story.append(Paragraph(conclusion, self.styles['Normal']))
        self.story.append(Spacer(1, 0.2*inch))
        
        footer_text = """
        <i>This report was generated automatically by SOC Analyst AI.
        For questions or additional analysis, contact the Security Operations Center.</i>
        """
        self.story.append(Paragraph(footer_text, self.styles['Normal']))
    
    def _generate_executive_summary_text(self, analysis_data: Dict[str, Any]) -> List[str]:
        """Generate executive summary paragraphs"""
        
        total_events = analysis_data.get('total_events', 0)
        suspicious_events = analysis_data.get('suspicious_events', 0)
        severity = analysis_data.get('severity', 'low')
        attack_patterns = analysis_data.get('attack_patterns', [])
        
        paragraphs = []
        
        # Opening paragraph
        paragraphs.append(
            f"This security analysis report covers {total_events} events analyzed by the "
            f"SOC AI system. Of these, {suspicious_events} events were flagged as suspicious "
            f"and warrant further investigation. The overall threat severity has been assessed "
            f"as <b>{severity.upper()}</b>."
        )
        
        # Attack patterns summary
        if attack_patterns:
            pattern_types = [p['type'].replace('_', ' ').title() for p in attack_patterns]
            paragraphs.append(
                f"The analysis identified {len(attack_patterns)} distinct attack pattern(s): "
                f"{', '.join(pattern_types)}. These patterns suggest potential malicious activity "
                f"targeting the infrastructure."
            )
        else:
            paragraphs.append(
                "No significant attack patterns were detected during this analysis period. "
                "The observed events appear to be within normal operational parameters."
            )
        
        # Impact statement
        affected_hosts = len(analysis_data.get('affected_hosts', []))
        affected_users = len(analysis_data.get('affected_users', []))
        
        if affected_hosts > 0 or affected_users > 0:
            paragraphs.append(
                f"The security events affected {affected_hosts} host(s) and {affected_users} "
                f"user account(s). Immediate review of these assets is recommended to ensure "
                f"no compromise has occurred."
            )
        
        return paragraphs
    
    def _add_key_metrics_table(self, analysis_data: Dict[str, Any]) -> None:
        """Add key metrics summary table"""
        
        self.story.append(Spacer(1, 0.2*inch))
        self.story.append(Paragraph("<b>Key Metrics:</b>", self.styles['Heading3']))
        
        metrics_data = [
            ['Metric', 'Count'],
            ['Total Events', str(analysis_data.get('total_events', 0))],
            ['Suspicious Events', str(analysis_data.get('suspicious_events', 0))],
            ['Attack Patterns', str(len(analysis_data.get('attack_patterns', [])))],
            ['Unique Threat Indicators', str(len(analysis_data.get('threat_indicators', [])))],
            ['Affected Systems', str(len(analysis_data.get('affected_hosts', [])))]
        ]
        
        metrics_table = Table(metrics_data, colWidths=[3*inch, 2*inch])
        metrics_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), self.color_primary),
            ('TEXTCOLOR', (0, 0), (-1, 0), white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BACKGROUND', (0, 1), (-1, -1), HexColor('#e8f4f8')),
            ('GRID', (0, 0), (-1, -1), 1, HexColor('#0d6efd'))
        ]))
        
        self.story.append(metrics_table)
    
    def _add_section_title(self, title: str) -> None:
        """Add section title"""
        self.story.append(Paragraph(title, self.styles['Heading2Custom']))
        self.story.append(Spacer(1, 0.2*inch))
    
    def _add_section_separator(self) -> None:
        """Add visual section separator"""
        self.story.append(Spacer(1, 0.3*inch))
    
    def _add_page_break(self) -> None:
        """Add page break"""
        self.story.append(PageBreak())
    
    def _get_severity_color(self, severity: str) -> str:
        """Get color for severity level"""
        colors = {
            'critical': '#dc3545',
            'high': '#fd7e14',
            'medium': '#ffc107',
            'low': '#28a745',
            'info': '#17a2b8'
        }
        return colors.get(severity.lower(), '#6c757d')
