"""
SOC Analyst AI - Command Line Interface
Main entry point for the application
"""

import sys
import click
from pathlib import Path
from datetime import datetime
from typing import Optional
from loguru import logger

from src.utils.config_loader import ConfigLoader
from src.utils.logger import setup_logger
from src.parsers import (
    FirewallParser, WindowsEventParser, SyslogParser,
    EDRParser, ProxyParser, DNSParser, IDSParser
)
from src.analyzers import ThreatAnalyzer, IOCDetector
from src.mitre import MitreMapper
from src.reporting import PDFReportGenerator


class SOCAnalystCLI:
    """Main SOC Analyst AI CLI application"""
    
    def __init__(self):
        self.config = ConfigLoader()
        self._setup_logging()
        self.parsers = {
            'firewall': FirewallParser(),
            'windows': WindowsEventParser(),
            'syslog': SyslogParser(),
            'edr': EDRParser(),
            'proxy': ProxyParser(),
            'dns': DNSParser(),
            'ids': IDSParser()
        }
    
    def _setup_logging(self):
        """Setup application logging"""
        log_level = self.config.get('general.log_level', 'INFO')
        log_file = self.config.get('logging.log_file', 'logs/soc_analyst.log')
        
        setup_logger(
            log_level=log_level,
            log_file=log_file,
            console_output=True
        )
    
    def auto_detect_parser(self, log_file: str):
        """Auto-detect log type and return appropriate parser"""
        
        logger.info(f"Auto-detecting log type for: {log_file}")
        
        # Read first few lines
        try:
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                sample = ''.join([f.readline() for _ in range(10)])
            
            # Detection logic
            if 'EventID' in sample or 'Event ID' in sample or '<Event' in sample:
                logger.info("Detected: Windows Event Log")
                return self.parsers['windows']
            
            elif any(x in sample for x in ['ASA-', 'TRAFFIC', 'THREAT', 'Fortinet']):
                logger.info("Detected: Firewall Log")
                return self.parsers['firewall']
            
            elif 'sshd' in sample or 'sudo' in sample or 'systemd' in sample:
                logger.info("Detected: Syslog")
                return self.parsers['syslog']
            
            elif any(x in sample.lower() for x in ['malware', 'threat', 'crowdstrike', 'carbon black']):
                logger.info("Detected: EDR Log")
                return self.parsers['edr']
            
            elif 'TCP_' in sample or 'CONNECT' in sample or 'squid' in sample.lower():
                logger.info("Detected: Proxy Log")
                return self.parsers['proxy']
            
            elif 'query:' in sample or 'DNS' in sample:
                logger.info("Detected: DNS Log")
                return self.parsers['dns']
            
            elif '[**]' in sample or 'Priority:' in sample:
                logger.info("Detected: IDS/IPS Log")
                return self.parsers['ids']
            
            else:
                logger.warning("Could not auto-detect log type, using firewall parser as default")
                return self.parsers['firewall']
                
        except Exception as e:
            logger.error(f"Error auto-detecting log type: {e}")
            return self.parsers['firewall']
    
    def analyze_file(
        self,
        file_path: str,
        output_pdf: Optional[str] = None,
        parser_type: str = 'auto'
    ) -> bool:
        """
        Analyze a log file and generate report
        
        Args:
            file_path: Path to log file
            output_pdf: Output PDF path (optional)
            parser_type: Parser type (auto, firewall, windows, etc.)
            
        Returns:
            True if successful
        """
        try:
            click.echo(f"\n🛡️  SOC Analyst AI - Log Analysis\n")
            click.echo(f"📁 Analyzing: {file_path}")
            
            # Select parser
            if parser_type == 'auto':
                parser = self.auto_detect_parser(file_path)
            else:
                parser = self.parsers.get(parser_type)
                if not parser:
                    logger.error(f"Unknown parser type: {parser_type}")
                    return False
            
            # Parse logs
            click.echo(f"\n🔍 Parsing logs...")
            events = parser.parse_file(file_path)
            
            if not events:
                click.echo("❌ No events parsed. Check log format.")
                return False
            
            stats = parser.get_stats()
            click.echo(f"✅ Parsed {stats['parsed_successfully']} events")
            click.echo(f"⚠️  Found {stats['suspicious_events']} suspicious events")
            
            # Threat Analysis
            click.echo(f"\n🔎 Performing threat analysis...")
            analyzer = ThreatAnalyzer()
            analysis = analyzer.analyze(events)
            
            click.echo(f"\n📊 Analysis Results:")
            click.echo(f"   Threat Score: {analysis.threat_score}/10")
            click.echo(f"   Severity: {analysis.severity.upper()}")
            click.echo(f"   Attack Patterns: {len(analysis.attack_patterns)}")
            
            # IOC Detection
            click.echo(f"\n🚨 Detecting Indicators of Compromise...")
            ioc_detector = IOCDetector()
            iocs = ioc_detector.detect(events)
            click.echo(f"   Found {len(iocs)} unique IOCs")
            
            # MITRE ATT&CK Mapping
            click.echo(f"\n🎯 Mapping to MITRE ATT&CK...")
            mitre_mapper = MitreMapper()
            mitre_mappings = mitre_mapper.map_events(events)
            click.echo(f"   Mapped to {len(mitre_mappings)} techniques")
            
            # Generate PDF Report
            if output_pdf is None:
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                output_pdf = f"reports/soc_report_{timestamp}.pdf"
            
            # Ensure reports directory exists
            Path(output_pdf).parent.mkdir(parents=True, exist_ok=True)
            
            click.echo(f"\n📄 Generating PDF report...")
            
            report_gen = PDFReportGenerator(
                output_path=output_pdf,
                title="Security Analysis Report"
            )
            
            metadata = {
                'Log Source': file_path,
                'Analysis Date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'Log Type': parser.source_type,
                'Analyst': 'SOC AI'
            }
            
            success = report_gen.generate_report(
                analysis_data=analysis.to_dict(),
                mitre_mappings=mitre_mappings,
                iocs=[ioc.to_dict() for ioc in iocs],
                metadata=metadata
            )
            
            if success:
                click.echo(f"✅ Report generated: {output_pdf}")
                click.echo(f"\n{'='*60}")
                click.echo(f"🎉 Analysis Complete!")
                click.echo(f"{'='*60}")
                
                # Summary
                self._print_summary(analysis, mitre_mappings, iocs)
                
                return True
            else:
                click.echo(f"❌ Failed to generate report")
                return False
                
        except Exception as e:
            logger.error(f"Error during analysis: {e}", exc_info=True)
            click.echo(f"❌ Error: {e}")
            return False
    
    def _print_summary(self, analysis, mitre_mappings, iocs):
        """Print analysis summary to console"""
        
        click.echo(f"\n📋 SUMMARY")
        click.echo(f"{'─'*60}")
        click.echo(f"Severity Level: {analysis.severity.upper()}")
        click.echo(f"Threat Score: {analysis.threat_score}/10")
        click.echo(f"Suspicious Events: {analysis.suspicious_events}/{analysis.total_events}")
        
        if analysis.attack_patterns:
            click.echo(f"\n⚠️  DETECTED ATTACK PATTERNS:")
            for pattern in analysis.attack_patterns[:5]:
                click.echo(f"   • {pattern['type'].replace('_', ' ').title()} [{pattern['severity'].upper()}]")
        
        if mitre_mappings:
            click.echo(f"\n🎯 TOP MITRE ATT&CK TECHNIQUES:")
            for mapping in mitre_mappings[:5]:
                click.echo(f"   • {mapping['technique_id']}: {mapping['technique_name']} ({mapping['occurrences']}x)")
        
        if iocs:
            high_severity_iocs = [ioc for ioc in iocs if ioc.severity in ['high', 'critical']]
            if high_severity_iocs:
                click.echo(f"\n🚨 HIGH-SEVERITY IOCs:")
                for ioc in high_severity_iocs[:5]:
                    click.echo(f"   • [{ioc.type.upper()}] {ioc.value}")
        
        if analysis.recommendations:
            click.echo(f"\n✅ TOP RECOMMENDATIONS:")
            for rec in analysis.recommendations[:3]:
                click.echo(f"   {rec}")
        
        click.echo(f"{'─'*60}\n")


@click.group()
@click.version_option(version="1.0.0")
def cli():
    """
    🛡️  SOC Analyst AI - Automated Security Analysis
    
    Analyze security logs, detect threats, and generate professional reports.
    """
    pass


@cli.command()
@click.option(
    '-f', '--file',
    type=click.Path(exists=True),
    required=True,
    help='Log file to analyze'
)
@click.option(
    '-o', '--output',
    type=str,
    help='Output PDF report path (default: auto-generated in reports/)'
)
@click.option(
    '-p', '--parser',
    type=click.Choice(['auto', 'firewall', 'windows', 'syslog', 'edr', 'proxy', 'dns', 'ids']),
    default='auto',
    help='Log parser type (default: auto-detect)'
)
def analyze(file, output, parser):
    """Analyze a log file and generate security report"""
    
    app = SOCAnalystCLI()
    success = app.analyze_file(file, output, parser)
    
    sys.exit(0 if success else 1)


@cli.command()
@click.option(
    '-d', '--directory',
    type=click.Path(exists=True),
    required=True,
    help='Directory containing log files'
)
@click.option(
    '-o', '--output',
    type=str,
    help='Output PDF report path'
)
def batch(directory, output):
    """Analyze multiple log files in a directory"""
    
    click.echo("🔄 Batch analysis mode")
    
    log_files = []
    for ext in ['*.log', '*.txt', '*.json', '*.csv']:
        log_files.extend(Path(directory).glob(ext))
    
    if not log_files:
        click.echo("❌ No log files found in directory")
        sys.exit(1)
    
    click.echo(f"📁 Found {len(log_files)} log file(s)")
    
    app = SOCAnalystCLI()
    
    # Analyze each file
    all_events = []
    for log_file in log_files:
        click.echo(f"\n📄 Processing: {log_file.name}")
        
        parser = app.auto_detect_parser(str(log_file))
        events = parser.parse_file(str(log_file))
        all_events.extend(events)
        
        click.echo(f"   ✅ Parsed {len(events)} events")
    
    click.echo(f"\n📊 Total events across all files: {len(all_events)}")
    
    # Combined analysis
    if output is None:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output = f"reports/batch_report_{timestamp}.pdf"
    
    # Continue with analysis...
    click.echo("\n🔎 Performing combined threat analysis...")
    
    analyzer = ThreatAnalyzer()
    analysis = analyzer.analyze(all_events)
    
    ioc_detector = IOCDetector()
    iocs = ioc_detector.detect(all_events)
    
    mitre_mapper = MitreMapper()
    mitre_mappings = mitre_mapper.map_events(all_events)
    
    # Generate report
    Path(output).parent.mkdir(parents=True, exist_ok=True)
    
    report_gen = PDFReportGenerator(output, "Batch Security Analysis Report")
    
    metadata = {
        'Analysis Type': 'Batch Analysis',
        'Files Analyzed': str(len(log_files)),
        'Analysis Date': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    
    success = report_gen.generate_report(
        analysis.to_dict(),
        mitre_mappings,
        [ioc.to_dict() for ioc in iocs],
        metadata
    )
    
    if success:
        click.echo(f"\n✅ Batch report generated: {output}")
        app._print_summary(analysis, mitre_mappings, iocs)
    else:
        click.echo("\n❌ Failed to generate batch report")
        sys.exit(1)


@cli.command()
def interactive():
    """Start interactive analysis mode"""
    
    click.echo("\n🛡️  SOC Analyst AI - Interactive Mode\n")
    click.echo("Type 'help' for available commands, 'quit' to exit.\n")
    
    app = SOCAnalystCLI()
    
    while True:
        try:
            user_input = click.prompt("SOC-AI", type=str)
            
            if user_input.lower() in ['quit', 'exit', 'q']:
                click.echo("👋 Goodbye!")
                break
            
            elif user_input.lower() == 'help':
                click.echo("""
Available commands:
  analyze <file>     - Analyze a log file
  status            - Show system status
  config            - Show configuration
  help              - Show this help
  quit              - Exit interactive mode
                """)
            
            elif user_input.lower() == 'status':
                click.echo("✅ SOC Analyst AI is running")
                click.echo(f"   Parsers loaded: {len(app.parsers)}")
                click.echo(f"   Config: {app.config.config_path}")
            
            elif user_input.lower() == 'config':
                click.echo(f"\nConfiguration: {app.config.config_path}")
                click.echo(f"Log Level: {app.config.get('general.log_level')}")
                click.echo(f"MITRE Enabled: {app.config.get('mitre.enable')}")
                click.echo(f"Correlation Enabled: {app.config.get('correlation.enable')}")
            
            elif user_input.lower().startswith('analyze '):
                file_path = user_input.split(' ', 1)[1]
                app.analyze_file(file_path)
            
            else:
                click.echo("❌ Unknown command. Type 'help' for available commands.")
                
        except KeyboardInterrupt:
            click.echo("\n👋 Goodbye!")
            break
        except Exception as e:
            click.echo(f"❌ Error: {e}")


@cli.command()
def version():
    """Show version information"""
    click.echo("""
🛡️  SOC Analyst AI
Version: 1.0.0
Python Security Analysis & Reporting System

Features:
  ✅ Multi-source log parsing
  ✅ Threat detection & analysis
  ✅ MITRE ATT&CK mapping
  ✅ IOC extraction
  ✅ Professional PDF reports
  ✅ SIEM & Threat Intel integration

Author: SOC Team
License: MIT
    """)


if __name__ == '__main__':
    cli()
