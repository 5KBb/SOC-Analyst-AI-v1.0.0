"""
Threat Analyzer - Analyzes parsed events for security threats
"""

from typing import List, Dict, Any
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from loguru import logger

from ..parsers.base_parser import ParsedEvent


class ThreatAnalysis:
    """Results of threat analysis"""
    
    def __init__(self):
        self.total_events = 0
        self.suspicious_events = 0
        self.threat_score = 0.0  # 0-10 scale
        self.severity = "low"
        self.threat_indicators: List[str] = []
        self.affected_hosts: List[str] = []
        self.affected_users: List[str] = []
        self.source_ips: List[str] = []
        self.attack_patterns: List[Dict[str, Any]] = []
        self.recommendations: List[str] = []
        self.timeline: List[Dict[str, Any]] = []
        
    def to_dict(self) -> Dict[str, Any]:
        return {
            'total_events': self.total_events,
            'suspicious_events': self.suspicious_events,
            'threat_score': round(self.threat_score, 2),
            'severity': self.severity,
            'threat_indicators': self.threat_indicators,
            'affected_hosts': self.affected_hosts,
            'affected_users': self.affected_users,
            'source_ips': self.source_ips,
            'attack_patterns': self.attack_patterns,
            'recommendations': self.recommendations,
            'timeline': self.timeline
        }


class ThreatAnalyzer:
    """Analyzes events to detect threats and patterns"""
    
    def __init__(self):
        self.events: List[ParsedEvent] = []
        self.analysis = ThreatAnalysis()
    
    def analyze(self, events: List[ParsedEvent]) -> ThreatAnalysis:
        """
        Perform comprehensive threat analysis on events
        
        Args:
            events: List of parsed events
            
        Returns:
            ThreatAnalysis object
        """
        self.events = events
        self.analysis = ThreatAnalysis()
        
        if not events:
            logger.warning("No events to analyze")
            return self.analysis
        
        logger.info(f"Analyzing {len(events)} events...")
        
        # Basic statistics
        self.analysis.total_events = len(events)
        self.analysis.suspicious_events = sum(1 for e in events if e.is_suspicious)
        
        # Collect metadata
        self._collect_metadata()
        
        # Detect attack patterns
        self._detect_brute_force()
        self._detect_port_scanning()
        self._detect_lateral_movement()
        self._detect_data_exfiltration()
        self._detect_privilege_escalation()
        
        # Calculate threat score
        self._calculate_threat_score()
        
        # Generate recommendations
        self._generate_recommendations()
        
        # Build timeline
        self._build_timeline()
        
        logger.info(f"Analysis complete. Threat score: {self.analysis.threat_score}/10")
        
        return self.analysis
    
    def _collect_metadata(self) -> None:
        """Collect metadata from events"""
        
        # Collect unique values
        hosts = set()
        users = set()
        ips = set()
        indicators = []
        
        for event in self.events:
            if event.hostname:
                hosts.add(event.hostname)
            if event.username:
                users.add(event.username)
            if event.source_ip:
                ips.add(event.source_ip)
            if event.threat_indicators:
                indicators.extend(event.threat_indicators)
        
        self.analysis.affected_hosts = sorted(list(hosts))
        self.analysis.affected_users = sorted(list(users))
        self.analysis.source_ips = sorted(list(ips))
        
        # Count indicator frequency
        indicator_counts = Counter(indicators)
        self.analysis.threat_indicators = [
            f"{indicator} ({count}x)" 
            for indicator, count in indicator_counts.most_common(10)
        ]
    
    def _detect_brute_force(self) -> None:
        """Detect brute force attacks"""
        
        # Group failed auth attempts by source IP
        failed_auth = defaultdict(list)
        
        for event in self.events:
            if ('failed' in event.event_type.lower() or 
                'failed_authentication' in event.event_type or
                'failed_logon' in event.threat_indicators):
                
                if event.source_ip:
                    failed_auth[event.source_ip].append(event)
        
        # Threshold: 5+ failed attempts from same IP
        for ip, events in failed_auth.items():
            if len(events) >= 5:
                self.analysis.attack_patterns.append({
                    'type': 'brute_force_attack',
                    'severity': 'high',
                    'source_ip': ip,
                    'attempts': len(events),
                    'description': f'Detected {len(events)} failed authentication attempts from {ip}',
                    'mitre_technique': 'T1110 - Brute Force'
                })
    
    def _detect_port_scanning(self) -> None:
        """Detect port scanning activity"""
        
        # Group by source IP and destination ports
        port_scans = defaultdict(set)
        
        for event in self.events:
            if event.source_ip and event.destination_port:
                if 'deny' in event.event_type.lower() or 'drop' in event.event_type.lower():
                    port_scans[event.source_ip].add(event.destination_port)
        
        # Threshold: 10+ different ports from same IP
        for ip, ports in port_scans.items():
            if len(ports) >= 10:
                self.analysis.attack_patterns.append({
                    'type': 'port_scanning',
                    'severity': 'medium',
                    'source_ip': ip,
                    'ports_scanned': len(ports),
                    'description': f'Detected port scanning from {ip} targeting {len(ports)} ports',
                    'mitre_technique': 'T1046 - Network Service Scanning'
                })
    
    def _detect_lateral_movement(self) -> None:
        """Detect lateral movement attempts"""
        
        # Look for SMB, RDP, PSExec indicators
        lateral_indicators = []
        
        for event in self.events:
            indicators = event.threat_indicators
            
            if any(ind in ['lateral_movement', 'psexec', 'smb_access'] for ind in indicators):
                lateral_indicators.append(event)
            
            # Check destination ports
            if event.destination_port in [445, 3389, 5985, 5986]:  # SMB, RDP, WinRM
                if event.source_ip:
                    lateral_indicators.append(event)
        
        if len(lateral_indicators) >= 3:
            self.analysis.attack_patterns.append({
                'type': 'lateral_movement',
                'severity': 'critical',
                'events': len(lateral_indicators),
                'description': 'Detected potential lateral movement activity',
                'mitre_technique': 'T1021 - Remote Services'
            })
    
    def _detect_data_exfiltration(self) -> None:
        """Detect data exfiltration attempts"""
        
        exfil_events = []
        
        for event in self.events:
            if 'exfiltration' in event.threat_indicators:
                exfil_events.append(event)
            
            # Large file uploads
            if event.additional_fields.get('http_method') == 'POST':
                if event.additional_fields.get('bytes_sent', 0) > 10000000:  # 10MB
                    exfil_events.append(event)
        
        if exfil_events:
            self.analysis.attack_patterns.append({
                'type': 'data_exfiltration',
                'severity': 'critical',
                'events': len(exfil_events),
                'description': 'Detected potential data exfiltration activity',
                'mitre_technique': 'T1041 - Exfiltration Over C2 Channel'
            })
    
    def _detect_privilege_escalation(self) -> None:
        """Detect privilege escalation attempts"""
        
        priv_esc_events = []
        
        for event in self.events:
            # Windows privilege escalation
            if event.event_id in ['4672', '4673', '4728', '4732']:
                priv_esc_events.append(event)
            
            # Linux sudo usage
            if 'privilege_escalation' in event.event_type or 'sudo' in event.threat_indicators:
                priv_esc_events.append(event)
        
        if priv_esc_events:
            self.analysis.attack_patterns.append({
                'type': 'privilege_escalation',
                'severity': 'high',
                'events': len(priv_esc_events),
                'description': 'Detected privilege escalation attempts',
                'mitre_technique': 'T1068 - Exploitation for Privilege Escalation'
            })
    
    def _calculate_threat_score(self) -> None:
        """Calculate overall threat score (0-10)"""
        
        score = 0.0
        
        # Base score from suspicious events
        if self.analysis.total_events > 0:
            suspicious_ratio = self.analysis.suspicious_events / self.analysis.total_events
            score += suspicious_ratio * 3.0
        
        # Add score for each attack pattern
        severity_scores = {
            'critical': 3.0,
            'high': 2.0,
            'medium': 1.0,
            'low': 0.5
        }
        
        for pattern in self.analysis.attack_patterns:
            score += severity_scores.get(pattern['severity'], 0.5)
        
        # Cap at 10
        self.analysis.threat_score = min(score, 10.0)
        
        # Determine overall severity
        if self.analysis.threat_score >= 8:
            self.analysis.severity = "critical"
        elif self.analysis.threat_score >= 6:
            self.analysis.severity = "high"
        elif self.analysis.threat_score >= 3:
            self.analysis.severity = "medium"
        else:
            self.analysis.severity = "low"
    
    def _generate_recommendations(self) -> None:
        """Generate security recommendations"""
        
        recommendations = []
        
        # Based on attack patterns
        for pattern in self.analysis.attack_patterns:
            if pattern['type'] == 'brute_force_attack':
                recommendations.append(
                    f"🔒 Block IP {pattern.get('source_ip')} at firewall level"
                )
                recommendations.append(
                    "🔐 Implement account lockout policy after failed attempts"
                )
                recommendations.append(
                    "🛡️ Enable multi-factor authentication (MFA)"
                )
            
            elif pattern['type'] == 'port_scanning':
                recommendations.append(
                    f"🚫 Block scanning IP {pattern.get('source_ip')}"
                )
                recommendations.append(
                    "🔍 Review firewall rules and close unnecessary ports"
                )
            
            elif pattern['type'] == 'lateral_movement':
                recommendations.append(
                    "⚠️ CRITICAL: Isolate affected systems immediately"
                )
                recommendations.append(
                    "🔐 Force password reset for affected accounts"
                )
                recommendations.append(
                    "🔎 Conduct full forensic investigation"
                )
            
            elif pattern['type'] == 'data_exfiltration':
                recommendations.append(
                    "🚨 CRITICAL: Block outbound connections immediately"
                )
                recommendations.append(
                    "📊 Identify and secure exfiltrated data"
                )
                recommendations.append(
                    "🔒 Implement DLP (Data Loss Prevention) controls"
                )
            
            elif pattern['type'] == 'privilege_escalation':
                recommendations.append(
                    "👤 Audit and restrict administrative privileges"
                )
                recommendations.append(
                    "📝 Review and update access control policies"
                )
        
        # General recommendations
        if self.analysis.severity in ['high', 'critical']:
            recommendations.append(
                "📞 Escalate to Tier 2 SOC team immediately"
            )
            recommendations.append(
                "📋 Create incident response ticket"
            )
        
        recommendations.append(
            "📊 Continue monitoring for 24-48 hours"
        )
        
        self.analysis.recommendations = recommendations
    
    def _build_timeline(self) -> None:
        """Build event timeline"""
        
        # Sort events by timestamp
        sorted_events = sorted(
            [e for e in self.events if e.timestamp],
            key=lambda x: x.timestamp or datetime.min
        )
        
        # Take top 20 most significant events
        significant_events = [e for e in sorted_events if e.is_suspicious][:20]
        
        for event in significant_events:
            self.analysis.timeline.append({
                'timestamp': event.timestamp.isoformat() if event.timestamp else None,
                'event_type': event.event_type,
                'severity': event.severity,
                'source_ip': event.source_ip,
                'description': event.message[:100]
            })
