"""
Firewall Log Parser
Supports: Cisco ASA, Palo Alto, Fortinet, pfSense, iptables
"""

import re
from datetime import datetime
from typing import Optional
from loguru import logger

from .base_parser import BaseParser, ParsedEvent


class FirewallParser(BaseParser):
    """Parser for firewall logs from various vendors"""
    
    def __init__(self):
        super().__init__(source_type="firewall")
        
        # Suspicious patterns
        self.suspicious_patterns = [
            (r'(?i)drop|deny|block|reject', 'traffic_blocked'),
            (r'(?i)scan|probe', 'port_scan'),
            (r'(?i)attack|intrusion|malicious', 'attack_detected'),
            (r'repeated.*(?:attempts|failures)', 'brute_force'),
            (r'(?i)exploit|vulnerability', 'exploitation_attempt')
        ]
        
        # Common ports that are often targeted
        self.high_risk_ports = {
            22: 'SSH', 23: 'Telnet', 3389: 'RDP',
            445: 'SMB', 139: 'NetBIOS', 1433: 'MSSQL',
            3306: 'MySQL', 5432: 'PostgreSQL', 21: 'FTP'
        }
    
    def parse_line(self, line: str) -> Optional[ParsedEvent]:
        """Parse a single firewall log line"""
        
        # Try different formats
        parsers = [
            self._parse_cisco_asa,
            self._parse_palo_alto,
            self._parse_fortinet,
            self._parse_iptables,
            self._parse_generic
        ]
        
        for parser in parsers:
            try:
                event = parser(line)
                if event:
                    self._detect_suspicious_patterns(event)
                    return event
            except Exception as e:
                logger.debug(f"Parser failed: {e}")
                continue
        
        return None
    
    def _parse_cisco_asa(self, line: str) -> Optional[ParsedEvent]:
        """Parse Cisco ASA format"""
        # Example: %ASA-4-106023: Deny tcp src outside:10.1.1.1/12345 dst inside:192.168.1.1/80
        
        pattern = r'%ASA-(\d)-(\d+):\s+(\w+)\s+(\w+)\s+src\s+\w+:(\d+\.\d+\.\d+\.\d+)/(\d+)\s+dst\s+\w+:(\d+\.\d+\.\d+\.\d+)/(\d+)'
        match = re.search(pattern, line)
        
        if match:
            event = ParsedEvent(line, self.source_type)
            event.severity = self._map_cisco_severity(match.group(1))
            event.event_id = match.group(2)
            event.event_type = match.group(3).lower()
            event.protocol = match.group(4).lower()
            event.source_ip = match.group(5)
            event.source_port = int(match.group(6))
            event.destination_ip = match.group(7)
            event.destination_port = int(match.group(8))
            event.message = line
            
            # Extract timestamp if present
            timestamp_match = re.search(r'(\w+\s+\d+\s+\d+:\d+:\d+)', line)
            if timestamp_match:
                try:
                    event.timestamp = datetime.strptime(
                        timestamp_match.group(1), 
                        '%b %d %H:%M:%S'
                    )
                except:
                    event.timestamp = datetime.now()
            
            return event
        
        return None
    
    def _parse_palo_alto(self, line: str) -> Optional[ParsedEvent]:
        """Parse Palo Alto Networks format (CSV-based)"""
        
        if 'TRAFFIC' in line or 'THREAT' in line:
            parts = line.split(',')
            
            if len(parts) > 20:
                event = ParsedEvent(line, self.source_type)
                
                try:
                    event.timestamp = datetime.now()  # Parse actual timestamp from log
                    event.source_ip = parts[7] if len(parts) > 7 else None
                    event.destination_ip = parts[8] if len(parts) > 8 else None
                    event.source_port = int(parts[9]) if len(parts) > 9 and parts[9].isdigit() else None
                    event.destination_port = int(parts[10]) if len(parts) > 10 and parts[10].isdigit() else None
                    event.protocol = parts[11] if len(parts) > 11 else None
                    event.event_type = parts[3] if len(parts) > 3 else 'traffic'
                    event.message = parts[-1] if parts else line
                    
                    return event
                except Exception as e:
                    logger.debug(f"Palo Alto parse error: {e}")
        
        return None
    
    def _parse_fortinet(self, line: str) -> Optional[ParsedEvent]:
        """Parse Fortinet FortiGate format"""
        # Example: date=2024-01-01 time=10:00:00 devname="FW01" action=deny srcip=10.1.1.1 dstip=192.168.1.1
        
        event = ParsedEvent(line, self.source_type)
        
        # Extract key-value pairs
        kv_pattern = r'(\w+)=(?:"([^"]+)"|(\S+))'
        matches = re.findall(kv_pattern, line)
        
        fields = {}
        for match in matches:
            key = match[0]
            value = match[1] if match[1] else match[2]
            fields[key] = value
        
        if fields:
            event.source_ip = fields.get('srcip')
            event.destination_ip = fields.get('dstip')
            event.source_port = int(fields.get('srcport', 0)) if fields.get('srcport', '0').isdigit() else None
            event.destination_port = int(fields.get('dstport', 0)) if fields.get('dstport', '0').isdigit() else None
            event.protocol = fields.get('proto')
            event.event_type = fields.get('action', 'unknown')
            event.hostname = fields.get('devname')
            event.message = fields.get('msg', line)
            event.additional_fields = fields
            
            # Parse timestamp
            if 'date' in fields and 'time' in fields:
                try:
                    timestamp_str = f"{fields['date']} {fields['time']}"
                    event.timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
                except:
                    event.timestamp = datetime.now()
            
            return event
        
        return None
    
    def _parse_iptables(self, line: str) -> Optional[ParsedEvent]:
        """Parse Linux iptables logs"""
        # Example: IN=eth0 OUT= SRC=10.1.1.1 DST=192.168.1.1 PROTO=TCP SPT=12345 DPT=80
        
        if 'SRC=' in line and 'DST=' in line:
            event = ParsedEvent(line, self.source_type)
            
            # Extract fields
            src_match = re.search(r'SRC=([\d.]+)', line)
            dst_match = re.search(r'DST=([\d.]+)', line)
            sport_match = re.search(r'SPT=(\d+)', line)
            dport_match = re.search(r'DPT=(\d+)', line)
            proto_match = re.search(r'PROTO=(\w+)', line)
            
            if src_match:
                event.source_ip = src_match.group(1)
            if dst_match:
                event.destination_ip = dst_match.group(1)
            if sport_match:
                event.source_port = int(sport_match.group(1))
            if dport_match:
                event.destination_port = int(dport_match.group(1))
            if proto_match:
                event.protocol = proto_match.group(1).lower()
            
            event.event_type = 'drop' if 'DROP' in line else 'accept'
            event.message = line
            
            # Timestamp
            timestamp_match = re.search(r'(\w+\s+\d+\s+\d+:\d+:\d+)', line)
            if timestamp_match:
                try:
                    event.timestamp = datetime.strptime(
                        timestamp_match.group(1),
                        '%b %d %H:%M:%S'
                    )
                except:
                    event.timestamp = datetime.now()
            
            return event
        
        return None
    
    def _parse_generic(self, line: str) -> Optional[ParsedEvent]:
        """Generic parser for common firewall log patterns"""
        
        event = ParsedEvent(line, self.source_type)
        event.message = line
        
        # Try to extract IPs
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips = re.findall(ip_pattern, line)
        
        if len(ips) >= 2:
            event.source_ip = ips[0]
            event.destination_ip = ips[1]
        elif len(ips) == 1:
            event.source_ip = ips[0]
        
        # Extract ports
        port_pattern = r':(\d{1,5})\b'
        ports = re.findall(port_pattern, line)
        if ports:
            event.source_port = int(ports[0]) if len(ports) > 0 else None
            event.destination_port = int(ports[1]) if len(ports) > 1 else None
        
        # Detect protocol
        if re.search(r'\bTCP\b', line, re.IGNORECASE):
            event.protocol = 'tcp'
        elif re.search(r'\bUDP\b', line, re.IGNORECASE):
            event.protocol = 'udp'
        elif re.search(r'\bICMP\b', line, re.IGNORECASE):
            event.protocol = 'icmp'
        
        # Event type
        if re.search(r'\b(deny|drop|block|reject)\b', line, re.IGNORECASE):
            event.event_type = 'deny'
        elif re.search(r'\b(allow|accept|permit)\b', line, re.IGNORECASE):
            event.event_type = 'allow'
        
        event.timestamp = datetime.now()
        
        return event if event.source_ip or event.destination_ip else None
    
    def _detect_suspicious_patterns(self, event: ParsedEvent) -> None:
        """Detect suspicious patterns in parsed event"""
        
        # Check message patterns
        for pattern, indicator in self.suspicious_patterns:
            if re.search(pattern, event.message, re.IGNORECASE):
                event.is_suspicious = True
                event.threat_indicators.append(indicator)
        
        # Check high-risk ports
        if event.destination_port in self.high_risk_ports:
            event.threat_indicators.append(f'high_risk_port_{self.high_risk_ports[event.destination_port]}')
            if event.event_type in ['deny', 'drop', 'block']:
                event.is_suspicious = True
        
        # Multiple connections to same destination (requires correlation)
        # This would be handled by correlation engine
        
        # Severity adjustment
        if event.is_suspicious and event.severity == 'info':
            event.severity = 'medium'
    
    def _map_cisco_severity(self, level: str) -> str:
        """Map Cisco severity levels to standard levels"""
        severity_map = {
            '0': 'critical',  # Emergency
            '1': 'critical',  # Alert
            '2': 'critical',  # Critical
            '3': 'high',      # Error
            '4': 'medium',    # Warning
            '5': 'low',       # Notification
            '6': 'info',      # Informational
            '7': 'info'       # Debug
        }
        return severity_map.get(level, 'info')
