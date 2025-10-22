"""
IDS/IPS Parser
Supports: Snort, Suricata, Zeek/Bro
"""

import re
import json
from datetime import datetime
from typing import Optional
from loguru import logger

from .base_parser import BaseParser, ParsedEvent


class IDSParser(BaseParser):
    """Parser for IDS/IPS logs"""
    
    def __init__(self):
        super().__init__(source_type="ids_ips")
        
        self.priority_severity = {
            1: 'critical',
            2: 'high',
            3: 'medium',
            4: 'low'
        }
    
    def parse_line(self, line: str) -> Optional[ParsedEvent]:
        """Parse IDS/IPS log line"""
        
        # Snort/Suricata alert format
        if '[**]' in line:
            return self._parse_snort(line)
        
        # Zeek JSON format
        if line.strip().startswith('{'):
            return self._parse_zeek_json(line)
        
        return None
    
    def _parse_snort(self, line: str) -> Optional[ParsedEvent]:
        """Parse Snort/Suricata alert"""
        # [**] [1:12345:1] Attack Description [**] [Priority: 1] {TCP} 1.2.3.4:80 -> 5.6.7.8:443
        
        event = ParsedEvent(line, self.source_type)
        event.message = line
        event.is_suspicious = True  # IDS alerts are always suspicious
        
        # Extract alert description
        desc_match = re.search(r'\[\*\*\]\s+\[.*?\]\s+(.*?)\s+\[\*\*\]', line)
        if desc_match:
            event.event_type = desc_match.group(1)
        
        # Extract priority
        priority_match = re.search(r'Priority:\s+(\d+)', line)
        if priority_match:
            priority = int(priority_match.group(1))
            event.severity = self.priority_severity.get(priority, 'medium')
        
        # Extract IPs and ports
        ip_pattern = r'(\d+\.\d+\.\d+\.\d+):(\d+)\s+->\s+(\d+\.\d+\.\d+\.\d+):(\d+)'
        ip_match = re.search(ip_pattern, line)
        if ip_match:
            event.source_ip = ip_match.group(1)
            event.source_port = int(ip_match.group(2))
            event.destination_ip = ip_match.group(3)
            event.destination_port = int(ip_match.group(4))
        
        # Extract protocol
        proto_match = re.search(r'\{(TCP|UDP|ICMP)\}', line)
        if proto_match:
            event.protocol = proto_match.group(1).lower()
        
        event.timestamp = datetime.now()
        event.threat_indicators.append('ids_alert')
        
        return event
    
    def _parse_zeek_json(self, line: str) -> Optional[ParsedEvent]:
        """Parse Zeek JSON logs"""
        try:
            data = json.loads(line)
            event = ParsedEvent(line, self.source_type)
            
            event.timestamp = datetime.fromtimestamp(data.get('ts', datetime.now().timestamp()))
            event.source_ip = data.get('id.orig_h')
            event.destination_ip = data.get('id.resp_h')
            event.source_port = data.get('id.orig_p')
            event.destination_port = data.get('id.resp_p')
            event.protocol = data.get('proto', '').lower()
            
            # Zeek notice/alert
            if 'note' in data:
                event.is_suspicious = True
                event.event_type = data['note']
                event.severity = 'high'
                event.threat_indicators.append('zeek_notice')
            
            event.message = data.get('msg', str(data))
            event.additional_fields = data
            
            return event
            
        except json.JSONDecodeError:
            return None
