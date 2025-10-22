"""
EDR (Endpoint Detection and Response) Parser
Supports: CrowdStrike, Carbon Black, SentinelOne, Microsoft Defender
"""

import re
import json
from datetime import datetime
from typing import Optional
from loguru import logger

from .base_parser import BaseParser, ParsedEvent


class EDRParser(BaseParser):
    """Parser for EDR logs"""
    
    def __init__(self):
        super().__init__(source_type="edr")
        
        self.threat_types = {
            'malware': 'critical',
            'ransomware': 'critical',
            'trojan': 'critical',
            'exploit': 'high',
            'suspicious_behavior': 'high',
            'pua': 'medium',  # Potentially Unwanted Application
            'adware': 'low'
        }
    
    def parse_line(self, line: str) -> Optional[ParsedEvent]:
        """Parse EDR log line"""
        
        # Try JSON format
        if line.strip().startswith('{'):
            return self._parse_json(line)
        
        return self._parse_text(line)
    
    def _parse_json(self, line: str) -> Optional[ParsedEvent]:
        """Parse JSON EDR logs"""
        try:
            data = json.loads(line)
            event = ParsedEvent(line, self.source_type)
            
            event.timestamp = datetime.now()
            event.hostname = data.get('hostname', data.get('computer_name'))
            event.process_name = data.get('process_name', data.get('file_path'))
            event.username = data.get('user', data.get('username'))
            
            # Threat detection
            threat_type = data.get('threat_type', '').lower()
            for threat, severity in self.threat_types.items():
                if threat in threat_type:
                    event.severity = severity
                    event.is_suspicious = True
                    event.event_type = threat_type
                    break
            
            event.message = data.get('description', data.get('message', ''))
            event.additional_fields = data
            
            # Extract file hash
            if 'hash' in data or 'sha256' in data or 'md5' in data:
                event.threat_indicators.append('malicious_hash_detected')
            
            return event
            
        except json.JSONDecodeError:
            return None
    
    def _parse_text(self, line: str) -> Optional[ParsedEvent]:
        """Parse text format EDR logs"""
        event = ParsedEvent(line, self.source_type)
        event.message = line
        
        # Detect threats in text
        for threat, severity in self.threat_types.items():
            if threat in line.lower():
                event.severity = severity
                event.is_suspicious = True
                event.event_type = threat
                event.threat_indicators.append(threat)
        
        # Extract hostname
        host_match = re.search(r'(?:host|computer)[:\s]+([^\s,]+)', line, re.IGNORECASE)
        if host_match:
            event.hostname = host_match.group(1)
        
        # Extract process
        proc_match = re.search(r'(?:process|file)[:\s]+([^\s,]+\.exe)', line, re.IGNORECASE)
        if proc_match:
            event.process_name = proc_match.group(1)
        
        event.timestamp = datetime.now()
        
        return event if event.is_suspicious else None
