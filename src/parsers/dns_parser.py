"""
DNS Log Parser
Supports: BIND, Windows DNS, Pi-hole
"""

import re
from datetime import datetime
from typing import Optional
from loguru import logger

from .base_parser import BaseParser, ParsedEvent


class DNSParser(BaseParser):
    """Parser for DNS query logs"""
    
    def __init__(self):
        super().__init__(source_type="dns")
        
        self.suspicious_tlds = ['.xyz', '.top', '.tk', '.ml', '.ga']
        
        self.dga_patterns = [
            r'[a-z]{20,}\.com',  # Long random strings
            r'[0-9]{5,}[a-z]{5,}',  # Numbers + letters
        ]
    
    def parse_line(self, line: str) -> Optional[ParsedEvent]:
        """Parse DNS log line"""
        
        event = ParsedEvent(line, self.source_type)
        event.message = line
        
        # Extract client IP
        ip_match = re.search(r'client\s+(\d+\.\d+\.\d+\.\d+)#', line)
        if ip_match:
            event.source_ip = ip_match.group(1)
        
        # Extract query domain
        query_match = re.search(r'query:\s+([^\s]+)\s+', line)
        if query_match:
            domain = query_match.group(1)
            event.additional_fields['queried_domain'] = domain
            event.message = f"DNS query for {domain}"
            
            # Check for threats
            self._detect_dns_threats(event, domain)
        
        event.timestamp = datetime.now()
        
        return event
    
    def _detect_dns_threats(self, event: ParsedEvent, domain: str) -> None:
        """Detect DNS-based threats"""
        
        domain_lower = domain.lower()
        
        # Check suspicious TLDs
        for tld in self.suspicious_tlds:
            if domain_lower.endswith(tld):
                event.is_suspicious = True
                event.threat_indicators.append('suspicious_tld')
                event.severity = 'medium'
        
        # Check DGA patterns
        for pattern in self.dga_patterns:
            if re.search(pattern, domain_lower):
                event.is_suspicious = True
                event.threat_indicators.append('possible_dga')
                event.severity = 'high'
        
        # Check for tunneling (very long domains)
        if len(domain) > 80:
            event.is_suspicious = True
            event.threat_indicators.append('possible_dns_tunneling')
            event.severity = 'high'
