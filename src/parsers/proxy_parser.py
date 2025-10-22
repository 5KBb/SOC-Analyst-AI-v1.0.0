"""
Web Proxy Parser
Supports: Squid, BlueCoat, Zscaler, Forcepoint
"""

import re
from datetime import datetime
from typing import Optional
from loguru import logger

from .base_parser import BaseParser, ParsedEvent


class ProxyParser(BaseParser):
    """Parser for web proxy logs"""
    
    def __init__(self):
        super().__init__(source_type="proxy")
        
        self.suspicious_categories = [
            'malware', 'phishing', 'c2', 'command-and-control',
            'cryptomining', 'suspicious', 'newly-registered'
        ]
        
        self.suspicious_extensions = [
            '.exe', '.dll', '.scr', '.bat', '.ps1', '.vbs', '.js'
        ]
    
    def parse_line(self, line: str) -> Optional[ParsedEvent]:
        """Parse proxy log line"""
        
        # Squid format
        if '\t' in line or ' ' in line:
            return self._parse_squid(line)
        
        return None
    
    def _parse_squid(self, line: str) -> Optional[ParsedEvent]:
        """Parse Squid access log format"""
        # Format: timestamp elapsed client action/code size method URL user hierarchy/peer type
        
        parts = re.split(r'\s+', line.strip())
        
        if len(parts) < 7:
            return None
        
        event = ParsedEvent(line, self.source_type)
        
        try:
            # Timestamp
            event.timestamp = datetime.fromtimestamp(float(parts[0]))
            
            # Client IP
            event.source_ip = parts[2]
            
            # HTTP method and URL
            event.additional_fields['http_method'] = parts[5] if len(parts) > 5 else None
            url = parts[6] if len(parts) > 6 else ''
            event.message = f"{parts[5]} {url}" if len(parts) > 5 else url
            
            # Extract domain
            domain_match = re.search(r'https?://([^/]+)', url)
            if domain_match:
                event.additional_fields['domain'] = domain_match.group(1)
            
            # Check for suspicious content
            self._detect_threats(event, url)
            
            return event
            
        except Exception as e:
            logger.debug(f"Squid parse error: {e}")
            return None
    
    def _detect_threats(self, event: ParsedEvent, url: str) -> None:
        """Detect threats in proxy traffic"""
        
        url_lower = url.lower()
        
        # Check suspicious categories
        for category in self.suspicious_categories:
            if category in url_lower:
                event.is_suspicious = True
                event.severity = 'high'
                event.threat_indicators.append(f'suspicious_category_{category}')
        
        # Check suspicious file extensions
        for ext in self.suspicious_extensions:
            if url_lower.endswith(ext):
                event.is_suspicious = True
                event.severity = 'medium'
                event.threat_indicators.append(f'suspicious_download_{ext}')
        
        # Check for data exfiltration indicators
        if re.search(r'(upload|post).*\.(zip|rar|7z|tar|gz)', url_lower):
            event.is_suspicious = True
            event.threat_indicators.append('possible_data_exfiltration')
