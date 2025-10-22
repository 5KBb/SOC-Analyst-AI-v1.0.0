"""
IOC (Indicator of Compromise) Detector
"""

from typing import List, Dict, Any, Set
from loguru import logger

from ..parsers.base_parser import ParsedEvent
from ..utils.validators import validate_ip, validate_domain, validate_hash


class IOC:
    """Represents an Indicator of Compromise"""
    
    def __init__(self, ioc_type: str, value: str, severity: str = "medium"):
        self.type = ioc_type  # ip, domain, hash, url, email
        self.value = value
        self.severity = severity
        self.first_seen: str = ""
        self.last_seen: str = ""
        self.occurrences = 1
        self.related_events: List[str] = []
        self.threat_intel: Dict[str, Any] = {}
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'type': self.type,
            'value': self.value,
            'severity': self.severity,
            'first_seen': self.first_seen,
            'last_seen': self.last_seen,
            'occurrences': self.occurrences,
            'related_events': len(self.related_events),
            'threat_intel': self.threat_intel
        }


class IOCDetector:
    """Detects and extracts Indicators of Compromise from events"""
    
    def __init__(self):
        self.iocs: Dict[str, IOC] = {}
        self.known_malicious_ips: Set[str] = self._load_known_malicious_ips()
        self.known_malicious_domains: Set[str] = self._load_known_malicious_domains()
    
    def detect(self, events: List[ParsedEvent]) -> List[IOC]:
        """
        Detect IOCs from parsed events
        
        Args:
            events: List of parsed events
            
        Returns:
            List of IOC objects
        """
        logger.info(f"Detecting IOCs from {len(events)} events...")
        
        self.iocs = {}
        
        for event in events:
            if not event.is_suspicious:
                continue
            
            # Extract IPs
            if event.source_ip:
                self._add_ioc('ip', event.source_ip, event)
            
            # Extract domains
            if 'domain' in event.additional_fields:
                self._add_ioc('domain', event.additional_fields['domain'], event)
            
            # Extract hashes from additional fields
            for key in ['md5', 'sha1', 'sha256', 'hash']:
                if key in event.additional_fields:
                    hash_value = event.additional_fields[key]
                    is_valid, hash_type = validate_hash(hash_value)
                    if is_valid:
                        self._add_ioc('hash', hash_value, event)
            
            # Extract processes (suspicious executables)
            if event.process_name:
                if any(term in event.process_name.lower() for term in ['powershell', 'cmd.exe', 'wscript', 'cscript']):
                    self._add_ioc('process', event.process_name, event)
        
        logger.info(f"Detected {len(self.iocs)} unique IOCs")
        
        return list(self.iocs.values())
    
    def _add_ioc(self, ioc_type: str, value: str, event: ParsedEvent) -> None:
        """Add or update an IOC"""
        
        key = f"{ioc_type}:{value}"
        
        if key in self.iocs:
            # Update existing IOC
            ioc = self.iocs[key]
            ioc.occurrences += 1
            ioc.last_seen = event.timestamp.isoformat() if event.timestamp else ""
            if event.raw_log not in ioc.related_events:
                ioc.related_events.append(event.raw_log[:100])
        else:
            # Create new IOC
            severity = self._determine_severity(ioc_type, value)
            ioc = IOC(ioc_type, value, severity)
            ioc.first_seen = event.timestamp.isoformat() if event.timestamp else ""
            ioc.last_seen = event.timestamp.isoformat() if event.timestamp else ""
            ioc.related_events.append(event.raw_log[:100])
            
            self.iocs[key] = ioc
    
    def _determine_severity(self, ioc_type: str, value: str) -> str:
        """Determine IOC severity"""
        
        if ioc_type == 'ip':
            if value in self.known_malicious_ips:
                return 'critical'
            # Check if it's a public IP (simplified)
            if not value.startswith(('10.', '172.', '192.168.')):
                return 'high'
            return 'medium'
        
        elif ioc_type == 'domain':
            if value in self.known_malicious_domains:
                return 'critical'
            # Check suspicious TLDs
            if value.endswith(('.tk', '.ml', '.ga', '.xyz')):
                return 'high'
            return 'medium'
        
        elif ioc_type == 'hash':
            return 'high'
        
        elif ioc_type == 'process':
            return 'medium'
        
        return 'medium'
    
    def _load_known_malicious_ips(self) -> Set[str]:
        """Load known malicious IPs from database"""
        # In production, load from threat intelligence feeds
        return set()
    
    def _load_known_malicious_domains(self) -> Set[str]:
        """Load known malicious domains from database"""
        # In production, load from threat intelligence feeds
        return set()
    
    def get_iocs_by_type(self, ioc_type: str) -> List[IOC]:
        """Get all IOCs of a specific type"""
        return [ioc for ioc in self.iocs.values() if ioc.type == ioc_type]
    
    def get_high_severity_iocs(self) -> List[IOC]:
        """Get high and critical severity IOCs"""
        return [ioc for ioc in self.iocs.values() if ioc.severity in ['high', 'critical']]
