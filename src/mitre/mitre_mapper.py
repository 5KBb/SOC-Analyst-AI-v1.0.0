"""
MITRE ATT&CK Technique Mapper
Maps security events to MITRE ATT&CK tactics and techniques
"""

from typing import List, Dict, Any
from collections import defaultdict
from loguru import logger

from ..parsers.base_parser import ParsedEvent


class MitreMapper:
    """Maps events to MITRE ATT&CK framework"""
    
    def __init__(self):
        self.mappings: List[Dict[str, Any]] = []
        self.techniques_db = self._load_techniques_database()
    
    def map_events(self, events: List[ParsedEvent]) -> List[Dict[str, Any]]:
        """
        Map events to MITRE ATT&CK techniques
        
        Args:
            events: List of parsed events
            
        Returns:
            List of technique mappings
        """
        logger.info(f"Mapping {len(events)} events to MITRE ATT&CK...")
        
        self.mappings = []
        technique_counter = defaultdict(int)
        
        for event in events:
            if not event.is_suspicious:
                continue
            
            # Map based on event characteristics
            techniques = self._identify_techniques(event)
            
            for technique in techniques:
                technique_counter[technique['id']] += 1
                
                if technique['id'] not in [m['technique_id'] for m in self.mappings]:
                    self.mappings.append({
                        'technique_id': technique['id'],
                        'technique_name': technique['name'],
                        'tactic': technique['tactic'],
                        'description': technique['description'],
                        'occurrences': 1,
                        'severity': event.severity,
                        'examples': [event.message[:100]]
                    })
                else:
                    # Update existing mapping
                    for mapping in self.mappings:
                        if mapping['technique_id'] == technique['id']:
                            mapping['occurrences'] += 1
                            if event.message[:100] not in mapping['examples']:
                                mapping['examples'].append(event.message[:100])
        
        # Update occurrences
        for mapping in self.mappings:
            mapping['occurrences'] = technique_counter[mapping['technique_id']]
        
        logger.info(f"Mapped to {len(self.mappings)} MITRE ATT&CK techniques")
        
        return self.mappings
    
    def _identify_techniques(self, event: ParsedEvent) -> List[Dict[str, str]]:
        """Identify MITRE techniques from event"""
        
        techniques = []
        
        # Brute Force
        if any(ind in ['failed_logon', 'failed_authentication', 'ssh_brute_force'] 
               for ind in event.threat_indicators):
            techniques.append(self.techniques_db['T1110'])
        
        # Network Service Scanning
        if 'port_scan' in event.threat_indicators:
            techniques.append(self.techniques_db['T1046'])
        
        # Lateral Movement
        if 'lateral_movement' in event.threat_indicators or event.destination_port in [445, 3389]:
            techniques.append(self.techniques_db['T1021'])
        
        # Data Exfiltration
        if 'exfiltration' in event.threat_indicators:
            techniques.append(self.techniques_db['T1041'])
        
        # Privilege Escalation
        if 'privilege_escalation' in event.event_type:
            techniques.append(self.techniques_db['T1068'])
        
        # PowerShell
        if 'powershell' in event.process_name.lower() if event.process_name else False:
            techniques.append(self.techniques_db['T1059.001'])
        
        # Credential Dumping
        if 'credential_dump' in event.threat_indicators:
            techniques.append(self.techniques_db['T1003'])
        
        # Malware Execution
        if event.source_type == 'edr' and event.is_suspicious:
            techniques.append(self.techniques_db['T1204'])
        
        # DNS Tunneling
        if 'dns_tunneling' in event.threat_indicators:
            techniques.append(self.techniques_db['T1071.004'])
        
        # Account Manipulation
        if event.event_id in ['4720', '4728', '4732']:  # Windows user/group changes
            techniques.append(self.techniques_db['T1098'])
        
        return techniques
    
    def _load_techniques_database(self) -> Dict[str, Dict[str, str]]:
        """Load MITRE ATT&CK techniques database"""
        
        # Simplified database - in production, load from official MITRE CTI
        return {
            'T1110': {
                'id': 'T1110',
                'name': 'Brute Force',
                'tactic': 'Credential Access',
                'description': 'Adversaries may use brute force techniques to gain access to accounts'
            },
            'T1046': {
                'id': 'T1046',
                'name': 'Network Service Scanning',
                'tactic': 'Discovery',
                'description': 'Adversaries may attempt to get a listing of services running on remote hosts'
            },
            'T1021': {
                'id': 'T1021',
                'name': 'Remote Services',
                'tactic': 'Lateral Movement',
                'description': 'Adversaries may use valid accounts to log into a service that accepts remote connections'
            },
            'T1041': {
                'id': 'T1041',
                'name': 'Exfiltration Over C2 Channel',
                'tactic': 'Exfiltration',
                'description': 'Adversaries may steal data by exfiltrating it over an existing command and control channel'
            },
            'T1068': {
                'id': 'T1068',
                'name': 'Exploitation for Privilege Escalation',
                'tactic': 'Privilege Escalation',
                'description': 'Adversaries may exploit software vulnerabilities to elevate privileges'
            },
            'T1059.001': {
                'id': 'T1059.001',
                'name': 'PowerShell',
                'tactic': 'Execution',
                'description': 'Adversaries may abuse PowerShell commands and scripts for execution'
            },
            'T1003': {
                'id': 'T1003',
                'name': 'OS Credential Dumping',
                'tactic': 'Credential Access',
                'description': 'Adversaries may attempt to dump credentials to obtain account login information'
            },
            'T1204': {
                'id': 'T1204',
                'name': 'User Execution',
                'tactic': 'Execution',
                'description': 'An adversary may rely upon specific actions by a user in order to gain execution'
            },
            'T1071.004': {
                'id': 'T1071.004',
                'name': 'DNS',
                'tactic': 'Command and Control',
                'description': 'Adversaries may communicate using the DNS protocol to avoid detection'
            },
            'T1098': {
                'id': 'T1098',
                'name': 'Account Manipulation',
                'tactic': 'Persistence',
                'description': 'Adversaries may manipulate accounts to maintain access to victim systems'
            },
            'T1078': {
                'id': 'T1078',
                'name': 'Valid Accounts',
                'tactic': 'Initial Access',
                'description': 'Adversaries may obtain and abuse credentials of existing accounts'
            },
            'T1190': {
                'id': 'T1190',
                'name': 'Exploit Public-Facing Application',
                'tactic': 'Initial Access',
                'description': 'Adversaries may attempt to exploit weaknesses in Internet-facing applications'
            }
        }
    
    def get_tactics_summary(self) -> Dict[str, int]:
        """Get summary of tactics observed"""
        
        tactics = defaultdict(int)
        
        for mapping in self.mappings:
            tactics[mapping['tactic']] += mapping['occurrences']
        
        return dict(tactics)
    
    def get_top_techniques(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get most frequently observed techniques"""
        
        sorted_mappings = sorted(
            self.mappings,
            key=lambda x: x['occurrences'],
            reverse=True
        )
        
        return sorted_mappings[:limit]
