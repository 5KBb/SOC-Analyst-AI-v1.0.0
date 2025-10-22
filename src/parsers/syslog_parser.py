"""
Linux Syslog Parser
Supports: auth.log, syslog, messages, secure
"""

import re
from datetime import datetime
from typing import Optional
from loguru import logger

from .base_parser import BaseParser, ParsedEvent


class SyslogParser(BaseParser):
    """Parser for Linux syslog"""
    
    def __init__(self):
        super().__init__(source_type="syslog")
        
        self.suspicious_patterns = {
            'ssh_brute_force': r'(?i)failed password.*ssh',
            'sudo_privilege': r'(?i)sudo:.*command',
            'user_add': r'(?i)useradd|adduser',
            'auth_failure': r'(?i)authentication failure',
            'session_opened': r'(?i)session opened',
            'su_command': r'(?i)su:|su\[',
        }
    
    def parse_line(self, line: str) -> Optional[ParsedEvent]:
        """Parse syslog line"""
        event = ParsedEvent(line, self.source_type)
        
        # Standard syslog: Jan 15 10:30:15 hostname program[pid]: message
        pattern = r'^(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+([^:\[]+)(?:\[(\d+)\])?:\s+(.*)$'
        match = re.match(pattern, line)
        
        if match:
            timestamp_str, hostname, program, pid, message = match.groups()
            
            try:
                event.timestamp = datetime.strptime(f"{datetime.now().year} {timestamp_str}", '%Y %b %d %H:%M:%S')
            except:
                event.timestamp = datetime.now()
            
            event.hostname = hostname
            event.process_name = program
            event.message = message
            event.additional_fields = {'pid': pid} if pid else {}
            
            # Extract username if present
            user_match = re.search(r'user[=\s]+([a-zA-Z0-9_-]+)', message, re.IGNORECASE)
            if user_match:
                event.username = user_match.group(1)
            
            # Extract IP if present
            ip_match = re.search(r'from\s+(\d+\.\d+\.\d+\.\d+)', message)
            if ip_match:
                event.source_ip = ip_match.group(1)
            
            # Determine severity and detect suspicious activity
            self._analyze_message(event)
            
            return event
        
        return None
    
    def _analyze_message(self, event: ParsedEvent) -> None:
        """Analyze message for threats"""
        
        # Check suspicious patterns
        for indicator, pattern in self.suspicious_patterns.items():
            if re.search(pattern, event.message, re.IGNORECASE):
                event.threat_indicators.append(indicator)
        
        # Failed SSH attempts
        if 'failed password' in event.message.lower():
            event.is_suspicious = True
            event.severity = 'high'
            event.event_type = 'failed_authentication'
        
        # Successful authentication from unusual source
        elif 'accepted' in event.message.lower() and 'ssh' in event.message.lower():
            event.event_type = 'successful_authentication'
            event.severity = 'medium'
        
        # Sudo commands
        elif 'sudo' in event.message.lower() and 'command' in event.message.lower():
            event.event_type = 'privilege_escalation'
            event.severity = 'medium'
            event.is_suspicious = True
