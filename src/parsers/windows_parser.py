"""
Windows Event Log Parser
Supports: Security, System, Application logs
"""

import re
import json
from datetime import datetime
from typing import Optional
from loguru import logger

from .base_parser import BaseParser, ParsedEvent


class WindowsEventParser(BaseParser):
    """Parser for Windows Event Logs"""
    
    def __init__(self):
        super().__init__(source_type="windows_event")
        
        # Critical Windows Event IDs
        self.critical_events = {
            # Authentication
            4625: ('Failed Logon', 'high'),
            4740: ('Account Lockout', 'high'),
            4728: ('User Added to Privileged Group', 'high'),
            4732: ('User Added to Security-Enabled Local Group', 'medium'),
            4756: ('User Added to Security-Enabled Universal Group', 'medium'),
            
            # Account Management
            4720: ('User Account Created', 'medium'),
            4722: ('User Account Enabled', 'medium'),
            4724: ('Password Reset Attempt', 'medium'),
            4738: ('User Account Changed', 'low'),
            
            # Privilege Escalation
            4672: ('Special Privileges Assigned', 'high'),
            4673: ('Sensitive Privilege Use', 'high'),
            
            # Process Creation
            4688: ('New Process Created', 'low'),
            
            # Service Events
            7045: ('Service Installed', 'medium'),
            7040: ('Service State Changed', 'low'),
            
            # Audit Policy
            4719: ('System Audit Policy Changed', 'high'),
            
            # Object Access
            4663: ('Object Access Attempt', 'low'),
            4656: ('Handle to Object Requested', 'low'),
            
            # System Events
            1102: ('Audit Log Cleared', 'critical'),
            1100: ('Event Logging Service Shutdown', 'critical'),
            
            # PowerShell
            4104: ('PowerShell Script Block', 'medium'),
            4103: ('PowerShell Module Logging', 'low'),
        }
        
        # Suspicious patterns
        self.suspicious_patterns = {
            'mimikatz': r'(?i)mimikatz|sekurlsa|lsadump|kerberos::',
            'psexec': r'(?i)psexec|paexec',
            'lateral_movement': r'(?i)\\\\[^\\]+\\(admin\$|c\$|ipc\$)',
            'powershell_encoded': r'(?i)-enc(oded)?\s+[A-Za-z0-9+/=]{50,}',
            'suspicious_process': r'(?i)wscript|cscript|regsvr32|rundll32|mshta|certutil',
            'credential_dump': r'(?i)ntds\.dit|sam\s+database|lsass\.exe.*dump',
        }
    
    def parse_line(self, line: str) -> Optional[ParsedEvent]:
        """Parse Windows Event log line"""
        
        # Try JSON format first (modern Windows Event Forwarding)
        if line.strip().startswith('{'):
            return self._parse_json_format(line)
        
        # Try XML format
        if '<Event' in line:
            return self._parse_xml_format(line)
        
        # Try text format
        return self._parse_text_format(line)
    
    def _parse_json_format(self, line: str) -> Optional[ParsedEvent]:
        """Parse JSON formatted Windows events"""
        try:
            data = json.loads(line)
            event = ParsedEvent(line, self.source_type)
            
            # Extract common fields
            event.event_id = str(data.get('EventID', data.get('event_id', '')))
            event.timestamp = self._parse_timestamp(data.get('TimeCreated', data.get('timestamp')))
            event.hostname = data.get('Computer', data.get('hostname'))
            event.username = self._extract_username(data)
            event.message = data.get('Message', data.get('message', ''))
            
            # Extract IPs if present
            if 'IpAddress' in data:
                event.source_ip = data['IpAddress']
            if 'SourceAddress' in data:
                event.source_ip = data['SourceAddress']
            
            # Set severity based on event ID
            event_id_int = int(event.event_id) if event.event_id.isdigit() else 0
            if event_id_int in self.critical_events:
                desc, severity = self.critical_events[event_id_int]
                event.event_type = desc
                event.severity = severity
            
            # Store additional data
            event.additional_fields = data
            
            # Check for suspicious patterns
            self._detect_suspicious_activity(event)
            
            return event
            
        except json.JSONDecodeError:
            return None
        except Exception as e:
            logger.debug(f"JSON parse error: {e}")
            return None
    
    def _parse_xml_format(self, line: str) -> Optional[ParsedEvent]:
        """Parse XML formatted Windows events"""
        # Simplified XML parsing - in production use xml.etree
        event = ParsedEvent(line, self.source_type)
        
        # Extract Event ID
        event_id_match = re.search(r'<EventID>(\d+)</EventID>', line)
        if event_id_match:
            event.event_id = event_id_match.group(1)
        
        # Extract Computer
        computer_match = re.search(r'<Computer>([^<]+)</Computer>', line)
        if computer_match:
            event.hostname = computer_match.group(1)
        
        # Extract TimeCreated
        time_match = re.search(r'SystemTime=["\']([^"\']+)["\']', line)
        if time_match:
            event.timestamp = self._parse_timestamp(time_match.group(1))
        
        # Extract Data fields
        data_matches = re.findall(r'<Data[^>]*>([^<]+)</Data>', line)
        if data_matches:
            event.additional_fields['data'] = data_matches
            
            # Try to find username and IP
            for data in data_matches:
                if '\\' in data and '@' not in data:
                    event.username = data
                elif re.match(r'\d+\.\d+\.\d+\.\d+', data):
                    event.source_ip = data
        
        event.message = line
        
        # Set event type and severity
        if event.event_id and event.event_id.isdigit():
            event_id_int = int(event.event_id)
            if event_id_int in self.critical_events:
                desc, severity = self.critical_events[event_id_int]
                event.event_type = desc
                event.severity = severity
        
        self._detect_suspicious_activity(event)
        
        return event
    
    def _parse_text_format(self, line: str) -> Optional[ParsedEvent]:
        """Parse text formatted Windows events"""
        event = ParsedEvent(line, self.source_type)
        event.message = line
        
        # Extract Event ID
        event_id_match = re.search(r'(?:Event\s*ID|EventID):\s*(\d+)', line, re.IGNORECASE)
        if event_id_match:
            event.event_id = event_id_match.group(1)
        
        # Extract timestamp
        timestamp_patterns = [
            r'(\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}:\d{2}\s*(?:AM|PM)?)',
            r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})',
        ]
        for pattern in timestamp_patterns:
            match = re.search(pattern, line)
            if match:
                event.timestamp = self._parse_timestamp(match.group(1))
                break
        
        # Extract computer name
        computer_match = re.search(r'(?:Computer|Source):\s*([^\s,]+)', line, re.IGNORECASE)
        if computer_match:
            event.hostname = computer_match.group(1)
        
        # Extract username
        user_patterns = [
            r'(?:User|Account\s*Name|Subject.*Account\s*Name):\s*([^\s,]+)',
            r'([A-Z]+\\[a-zA-Z0-9_.-]+)',
        ]
        for pattern in user_patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                event.username = match.group(1)
                break
        
        # Extract IP address
        ip_match = re.search(r'(?:IP|Address|Source):\s*(\d+\.\d+\.\d+\.\d+)', line, re.IGNORECASE)
        if ip_match:
            event.source_ip = ip_match.group(1)
        
        # Set event type and severity
        if event.event_id and event.event_id.isdigit():
            event_id_int = int(event.event_id)
            if event_id_int in self.critical_events:
                desc, severity = self.critical_events[event_id_int]
                event.event_type = desc
                event.severity = severity
        
        self._detect_suspicious_activity(event)
        
        return event if event.event_id else None
    
    def _extract_username(self, data: dict) -> Optional[str]:
        """Extract username from various fields"""
        username_fields = [
            'TargetUserName', 'SubjectUserName', 'UserName',
            'AccountName', 'User', 'user', 'username'
        ]
        
        for field in username_fields:
            if field in data and data[field]:
                return data[field]
        
        return None
    
    def _parse_timestamp(self, timestamp_str: str) -> datetime:
        """Parse various timestamp formats"""
        if not timestamp_str:
            return datetime.now()
        
        formats = [
            '%Y-%m-%dT%H:%M:%S.%fZ',
            '%Y-%m-%d %H:%M:%S',
            '%m/%d/%Y %I:%M:%S %p',
            '%m/%d/%Y %H:%M:%S',
        ]
        
        for fmt in formats:
            try:
                return datetime.strptime(timestamp_str, fmt)
            except ValueError:
                continue
        
        return datetime.now()
    
    def _detect_suspicious_activity(self, event: ParsedEvent) -> None:
        """Detect suspicious Windows activity"""
        
        # Check message for suspicious patterns
        for indicator, pattern in self.suspicious_patterns.items():
            if re.search(pattern, event.message, re.IGNORECASE):
                event.is_suspicious = True
                event.threat_indicators.append(indicator)
                if event.severity in ['low', 'info']:
                    event.severity = 'high'
        
        # Check for multiple failed logons (Event ID 4625)
        if event.event_id == '4625':
            event.is_suspicious = True
            event.threat_indicators.append('failed_logon')
        
        # Check for audit log cleared (Event ID 1102)
        if event.event_id == '1102':
            event.is_suspicious = True
            event.severity = 'critical'
            event.threat_indicators.append('audit_log_cleared')
        
        # Check for new service installation (Event ID 7045)
        if event.event_id == '7045':
            event.is_suspicious = True
            event.threat_indicators.append('service_installed')
        
        # Check for PowerShell execution with encoded commands
        if event.event_id in ['4104', '4103']:
            if re.search(r'-enc(oded)?', event.message, re.IGNORECASE):
                event.is_suspicious = True
                event.severity = 'high'
                event.threat_indicators.append('powershell_encoded_command')
