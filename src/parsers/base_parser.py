"""
Base Parser class for all log parsers
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from datetime import datetime
from pathlib import Path
import json
from loguru import logger


class ParsedEvent:
    """Represents a single parsed log event"""
    
    def __init__(self, raw_log: str, source_type: str):
        self.raw_log = raw_log
        self.source_type = source_type
        self.timestamp: Optional[datetime] = None
        self.severity: str = "info"
        self.event_type: str = "unknown"
        self.source_ip: Optional[str] = None
        self.destination_ip: Optional[str] = None
        self.source_port: Optional[int] = None
        self.destination_port: Optional[int] = None
        self.protocol: Optional[str] = None
        self.username: Optional[str] = None
        self.hostname: Optional[str] = None
        self.process_name: Optional[str] = None
        self.event_id: Optional[str] = None
        self.message: str = ""
        self.additional_fields: Dict[str, Any] = {}
        self.is_suspicious: bool = False
        self.threat_indicators: List[str] = []
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary"""
        return {
            'raw_log': self.raw_log,
            'source_type': self.source_type,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'severity': self.severity,
            'event_type': self.event_type,
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'source_port': self.source_port,
            'destination_port': self.destination_port,
            'protocol': self.protocol,
            'username': self.username,
            'hostname': self.hostname,
            'process_name': self.process_name,
            'event_id': self.event_id,
            'message': self.message,
            'additional_fields': self.additional_fields,
            'is_suspicious': self.is_suspicious,
            'threat_indicators': self.threat_indicators
        }
    
    def to_json(self) -> str:
        """Convert event to JSON string"""
        return json.dumps(self.to_dict(), indent=2, default=str)
    
    def __repr__(self) -> str:
        return f"ParsedEvent(source={self.source_type}, type={self.event_type}, severity={self.severity})"


class BaseParser(ABC):
    """Abstract base class for all log parsers"""
    
    def __init__(self, source_type: str):
        """
        Initialize parser
        
        Args:
            source_type: Type of log source (firewall, edr, etc.)
        """
        self.source_type = source_type
        self.parsed_events: List[ParsedEvent] = []
        self.parse_errors: List[Dict[str, Any]] = []
        self.stats = {
            'total_lines': 0,
            'parsed_successfully': 0,
            'parse_errors': 0,
            'suspicious_events': 0
        }
    
    @abstractmethod
    def parse_line(self, line: str) -> Optional[ParsedEvent]:
        """
        Parse a single log line
        
        Args:
            line: Raw log line
            
        Returns:
            ParsedEvent or None if parsing failed
        """
        pass
    
    def parse_file(self, file_path: str, encoding: str = 'utf-8') -> List[ParsedEvent]:
        """
        Parse entire log file
        
        Args:
            file_path: Path to log file
            encoding: File encoding
            
        Returns:
            List of ParsedEvent objects
        """
        logger.info(f"Parsing {self.source_type} log file: {file_path}")
        
        try:
            path = Path(file_path)
            if not path.exists():
                logger.error(f"File not found: {file_path}")
                return []
            
            with open(path, 'r', encoding=encoding, errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    self.stats['total_lines'] += 1
                    line = line.strip()
                    
                    if not line or line.startswith('#'):
                        continue
                    
                    try:
                        event = self.parse_line(line)
                        if event:
                            self.parsed_events.append(event)
                            self.stats['parsed_successfully'] += 1
                            
                            if event.is_suspicious:
                                self.stats['suspicious_events'] += 1
                        else:
                            self.stats['parse_errors'] += 1
                            
                    except Exception as e:
                        self.stats['parse_errors'] += 1
                        self.parse_errors.append({
                            'line_number': line_num,
                            'line': line[:200],
                            'error': str(e)
                        })
                        logger.debug(f"Parse error at line {line_num}: {e}")
            
            logger.info(f"Parsed {self.stats['parsed_successfully']} events from {self.stats['total_lines']} lines")
            logger.info(f"Found {self.stats['suspicious_events']} suspicious events")
            
            return self.parsed_events
            
        except Exception as e:
            logger.error(f"Error reading file {file_path}: {e}")
            return []
    
    def parse_text(self, log_text: str) -> List[ParsedEvent]:
        """
        Parse log text directly
        
        Args:
            log_text: Raw log text
            
        Returns:
            List of ParsedEvent objects
        """
        lines = log_text.split('\n')
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            try:
                event = self.parse_line(line)
                if event:
                    self.parsed_events.append(event)
                    self.stats['parsed_successfully'] += 1
                    
                    if event.is_suspicious:
                        self.stats['suspicious_events'] += 1
            except Exception as e:
                self.stats['parse_errors'] += 1
                logger.debug(f"Parse error: {e}")
        
        return self.parsed_events
    
    def get_stats(self) -> Dict[str, int]:
        """Get parsing statistics"""
        return self.stats.copy()
    
    def get_suspicious_events(self) -> List[ParsedEvent]:
        """Get only suspicious events"""
        return [e for e in self.parsed_events if e.is_suspicious]
    
    def reset(self) -> None:
        """Reset parser state"""
        self.parsed_events = []
        self.parse_errors = []
        self.stats = {
            'total_lines': 0,
            'parsed_successfully': 0,
            'parse_errors': 0,
            'suspicious_events': 0
        }
