"""
Validation utilities for IP addresses, domains, hashes, etc.
"""

import re
import ipaddress
from typing import Optional, Union
from loguru import logger


def validate_ip(ip_string: str) -> tuple[bool, Optional[str]]:
    """
    Validate IP address (IPv4 or IPv6)
    
    Args:
        ip_string: IP address string
        
    Returns:
        Tuple of (is_valid, ip_version)
        ip_version is 'ipv4', 'ipv6', or None if invalid
    """
    try:
        ip_obj = ipaddress.ip_address(ip_string)
        if isinstance(ip_obj, ipaddress.IPv4Address):
            return True, 'ipv4'
        elif isinstance(ip_obj, ipaddress.IPv6Address):
            return True, 'ipv6'
    except ValueError:
        return False, None
    
    return False, None


def validate_domain(domain: str) -> bool:
    """
    Validate domain name format
    
    Args:
        domain: Domain name string
        
    Returns:
        True if valid, False otherwise
    """
    # Domain regex pattern
    domain_pattern = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    )
    
    if not domain or len(domain) > 253:
        return False
    
    return bool(domain_pattern.match(domain))


def validate_hash(hash_string: str, hash_type: Optional[str] = None) -> tuple[bool, Optional[str]]:
    """
    Validate hash value (MD5, SHA1, SHA256, SHA512)
    
    Args:
        hash_string: Hash string
        hash_type: Expected hash type (md5, sha1, sha256, sha512) or None for auto-detect
        
    Returns:
        Tuple of (is_valid, detected_hash_type)
    """
    hash_string = hash_string.lower().strip()
    
    hash_patterns = {
        'md5': (32, re.compile(r'^[a-f0-9]{32}$')),
        'sha1': (40, re.compile(r'^[a-f0-9]{40}$')),
        'sha256': (64, re.compile(r'^[a-f0-9]{64}$')),
        'sha512': (128, re.compile(r'^[a-f0-9]{128}$'))
    }
    
    # If hash_type specified, validate against that type only
    if hash_type:
        hash_type = hash_type.lower()
        if hash_type in hash_patterns:
            length, pattern = hash_patterns[hash_type]
            is_valid = len(hash_string) == length and bool(pattern.match(hash_string))
            return is_valid, hash_type if is_valid else None
        return False, None
    
    # Auto-detect hash type
    for htype, (length, pattern) in hash_patterns.items():
        if len(hash_string) == length and pattern.match(hash_string):
            return True, htype
    
    return False, None


def validate_email(email: str) -> bool:
    """
    Validate email address format
    
    Args:
        email: Email address string
        
    Returns:
        True if valid, False otherwise
    """
    email_pattern = re.compile(
        r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    )
    
    return bool(email_pattern.match(email))


def validate_url(url: str) -> bool:
    """
    Validate URL format
    
    Args:
        url: URL string
        
    Returns:
        True if valid, False otherwise
    """
    url_pattern = re.compile(
        r'^https?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain
        r'localhost|'  # localhost
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # or IP
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE
    )
    
    return bool(url_pattern.match(url))


def is_private_ip(ip_string: str) -> bool:
    """
    Check if IP address is private/internal
    
    Args:
        ip_string: IP address string
        
    Returns:
        True if private, False if public or invalid
    """
    try:
        ip_obj = ipaddress.ip_address(ip_string)
        return ip_obj.is_private
    except ValueError:
        return False


def is_reserved_ip(ip_string: str) -> bool:
    """
    Check if IP address is reserved (loopback, multicast, etc.)
    
    Args:
        ip_string: IP address string
        
    Returns:
        True if reserved, False otherwise
    """
    try:
        ip_obj = ipaddress.ip_address(ip_string)
        return (ip_obj.is_loopback or 
                ip_obj.is_multicast or 
                ip_obj.is_reserved or
                ip_obj.is_link_local)
    except ValueError:
        return False


def sanitize_string(text: str, max_length: int = 1000) -> str:
    """
    Sanitize input string for safe processing
    
    Args:
        text: Input text
        max_length: Maximum allowed length
        
    Returns:
        Sanitized string
    """
    if not text:
        return ""
    
    # Truncate if too long
    text = text[:max_length]
    
    # Remove null bytes and control characters
    text = ''.join(char for char in text if ord(char) >= 32 or char in '\n\r\t')
    
    return text.strip()


def validate_severity(severity: str) -> bool:
    """
    Validate severity level
    
    Args:
        severity: Severity string
        
    Returns:
        True if valid, False otherwise
    """
    valid_severities = ['low', 'medium', 'high', 'critical', 'info']
    return severity.lower() in valid_severities


def validate_port(port: Union[int, str]) -> bool:
    """
    Validate TCP/UDP port number
    
    Args:
        port: Port number (int or string)
        
    Returns:
        True if valid, False otherwise
    """
    try:
        port_num = int(port)
        return 0 <= port_num <= 65535
    except (ValueError, TypeError):
        return False
