"""
Configuration Loader for AI SOC Analyst
"""

import os
import yaml
from pathlib import Path
from typing import Dict, Any, Optional
from loguru import logger


class ConfigLoader:
    """Loads and manages application configuration"""
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize ConfigLoader
        
        Args:
            config_path: Path to config file. If None, uses default location
        """
        if config_path is None:
            # Default config path
            base_dir = Path(__file__).parent.parent.parent
            self.config_path = base_dir / "config" / "config.yaml"
        else:
            self.config_path = Path(config_path)
        
        self.config: Dict[str, Any] = {}
        self.load_config()
    
    def load_config(self) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        try:
            if not self.config_path.exists():
                logger.warning(f"Config file not found: {self.config_path}")
                return self._get_default_config()
            
            with open(self.config_path, 'r', encoding='utf-8') as f:
                self.config = yaml.safe_load(f)
            
            logger.info(f"Configuration loaded from {self.config_path}")
            return self.config
            
        except Exception as e:
            logger.error(f"Error loading config: {e}")
            return self._get_default_config()
    
    def get(self, key_path: str, default: Any = None) -> Any:
        """
        Get configuration value using dot notation
        
        Args:
            key_path: Configuration key path (e.g., 'mitre.enable')
            default: Default value if key not found
            
        Returns:
            Configuration value or default
        """
        keys = key_path.split('.')
        value = self.config
        
        try:
            for key in keys:
                value = value[key]
            return value
        except (KeyError, TypeError):
            return default
    
    def set(self, key_path: str, value: Any) -> None:
        """
        Set configuration value using dot notation
        
        Args:
            key_path: Configuration key path
            value: Value to set
        """
        keys = key_path.split('.')
        config = self.config
        
        for key in keys[:-1]:
            if key not in config:
                config[key] = {}
            config = config[key]
        
        config[keys[-1]] = value
    
    def save_config(self, path: Optional[str] = None) -> bool:
        """
        Save current configuration to file
        
        Args:
            path: Path to save config. If None, uses original path
            
        Returns:
            True if successful, False otherwise
        """
        try:
            save_path = Path(path) if path else self.config_path
            
            with open(save_path, 'w', encoding='utf-8') as f:
                yaml.dump(self.config, f, default_flow_style=False, sort_keys=False)
            
            logger.info(f"Configuration saved to {save_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error saving config: {e}")
            return False
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration if file not found"""
        return {
            'general': {
                'timezone': 'UTC',
                'log_level': 'INFO',
                'output_dir': 'reports'
            },
            'parsers': {
                'auto_detect': True,
                'encoding': 'utf-8'
            },
            'detection': {
                'enable_ml': True,
                'confidence_threshold': 0.7
            },
            'mitre': {
                'enable': True,
                'auto_map': True
            },
            'correlation': {
                'enable': True,
                'time_window_minutes': 60
            },
            'reporting': {
                'format': 'pdf',
                'language': 'en',
                'include_executive_summary': True
            }
        }
    
    def validate_config(self) -> tuple[bool, list[str]]:
        """
        Validate configuration structure and values
        
        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []
        
        # Check required sections
        required_sections = ['general', 'parsers', 'detection', 'reporting']
        for section in required_sections:
            if section not in self.config:
                errors.append(f"Missing required section: {section}")
        
        # Validate severity thresholds
        if 'severity' in self.config:
            severity = self.config['severity']
            # Additional validation logic here
        
        # Validate paths
        output_dir = self.get('general.output_dir')
        if output_dir and not Path(output_dir).exists():
            try:
                Path(output_dir).mkdir(parents=True, exist_ok=True)
            except Exception as e:
                errors.append(f"Cannot create output directory: {e}")
        
        is_valid = len(errors) == 0
        return is_valid, errors
    
    def get_all(self) -> Dict[str, Any]:
        """Get entire configuration dictionary"""
        return self.config.copy()
    
    def __repr__(self) -> str:
        return f"ConfigLoader(config_path='{self.config_path}')"
