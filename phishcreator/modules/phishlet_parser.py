#!/usr/bin/env python3
"""
Phishlet Parser
Parses and validates Evilginx3 phishlet YAML files
"""

import yaml
import re
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field


@dataclass
class PhishletValidationResult:
    """Result of phishlet validation"""
    is_valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    info: Dict[str, Any] = field(default_factory=dict)


class PhishletParser:
    """
    Parses and validates Evilginx3 phishlet YAML files
    """
    
    # Required top-level keys
    REQUIRED_KEYS = ['proxy_hosts', 'sub_filters', 'auth_tokens', 'credentials', 'login']
    
    # Optional top-level keys
    OPTIONAL_KEYS = ['min_ver', 'auth_urls', 'js_inject', 'force_post', 'landing_path']
    
    def __init__(self):
        self.phishlet_data = None
        self.raw_yaml = None
    
    def parse(self, yaml_content: str) -> Dict:
        """
        Parse phishlet YAML content
        
        Args:
            yaml_content: YAML string content
        
        Returns:
            Parsed phishlet dictionary
        
        Raises:
            yaml.YAMLError: If YAML is invalid
        """
        self.raw_yaml = yaml_content
        self.phishlet_data = yaml.safe_load(yaml_content)
        return self.phishlet_data
    
    def parse_file(self, filepath: str) -> Dict:
        """
        Parse phishlet YAML file
        
        Args:
            filepath: Path to YAML file
        
        Returns:
            Parsed phishlet dictionary
        """
        with open(filepath, 'r', encoding='utf-8') as f:
            return self.parse(f.read())
    
    def validate(self, phishlet_data: Optional[Dict] = None) -> PhishletValidationResult:
        """
        Validate phishlet structure
        
        Args:
            phishlet_data: Optional phishlet data (uses last parsed if not provided)
        
        Returns:
            PhishletValidationResult
        """
        if phishlet_data is None:
            phishlet_data = self.phishlet_data
        
        if phishlet_data is None:
            return PhishletValidationResult(
                is_valid=False,
                errors=['No phishlet data to validate']
            )
        
        result = PhishletValidationResult(is_valid=True)
        
        # Check required keys
        for key in self.REQUIRED_KEYS:
            if key not in phishlet_data:
                result.errors.append(f"Missing required key: {key}")
                result.is_valid = False
        
        # Validate proxy_hosts
        if 'proxy_hosts' in phishlet_data:
            proxy_hosts_errors = self._validate_proxy_hosts(phishlet_data['proxy_hosts'])
            result.errors.extend(proxy_hosts_errors)
            if proxy_hosts_errors:
                result.is_valid = False
        
        # Validate sub_filters
        if 'sub_filters' in phishlet_data:
            sub_filters_errors = self._validate_sub_filters(phishlet_data['sub_filters'])
            result.errors.extend(sub_filters_errors)
            if sub_filters_errors:
                result.is_valid = False
        
        # Validate auth_tokens
        if 'auth_tokens' in phishlet_data:
            auth_tokens_errors = self._validate_auth_tokens(phishlet_data['auth_tokens'])
            result.errors.extend(auth_tokens_errors)
            if auth_tokens_errors:
                result.is_valid = False
        
        # Validate credentials
        if 'credentials' in phishlet_data:
            credentials_errors = self._validate_credentials(phishlet_data['credentials'])
            result.errors.extend(credentials_errors)
            if credentials_errors:
                result.is_valid = False
        
        # Validate login
        if 'login' in phishlet_data:
            login_errors = self._validate_login(phishlet_data['login'])
            result.errors.extend(login_errors)
            if login_errors:
                result.is_valid = False
        
        # Add info
        result.info = {
            'proxy_hosts_count': len(phishlet_data.get('proxy_hosts', [])),
            'sub_filters_count': len(phishlet_data.get('sub_filters', [])),
            'auth_tokens_count': len(phishlet_data.get('auth_tokens', [])),
            'has_js_inject': 'js_inject' in phishlet_data,
            'has_force_post': 'force_post' in phishlet_data,
            'min_ver': phishlet_data.get('min_ver', 'not specified')
        }
        
        return result
    
    def _validate_proxy_hosts(self, proxy_hosts: List[Dict]) -> List[str]:
        """Validate proxy_hosts section"""
        errors = []
        
        if not isinstance(proxy_hosts, list):
            errors.append("proxy_hosts must be a list")
            return errors
        
        if len(proxy_hosts) == 0:
            errors.append("proxy_hosts cannot be empty")
        
        for i, host in enumerate(proxy_hosts):
            if not isinstance(host, dict):
                errors.append(f"proxy_hosts[{i}] must be a dictionary")
                continue
            
            # Check required fields
            required_fields = ['phish_sub', 'orig_sub', 'domain', 'session', 'is_landing']
            for field in required_fields:
                if field not in host:
                    errors.append(f"proxy_hosts[{i}] missing required field: {field}")
        
        return errors
    
    def _validate_sub_filters(self, sub_filters: List[Dict]) -> List[str]:
        """Validate sub_filters section"""
        errors = []
        
        if not isinstance(sub_filters, list):
            errors.append("sub_filters must be a list")
            return errors
        
        for i, filter_item in enumerate(sub_filters):
            if not isinstance(filter_item, dict):
                errors.append(f"sub_filters[{i}] must be a dictionary")
                continue
            
            # Check required fields
            required_fields = ['triggers_on', 'search', 'replace']
            for field in required_fields:
                if field not in filter_item:
                    errors.append(f"sub_filters[{i}] missing required field: {field}")
        
        return errors
    
    def _validate_auth_tokens(self, auth_tokens: List[Dict]) -> List[str]:
        """Validate auth_tokens section"""
        errors = []
        
        if not isinstance(auth_tokens, list):
            errors.append("auth_tokens must be a list")
            return errors
        
        if len(auth_tokens) == 0:
            errors.append("auth_tokens cannot be empty")
        
        for i, token in enumerate(auth_tokens):
            if not isinstance(token, dict):
                errors.append(f"auth_tokens[{i}] must be a dictionary")
                continue
            
            # Check required fields
            if 'domain' not in token:
                errors.append(f"auth_tokens[{i}] missing required field: domain")
            if 'keys' not in token:
                errors.append(f"auth_tokens[{i}] missing required field: keys")
            elif not isinstance(token['keys'], list):
                errors.append(f"auth_tokens[{i}].keys must be a list")
        
        return errors
    
    def _validate_credentials(self, credentials: Dict) -> List[str]:
        """Validate credentials section"""
        errors = []
        
        if not isinstance(credentials, dict):
            errors.append("credentials must be a dictionary")
            return errors
        
        # Check for username and password
        if 'username' not in credentials:
            errors.append("credentials missing 'username' field")
        else:
            username_errors = self._validate_credential_field(credentials['username'], 'username')
            errors.extend(username_errors)
        
        if 'password' not in credentials:
            errors.append("credentials missing 'password' field")
        else:
            password_errors = self._validate_credential_field(credentials['password'], 'password')
            errors.extend(password_errors)
        
        return errors
    
    def _validate_credential_field(self, field: Dict, field_name: str) -> List[str]:
        """Validate individual credential field"""
        errors = []
        
        if not isinstance(field, dict):
            errors.append(f"credentials.{field_name} must be a dictionary")
            return errors
        
        required_fields = ['key', 'search', 'type']
        for req_field in required_fields:
            if req_field not in field:
                errors.append(f"credentials.{field_name} missing required field: {req_field}")
        
        # Validate type
        if 'type' in field and field['type'] not in ['post', 'json', 'get']:
            errors.append(f"credentials.{field_name}.type must be 'post', 'json', or 'get'")
        
        return errors
    
    def _validate_login(self, login: Dict) -> List[str]:
        """Validate login section"""
        errors = []
        
        if not isinstance(login, dict):
            errors.append("login must be a dictionary")
            return errors
        
        # Check required fields
        if 'domain' not in login:
            errors.append("login missing required field: domain")
        if 'path' not in login:
            errors.append("login missing required field: path")
        
        return errors
    
    def get_proxy_hosts(self) -> List[Dict]:
        """Get proxy_hosts from parsed phishlet"""
        if self.phishlet_data:
            return self.phishlet_data.get('proxy_hosts', [])
        return []
    
    def get_auth_tokens(self) -> List[Dict]:
        """Get auth_tokens from parsed phishlet"""
        if self.phishlet_data:
            return self.phishlet_data.get('auth_tokens', [])
        return []
    
    def get_credentials(self) -> Dict:
        """Get credentials from parsed phishlet"""
        if self.phishlet_data:
            return self.phishlet_data.get('credentials', {})
        return {}
    
    def to_yaml(self, phishlet_data: Optional[Dict] = None) -> str:
        """
        Convert phishlet data to YAML string
        
        Args:
            phishlet_data: Optional phishlet data (uses last parsed if not provided)
        
        Returns:
            YAML string
        """
        if phishlet_data is None:
            phishlet_data = self.phishlet_data
        
        if phishlet_data is None:
            raise ValueError("No phishlet data to convert")
        
        return yaml.dump(phishlet_data, default_flow_style=False, sort_keys=False, allow_unicode=True)
