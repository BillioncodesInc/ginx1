#!/usr/bin/env python3
"""
HAR Comparator
Compares HAR (HTTP Archive) files with phishlet configurations
to identify missing hosts, cookies, and other discrepancies
"""

import json
from typing import Dict, List, Set, Optional
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qs


@dataclass
class ComparisonResult:
    """Result of HAR vs Phishlet comparison"""
    missing_hosts: List[str] = field(default_factory=list)
    missing_cookies: List[str] = field(default_factory=list)
    missing_credential_fields: List[str] = field(default_factory=list)
    extra_hosts: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    har_summary: Dict = field(default_factory=dict)
    phishlet_summary: Dict = field(default_factory=dict)


class HARComparator:
    """
    Compares HAR files with phishlet configurations
    Identifies discrepancies and suggests fixes
    """
    
    def __init__(self):
        self.har_data = None
        self.phishlet_data = None
    
    def load_har(self, har_content: str) -> Dict:
        """
        Load HAR file content
        
        Args:
            har_content: HAR JSON string
        
        Returns:
            Parsed HAR dictionary
        """
        self.har_data = json.loads(har_content)
        return self.har_data
    
    def load_har_file(self, filepath: str) -> Dict:
        """
        Load HAR file from path
        
        Args:
            filepath: Path to HAR file
        
        Returns:
            Parsed HAR dictionary
        """
        with open(filepath, 'r', encoding='utf-8') as f:
            return self.load_har(f.read())
    
    def set_phishlet(self, phishlet_data: Dict):
        """
        Set phishlet data for comparison
        
        Args:
            phishlet_data: Parsed phishlet dictionary
        """
        self.phishlet_data = phishlet_data
    
    def compare(self, har_data: Optional[Dict] = None, 
                phishlet_data: Optional[Dict] = None) -> ComparisonResult:
        """
        Compare HAR data with phishlet configuration
        
        Args:
            har_data: Optional HAR data (uses loaded if not provided)
            phishlet_data: Optional phishlet data (uses set if not provided)
        
        Returns:
            ComparisonResult with findings
        """
        if har_data is None:
            har_data = self.har_data
        if phishlet_data is None:
            phishlet_data = self.phishlet_data
        
        if har_data is None or phishlet_data is None:
            raise ValueError("Both HAR and phishlet data must be provided")
        
        result = ComparisonResult()
        
        # Extract data from HAR
        har_hosts = self._extract_hosts_from_har(har_data)
        har_cookies = self._extract_cookies_from_har(har_data)
        har_form_fields = self._extract_form_fields_from_har(har_data)
        
        # Extract data from phishlet
        phishlet_hosts = self._extract_hosts_from_phishlet(phishlet_data)
        phishlet_cookies = self._extract_cookies_from_phishlet(phishlet_data)
        phishlet_cred_fields = self._extract_credential_fields_from_phishlet(phishlet_data)
        
        # Compare hosts
        result.missing_hosts = list(har_hosts - phishlet_hosts)
        result.extra_hosts = list(phishlet_hosts - har_hosts)
        
        # Compare cookies
        result.missing_cookies = list(har_cookies - phishlet_cookies)
        
        # Compare credential fields
        result.missing_credential_fields = self._compare_credential_fields(
            har_form_fields, phishlet_cred_fields
        )
        
        # Generate recommendations
        result.recommendations = self._generate_recommendations(result)
        
        # Add summaries
        result.har_summary = {
            'total_requests': self._count_requests(har_data),
            'unique_hosts': len(har_hosts),
            'unique_cookies': len(har_cookies),
            'form_submissions': len(har_form_fields)
        }
        
        result.phishlet_summary = {
            'proxy_hosts': len(phishlet_data.get('proxy_hosts', [])),
            'auth_tokens': len(phishlet_data.get('auth_tokens', [])),
            'sub_filters': len(phishlet_data.get('sub_filters', []))
        }
        
        return result
    
    def _extract_hosts_from_har(self, har_data: Dict) -> Set[str]:
        """Extract unique hosts from HAR data"""
        hosts = set()
        
        entries = har_data.get('log', {}).get('entries', [])
        for entry in entries:
            request = entry.get('request', {})
            url = request.get('url', '')
            if url:
                parsed = urlparse(url)
                if parsed.netloc:
                    hosts.add(parsed.netloc)
        
        return hosts
    
    def _extract_cookies_from_har(self, har_data: Dict) -> Set[str]:
        """Extract unique cookie names from HAR data"""
        cookies = set()
        
        entries = har_data.get('log', {}).get('entries', [])
        for entry in entries:
            # From responses (Set-Cookie headers)
            response = entry.get('response', {})
            for cookie in response.get('cookies', []):
                cookie_name = cookie.get('name', '')
                if cookie_name:
                    cookies.add(cookie_name)
            
            # From requests (Cookie headers)
            request = entry.get('request', {})
            for cookie in request.get('cookies', []):
                cookie_name = cookie.get('name', '')
                if cookie_name:
                    cookies.add(cookie_name)
        
        return cookies
    
    def _extract_form_fields_from_har(self, har_data: Dict) -> List[Dict]:
        """Extract form field submissions from HAR data"""
        form_fields = []
        
        entries = har_data.get('log', {}).get('entries', [])
        for entry in entries:
            request = entry.get('request', {})
            method = str(request.get('method', '')).upper()
            
            if method == 'POST':
                post_data = request.get('postData', {}) or {}
                params = post_data.get('params', [])
                content_type = str(post_data.get('mimeType', '') or '').lower()
                fields = {}

                # 1) params (standard HAR form representation)
                if params:
                    for param in params:
                        name = param.get('name', '')
                        value = param.get('value', '')
                        if name:
                            fields[name] = value

                # 2) application/x-www-form-urlencoded from raw text
                if not fields and 'application/x-www-form-urlencoded' in content_type:
                    text = post_data.get('text') or ''
                    try:
                        parsed = parse_qs(text, keep_blank_values=True)
                        fields = {k: (v[0] if len(v) == 1 else v) for k, v in parsed.items()}
                    except Exception:
                        pass

                # 3) JSON bodies
                if not fields and 'application/json' in content_type:
                    text = post_data.get('text') or ''
                    try:
                        loaded = json.loads(text)
                        if isinstance(loaded, dict):
                            fields = loaded
                    except Exception:
                        pass

                if fields:
                    form_fields.append({
                        'url': request.get('url', ''),
                        'fields': fields
                    })
        
        return form_fields
    
    def _extract_hosts_from_phishlet(self, phishlet_data: Dict) -> Set[str]:
        """Extract hosts from phishlet proxy_hosts"""
        hosts = set()
        
        proxy_hosts = phishlet_data.get('proxy_hosts', [])
        for host in proxy_hosts:
            domain = host.get('domain', '')
            orig_sub = host.get('orig_sub', '')
            
            if domain:
                full_host = f"{orig_sub}.{domain}" if orig_sub else domain
                hosts.add(full_host)
        
        return hosts
    
    def _extract_cookies_from_phishlet(self, phishlet_data: Dict) -> Set[str]:
        """Extract cookie names from phishlet auth_tokens"""
        cookies = set()
        
        auth_tokens = phishlet_data.get('auth_tokens', [])
        for token in auth_tokens:
            keys = token.get('keys', [])
            for key in keys:
                # Remove regex markers
                clean_key = key.replace(',regexp', '')
                if clean_key and clean_key != '.*':
                    cookies.add(clean_key)
        
        return cookies
    
    def _extract_credential_fields_from_phishlet(self, phishlet_data: Dict) -> Dict:
        """Extract credential field names from phishlet"""
        credentials = phishlet_data.get('credentials', {})
        return {
            'username_key': credentials.get('username', {}).get('key', ''),
            'password_key': credentials.get('password', {}).get('key', '')
        }
    
    def _compare_credential_fields(self, har_form_fields: List[Dict], 
                                   phishlet_cred_fields: Dict) -> List[str]:
        """Compare credential fields between HAR and phishlet"""
        missing = []
        
        username_key = phishlet_cred_fields.get('username_key', '')
        password_key = phishlet_cred_fields.get('password_key', '')
        
        # Check if phishlet credential fields appear in HAR form submissions
        found_username = False
        found_password = False
        
        for form in har_form_fields:
            fields = form.get('fields', {})
            if username_key in fields:
                found_username = True
            if password_key in fields:
                found_password = True
        
        if username_key and not found_username:
            missing.append(f"Username field '{username_key}' not found in HAR form submissions")
        if password_key and not found_password:
            missing.append(f"Password field '{password_key}' not found in HAR form submissions")
        
        return missing
    
    def _count_requests(self, har_data: Dict) -> int:
        """Count total requests in HAR"""
        entries = har_data.get('log', {}).get('entries', [])
        return len(entries)
    
    def _generate_recommendations(self, result: ComparisonResult) -> List[str]:
        """Generate recommendations based on comparison results"""
        recommendations = []
        
        if result.missing_hosts:
            recommendations.append(
                f"Add {len(result.missing_hosts)} missing proxy hosts to phishlet: "
                f"{', '.join(result.missing_hosts[:3])}{'...' if len(result.missing_hosts) > 3 else ''}"
            )
        
        if result.missing_cookies:
            recommendations.append(
                f"Add {len(result.missing_cookies)} missing cookies to auth_tokens: "
                f"{', '.join(result.missing_cookies[:3])}{'...' if len(result.missing_cookies) > 3 else ''}"
            )
        
        if result.missing_credential_fields:
            recommendations.append(
                "Review credential field configuration - some fields may not match HAR data"
            )
        
        if result.extra_hosts:
            recommendations.append(
                f"Phishlet contains {len(result.extra_hosts)} hosts not seen in HAR - "
                "verify if they are still needed"
            )
        
        if not result.missing_hosts and not result.missing_cookies:
            recommendations.append(
                "✓ Phishlet appears to cover all hosts and cookies from HAR file"
            )
        
        return recommendations
