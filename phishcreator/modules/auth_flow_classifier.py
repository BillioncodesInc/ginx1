#!/usr/bin/env python3
"""
Authentication Flow Classifier
Intelligently determines the type of authentication architecture
"""

import re
import json
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qs

# Import shared constants
try:
    from phishcreator.modules.constants import (
        OAUTH_PATTERNS, SAML_PATTERNS, API_INDICATORS, FORM_INDICATORS
    )
    CONSTANTS_AVAILABLE = True
except ImportError:
    try:
        from constants import (
            OAUTH_PATTERNS, SAML_PATTERNS, API_INDICATORS, FORM_INDICATORS
        )
        CONSTANTS_AVAILABLE = True
    except ImportError:
        CONSTANTS_AVAILABLE = False
        OAUTH_PATTERNS = None
        SAML_PATTERNS = None
        API_INDICATORS = None
        FORM_INDICATORS = None


@dataclass
class AuthFlowAnalysis:
    """Result of authentication flow classification"""
    primary_type: str
    confidence: float
    characteristics: List[str] = field(default_factory=list)
    multi_step: bool = False
    credential_submissions: int = 0
    api_endpoints: List[str] = field(default_factory=list)
    form_endpoints: List[str] = field(default_factory=list)
    oauth_indicators: List[str] = field(default_factory=list)
    saml_indicators: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


class AuthFlowClassifier:
    """
    Classifies authentication flows into categories:
    - simple_form: Traditional HTML form-based authentication
    - api_driven: JSON/REST API-based authentication
    - oauth: OAuth 2.0 / OpenID Connect
    - multi_step: Multi-page authentication flow
    - saml: SAML-based SSO
    - hybrid: Combination of multiple types
    """

    # Fallback patterns if constants module not available
    _DEFAULT_OAUTH_PATTERNS = [
        'oauth', 'authorize', 'openid', 'oidc', 'connect',
        'client_id', 'redirect_uri', 'response_type', 'scope'
    ]

    _DEFAULT_SAML_PATTERNS = [
        'saml', 'SAMLRequest', 'SAMLResponse', 'RelayState',
        'sso', 'idp', 'sp', 'assertion'
    ]

    _DEFAULT_API_INDICATORS = [
        'application/json', 'api/', '/v1/', '/v2/', '/v3/',
        'graphql', 'rest', 'batchexecute'
    ]

    _DEFAULT_FORM_INDICATORS = [
        'application/x-www-form-urlencoded', 'multipart/form-data',
        'username=', 'password=', 'email='
    ]

    def __init__(self):
        # Use shared constants or fallback to defaults
        self.oauth_patterns = OAUTH_PATTERNS if OAUTH_PATTERNS else self._DEFAULT_OAUTH_PATTERNS
        self.saml_patterns = SAML_PATTERNS if SAML_PATTERNS else self._DEFAULT_SAML_PATTERNS
        self.api_indicators = API_INDICATORS if API_INDICATORS else self._DEFAULT_API_INDICATORS
        self.form_indicators = FORM_INDICATORS if FORM_INDICATORS else self._DEFAULT_FORM_INDICATORS
        self.scores = {
            'simple_form': 0,
            'api_driven': 0,
            'oauth': 0,
            'multi_step': 0,
            'saml': 0
        }
        self.evidence = {
            'simple_form': [],
            'api_driven': [],
            'oauth': [],
            'multi_step': [],
            'saml': []
        }
    
    def classify(self, traffic_data: Dict) -> AuthFlowAnalysis:
        """
        Classify authentication flow based on captured traffic
        
        Args:
            traffic_data: Dictionary containing requests, responses, and form submissions
        
        Returns:
            AuthFlowAnalysis object with classification results
        """
        self._reset_scores()
        
        requests = traffic_data.get('all_requests', [])
        responses = traffic_data.get('all_responses', [])
        form_submissions = traffic_data.get('form_submissions', [])
        
        # Analyze requests
        for request in requests:
            self._analyze_request(request)
        
        # Analyze responses
        for response in responses:
            self._analyze_response(response)
        
        # Analyze form submissions
        credential_submissions = 0
        for form in form_submissions:
            if self._is_credential_submission(form):
                credential_submissions += 1
                self._analyze_form_submission(form)
        
        # Determine multi-step authentication
        if credential_submissions > 1:
            self.scores['multi_step'] += credential_submissions * 10
            self.evidence['multi_step'].append(f"Detected {credential_submissions} credential submissions")
        
        # Calculate final classification
        primary_type = max(self.scores, key=self.scores.get)
        max_score = self.scores[primary_type]
        total_score = sum(self.scores.values())
        confidence = max_score / total_score if total_score > 0 else 0
        
        # Build characteristics list
        characteristics = []
        for auth_type, score in self.scores.items():
            if score > 0:
                characteristics.append(f"{auth_type}: {score}")
        
        # Generate recommendations
        recommendations = self._generate_recommendations(primary_type, self.evidence)
        
        return AuthFlowAnalysis(
            primary_type=primary_type,
            confidence=confidence,
            characteristics=characteristics,
            multi_step=credential_submissions > 1,
            credential_submissions=credential_submissions,
            api_endpoints=self.evidence['api_driven'],
            form_endpoints=self.evidence['simple_form'],
            oauth_indicators=self.evidence['oauth'],
            saml_indicators=self.evidence['saml'],
            recommendations=recommendations
        )
    
    def _reset_scores(self):
        """Reset scores for new classification"""
        self.scores = {k: 0 for k in self.scores}
        self.evidence = {k: [] for k in self.evidence}
    
    def _analyze_request(self, request: Dict):
        """Analyze individual request"""
        url = request.get('url', '') or ''
        method = request.get('method', '')
        headers = request.get('headers') or {}
        post_data = str(request.get('post_data') or '')
        
        # Check content type
        content_type = str(headers.get('Content-Type', headers.get('content-type', '')) or '')
        
        # OAuth detection
        if any(pattern in url.lower() for pattern in self.oauth_patterns):
            self.scores['oauth'] += 5
            self.evidence['oauth'].append(url)

        # SAML detection
        if any(pattern in url.lower() or pattern in post_data for pattern in self.saml_patterns):
            self.scores['saml'] += 5
            self.evidence['saml'].append(url)

        # API detection
        if any(indicator in content_type or indicator in url for indicator in self.api_indicators):
            self.scores['api_driven'] += 3
            self.evidence['api_driven'].append(url)

        # Form detection
        if any(indicator in content_type for indicator in self.form_indicators):
            self.scores['simple_form'] += 3
            self.evidence['simple_form'].append(url)
        
        # JSON payload detection
        if 'application/json' in content_type:
            self.scores['api_driven'] += 2
            if url not in self.evidence['api_driven']:
                self.evidence['api_driven'].append(url)
    
    def _analyze_response(self, response: Dict):
        """Analyze individual response"""
        url = response.get('url', '')
        headers = response.get('headers', {})
        status = response.get('status', 0)
        
        # Check for OAuth redirects
        location = headers.get('Location', headers.get('location', ''))
        if location and any(pattern in location.lower() for pattern in self.oauth_patterns):
            self.scores['oauth'] += 3
    
    def _analyze_form_submission(self, form: Dict):
        """Analyze form submission"""
        url = form.get('url', '')
        fields = form.get('fields', {})
        content_type = form.get('content_type', '')
        
        # Check if it's JSON-based
        if 'application/json' in content_type:
            self.scores['api_driven'] += 5
        else:
            self.scores['simple_form'] += 5
    
    def _is_credential_submission(self, form: Dict) -> bool:
        """Check if form submission contains credentials"""
        fields = form.get('fields', {})
        detected_username = form.get('detected_username_field')
        detected_password = form.get('detected_password_field')
        
        return detected_username is not None or detected_password is not None
    
    def _generate_recommendations(self, primary_type: str, evidence: Dict) -> List[str]:
        """Generate recommendations based on classification"""
        recommendations = []
        
        if primary_type == 'simple_form':
            recommendations.append("Use simple form field extraction for credentials")
            recommendations.append("Focus on traditional cookie-based session management")
            recommendations.append("Sub-filters may be minimal")
        
        elif primary_type == 'api_driven':
            recommendations.append("Use regex-based extraction for JSON payloads")
            recommendations.append("Monitor API endpoints for credential submission")
            recommendations.append("May require JavaScript injection for API interception")
            recommendations.append("Sub-filters should target JSON responses")
        
        elif primary_type == 'oauth':
            recommendations.append("Capture OAuth tokens from authorization flow")
            recommendations.append("Monitor redirect_uri parameters")
            recommendations.append("May need to proxy OAuth provider domains")
            recommendations.append("Focus on access_token and refresh_token cookies")
        
        elif primary_type == 'multi_step':
            recommendations.append("Track credentials across multiple submissions")
            recommendations.append("May need JavaScript to control flow progression")
            recommendations.append("Monitor all steps in authentication sequence")
            recommendations.append("Ensure all intermediate pages are proxied")
        
        elif primary_type == 'saml':
            recommendations.append("Capture SAML assertions and responses")
            recommendations.append("Proxy both IdP and SP domains")
            recommendations.append("Monitor RelayState parameters")
            recommendations.append("Session cookies may be on multiple domains")
        
        return recommendations


def classify_auth_flow(traffic_data: Dict) -> AuthFlowAnalysis:
    """
    Convenience function to classify authentication flow
    
    Args:
        traffic_data: Traffic analysis data
    
    Returns:
        AuthFlowAnalysis object
    """
    classifier = AuthFlowClassifier()
    return classifier.classify(traffic_data)
