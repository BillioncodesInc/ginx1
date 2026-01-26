"""PhishCreator internal modules package.

This file allows IDEs (Pylance) and Python to resolve imports like
`phishcreator.modules.ai_phishlet_refiner`.
"""

from .constants import (
    USERNAME_PATTERNS,
    PASSWORD_PATTERNS,
    COOKIE_PRIORITY_PATTERNS,
    COOKIE_ATTRIBUTE_SCORES,
    OAUTH_PATTERNS,
    SAML_PATTERNS,
    API_INDICATORS,
    FORM_INDICATORS,
)
from .phishlet_parser import PhishletParser
from .har_comparator import HARComparator, ComparisonResult
from .phishlet_updater import PhishletUpdater, UpdateResult
from .live_traffic_analyzer import LiveTrafficAnalyzer, LiveAnalysisSession, LiveAnalysisResult, is_available as playwright_available

from .auth_flow_classifier import AuthFlowClassifier, AuthFlowAnalysis, classify_auth_flow
from .intelligent_credential_extractor import IntelligentCredentialExtractor, CredentialPattern, extract_credentials
from .smart_cookie_analyzer import SmartCookieAnalyzer, CookieAnalysis, analyze_cookies
from .dynamic_phishlet_generator import DynamicPhishletGenerator, PhishletGenerationResult, generate_phishlet
from .self_improvement_engine import SelfImprovementEngine, PhishletTestResult, LearningPattern
from .ai_phishlet_refiner import AIPhishletRefiner, AIRefinementResult, refine_with_ai

__all__ = [
    # Constants
    'USERNAME_PATTERNS',
    'PASSWORD_PATTERNS',
    'COOKIE_PRIORITY_PATTERNS',
    'COOKIE_ATTRIBUTE_SCORES',
    'OAUTH_PATTERNS',
    'SAML_PATTERNS',
    'API_INDICATORS',
    'FORM_INDICATORS',
    # Core modules
    'PhishletParser',
    'HARComparator',
    'ComparisonResult',
    'PhishletUpdater',
    'UpdateResult',
    'LiveTrafficAnalyzer',
    'LiveAnalysisSession',
    'LiveAnalysisResult',
    'playwright_available',
    'AuthFlowClassifier',
    'AuthFlowAnalysis',
    'classify_auth_flow',
    'IntelligentCredentialExtractor',
    'CredentialPattern',
    'extract_credentials',
    'SmartCookieAnalyzer',
    'CookieAnalysis',
    'analyze_cookies',
    'DynamicPhishletGenerator',
    'PhishletGenerationResult',
    'generate_phishlet',
    'SelfImprovementEngine',
    'PhishletTestResult',
    'LearningPattern',
    'AIPhishletRefiner',
    'AIRefinementResult',
    'refine_with_ai',
]
