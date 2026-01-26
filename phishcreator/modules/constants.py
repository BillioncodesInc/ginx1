#!/usr/bin/env python3
"""
Shared Constants for PhishCreator Modules
Centralized credential patterns and other shared constants
"""

from typing import List, Dict

# Common username field patterns - used across multiple modules
USERNAME_PATTERNS: List[str] = [
    'username', 'user', 'email', 'login', 'account', 'userid', 'user_id',
    'identifier', 'loginfmt', 'j_username', 'login_email', 'signin_email',
    'userPrincipalName', 'login_hint', 'emailAddress', 'userName', 'loginId',
    'userLogin', 'session[username_or_email]', 'identity', 'principal',
    'user_name', 'user-name', 'user.name', 'loginname', 'login_name'
]

# Common password field patterns - used across multiple modules
PASSWORD_PATTERNS: List[str] = [
    'password', 'passwd', 'pass', 'pwd', 'secret', 'credential',
    'j_password', 'session[password]', 'signin_password', 'login_password',
    'userPassword', 'secretKey', 'accessKey', 'pin', 'passcode',
    'pass_word', 'pass-word', 'pass.word', 'user_password'
]

# Cookie name patterns with priority levels for SmartCookieAnalyzer
COOKIE_PRIORITY_PATTERNS: Dict[str, List[str]] = {
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

# Authentication type indicators for AuthFlowClassifier
OAUTH_PATTERNS: List[str] = [
    'oauth', 'authorize', 'openid', 'oidc', 'connect',
    'client_id', 'redirect_uri', 'response_type', 'scope'
]

SAML_PATTERNS: List[str] = [
    'saml', 'SAMLRequest', 'SAMLResponse', 'RelayState',
    'sso', 'idp', 'sp', 'assertion'
]

API_INDICATORS: List[str] = [
    'application/json', 'api/', '/v1/', '/v2/', '/v3/',
    'graphql', 'rest', 'batchexecute'
]

FORM_INDICATORS: List[str] = [
    'application/x-www-form-urlencoded', 'multipart/form-data',
    'username=', 'password=', 'email='
]

# Cookie attribute scoring for SmartCookieAnalyzer
COOKIE_ATTRIBUTE_SCORES: Dict[str, int] = {
    'httpOnly': 5,      # HttpOnly cookies are often auth-related
    'secure': 3,        # Secure flag indicates sensitive data
    'sameSite_none': 2, # SameSite=None may indicate cross-domain auth
    'long_expiry': 4,   # Long expiry suggests session persistence
    'short_expiry': -2  # Very short expiry might be temporary
}

# File size limits
MAX_UPLOAD_SIZE_MB = 50
MAX_UPLOAD_SIZE_BYTES = MAX_UPLOAD_SIZE_MB * 1024 * 1024

# Allowed file extensions
ALLOWED_PHISHLET_EXTENSIONS = {'.yaml', '.yml'}
ALLOWED_HAR_EXTENSIONS = {'.har', '.json'}

# TTL values in seconds
RESULT_TTL_SECONDS = 3600      # Analysis results expire after 1 hour
LIVE_SESSION_TTL_SECONDS = 1800  # Live sessions expire after 30 minutes
