#!/usr/bin/env python3
"""
Phishlet Updater Web Application
Simple Flask web UI for analyzing and fixing phishlet YAML files
Enhanced with live traffic analysis using Playwright
"""

import os
import sys
import json
import tempfile
import uuid
import time
import threading
import asyncio
import logging
import yaml
from flask import Flask, render_template, request, jsonify, send_file
from flask_cors import CORS
from werkzeug.utils import secure_filename

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Prefer package imports (better for IDEs/Pylance). Fall back to legacy sys.path
# behavior for users running this file directly without installing as a package.
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

MODULES_AVAILABLE = False
LIVE_ANALYZER_AVAILABLE = False
INTELLIGENT_MODULES_AVAILABLE = False
PLAYWRIGHT_STATUS = {'available': False, 'message': 'Live analyzer not loaded'}

try:
    # Try package imports first, fall back to direct imports
    try:
        from phishcreator.modules.phishlet_parser import PhishletParser
        from phishcreator.modules.har_comparator import HARComparator
        from phishcreator.modules.phishlet_updater import PhishletUpdater
    except ImportError:
        from modules.phishlet_parser import PhishletParser
        from modules.har_comparator import HARComparator
        from modules.phishlet_updater import PhishletUpdater
    MODULES_AVAILABLE = True
    logger.info("Core modules loaded successfully")
except ImportError as e:
    logger.warning(f"Core modules not available: {e}")

try:
    try:
        from phishcreator.modules.live_traffic_analyzer import (
            LiveAnalysisSession,
            LiveTrafficAnalyzer,
            is_available as playwright_available,
            playwright_status,
        )
    except ImportError:
        from modules.live_traffic_analyzer import (
            LiveAnalysisSession,
            LiveTrafficAnalyzer,
            is_available as playwright_available,
            playwright_status,
        )
    PLAYWRIGHT_STATUS = playwright_status()
    LIVE_ANALYZER_AVAILABLE = PLAYWRIGHT_STATUS.get('available', False) if isinstance(PLAYWRIGHT_STATUS, dict) else playwright_available()
    logger.info(f"Live analyzer module loaded (available: {LIVE_ANALYZER_AVAILABLE})")
except ImportError as e:
    PLAYWRIGHT_STATUS = {'available': False, 'message': f"Live analyzer module not available: {e}"}
    logger.warning(f"Live analyzer module not available: {e}")

try:
    try:
        from phishcreator.modules.ai_phishlet_refiner import refine_with_ai, AIPhishletRefiner
        from phishcreator.modules.self_improvement_engine import SelfImprovementEngine, PhishletTestResult
        from phishcreator.modules.auth_flow_classifier import classify_auth_flow
        from phishcreator.modules.intelligent_credential_extractor import extract_credentials
        from phishcreator.modules.smart_cookie_analyzer import analyze_cookies
        from phishcreator.modules.har_traffic_extractor import traffic_data_from_har
    except ImportError:
        from modules.ai_phishlet_refiner import refine_with_ai, AIPhishletRefiner
        from modules.self_improvement_engine import SelfImprovementEngine, PhishletTestResult
        from modules.auth_flow_classifier import classify_auth_flow
        from modules.intelligent_credential_extractor import extract_credentials
        from modules.smart_cookie_analyzer import analyze_cookies
        from modules.har_traffic_extractor import traffic_data_from_har
    INTELLIGENT_MODULES_AVAILABLE = True
    logger.info("Intelligent analysis modules loaded successfully")
except ImportError as e:
    logger.warning(f"Intelligent modules not available: {e}")

app = Flask(__name__)
CORS(app)

# Import shared constants if available
try:
    try:
        from phishcreator.modules.constants import (
            MAX_UPLOAD_SIZE_BYTES,
            RESULT_TTL_SECONDS as CONST_RESULT_TTL,
            LIVE_SESSION_TTL_SECONDS as CONST_LIVE_TTL,
            ALLOWED_PHISHLET_EXTENSIONS,
            ALLOWED_HAR_EXTENSIONS,
        )
    except ImportError:
        from modules.constants import (
            MAX_UPLOAD_SIZE_BYTES,
            RESULT_TTL_SECONDS as CONST_RESULT_TTL,
            LIVE_SESSION_TTL_SECONDS as CONST_LIVE_TTL,
            ALLOWED_PHISHLET_EXTENSIONS,
            ALLOWED_HAR_EXTENSIONS,
        )
    CONSTANTS_AVAILABLE = True
except ImportError:
    CONSTANTS_AVAILABLE = False
    MAX_UPLOAD_SIZE_BYTES = 50 * 1024 * 1024  # 50MB
    CONST_RESULT_TTL = 3600
    CONST_LIVE_TTL = 1800
    ALLOWED_PHISHLET_EXTENSIONS = {'.yaml', '.yml'}
    ALLOWED_HAR_EXTENSIONS = {'.har', '.json'}

# Configuration
app.config['MAX_CONTENT_LENGTH'] = MAX_UPLOAD_SIZE_BYTES
app.config['UPLOAD_FOLDER'] = tempfile.gettempdir()

# Store analysis results in memory with TTL (in production, use database)
analysis_results = {}
RESULT_TTL_SECONDS = CONST_RESULT_TTL

# Store live analysis sessions
live_sessions = {}
LIVE_SESSION_TTL_SECONDS = CONST_LIVE_TTL

# In-memory config storage (in production, use database or secure storage)
app_config = {
    'manus_api_key': os.environ.get('MANUS_API_KEY', ''),
    'openai_api_key': os.environ.get('OPENAI_API_KEY', ''),
}

# Initialize self-improvement engine if available
learning_engine = None
if INTELLIGENT_MODULES_AVAILABLE:
    try:
        learning_engine = SelfImprovementEngine()
        logger.info("Learning engine initialized successfully")
    except Exception as e:
        logger.warning(f"Failed to initialize learning engine: {e}")

def cleanup_expired_results():
    """Remove expired results and their temp files"""
    while True:
        time.sleep(300)  # Check every 5 minutes
        current_time = time.time()
        expired_ids = []

        for result_id, result in list(analysis_results.items()):
            if current_time - result.get('created_at', 0) > RESULT_TTL_SECONDS:
                expired_ids.append(result_id)
                # Clean up temp files
                for path_key in ['fixed_path', 'original_path']:
                    path = result.get(path_key)
                    if path and os.path.exists(path):
                        try:
                            os.remove(path)
                        except OSError as e:
                            logger.debug(f"Could not remove temp file {path}: {e}")

        for result_id in expired_ids:
            analysis_results.pop(result_id, None)

# Start cleanup thread
cleanup_thread = threading.Thread(target=cleanup_expired_results, daemon=True)
cleanup_thread.start()

@app.route('/')
def index():
    """Render main page"""
    return render_template('index.html')

@app.route('/api/analyze', methods=['POST'])
def analyze():
    """Analyze phishlet and HAR files"""
    try:
        # Check if modules are available
        if not MODULES_AVAILABLE:
            return jsonify({
                'error': 'Analysis modules not available. Please install phishlet_parser, har_comparator, and phishlet_updater modules in the modules/ directory.'
            }), 503

        # Get uploaded files
        if 'phishlet' not in request.files or 'har' not in request.files:
            return jsonify({'error': 'Both phishlet and HAR files are required'}), 400

        phishlet_file = request.files['phishlet']
        har_file = request.files['har']
        use_ai = request.form.get('use_ai', 'false').lower() == 'true'

        # Validate file extensions
        phishlet_filename = phishlet_file.filename or 'phishlet.yaml'
        har_filename = har_file.filename or 'traffic.har'

        phishlet_ext = os.path.splitext(phishlet_filename)[1].lower()
        har_ext = os.path.splitext(har_filename)[1].lower()

        if phishlet_ext not in ALLOWED_PHISHLET_EXTENSIONS:
            return jsonify({
                'error': f'Invalid phishlet file extension. Allowed: {", ".join(ALLOWED_PHISHLET_EXTENSIONS)}'
            }), 400

        if har_ext not in ALLOWED_HAR_EXTENSIONS:
            return jsonify({
                'error': f'Invalid HAR file extension. Allowed: {", ".join(ALLOWED_HAR_EXTENSIONS)}'
            }), 400

        # Generate unique filenames to avoid conflicts
        unique_id = str(uuid.uuid4())[:8]

        phishlet_path = os.path.join(app.config['UPLOAD_FOLDER'], f'{unique_id}_{secure_filename(phishlet_filename)}')
        har_path = os.path.join(app.config['UPLOAD_FOLDER'], f'{unique_id}_{secure_filename(har_filename)}')

        phishlet_file.save(phishlet_path)
        har_file.save(har_path)

        # Validate and parse phishlet YAML
        parser = PhishletParser()
        try:
            phishlet_data = parser.parse_file(phishlet_path)
            if phishlet_data is None:
                return jsonify({'error': 'Phishlet file is empty or invalid'}), 400
        except yaml.YAMLError as e:
            logger.error(f"Invalid YAML in phishlet file: {e}")
            return jsonify({'error': 'Invalid YAML format in phishlet file'}), 400

        # Load and validate HAR file
        try:
            with open(har_path, 'r', encoding='utf-8') as f:
                har_data = json.load(f)
            # Basic HAR structure validation
            if not isinstance(har_data, dict) or 'log' not in har_data:
                return jsonify({'error': 'Invalid HAR file structure. Expected {"log": {...}}'}), 400
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in HAR file: {e}")
            return jsonify({'error': 'Invalid JSON format in HAR file'}), 400

        # Compare and find issues (module API)
        comparator = HARComparator()
        comparison = comparator.compare(har_data=har_data, phishlet_data=phishlet_data)

        # Apply fixes
        updater = PhishletUpdater()
        update_result_obj = updater.update_from_comparison(phishlet_data, comparison)
        fixed_yaml = parser.to_yaml(update_result_obj.updated_phishlet)

        # Save fixed phishlet with explicit encoding
        fixed_path = os.path.join(app.config['UPLOAD_FOLDER'], f'fixed_{unique_id}_{secure_filename(phishlet_filename)}')
        with open(fixed_path, 'w', encoding='utf-8') as f:
            f.write(fixed_yaml)

        # Prepare response
        issues = []

        # Convert ComparisonResult -> issue list
        def _add_issues(issue_type: str, severity: str, items):
            for item in items:
                issues.append({
                    'type': issue_type,
                    'severity': severity,
                    'description': str(item),
                    'fixed': True,
                    'source': 'har'
                })

        _add_issues('missing_hosts', 'critical', comparison.missing_hosts)
        _add_issues('missing_cookies', 'important', comparison.missing_cookies)
        _add_issues('missing_credential_fields', 'important', comparison.missing_credential_fields)
        _add_issues('extra_hosts', 'optional', comparison.extra_hosts)

        # Intelligent analysis on HAR-derived traffic (optional)
        intelligent_analysis = None
        if INTELLIGENT_MODULES_AVAILABLE:
            try:
                # Build traffic_data from HAR for intelligent modules
                traffic_data = traffic_data_from_har(har_data)

                auth_analysis = classify_auth_flow(traffic_data)
                cred_pattern = extract_credentials(traffic_data.get('form_submissions', []))
                cookie_analysis = analyze_cookies(traffic_data.get('cookies_captured', {}), traffic_data)

                intelligent_analysis = {
                    'auth_flow_type': auth_analysis.primary_type,
                    'auth_flow_confidence': auth_analysis.confidence,
                    'recommendations': auth_analysis.recommendations,
                    'credential_pattern': {
                        'username_key': cred_pattern.username_key,
                        'password_key': cred_pattern.password_key,
                        'confidence': cred_pattern.confidence,
                        'method': cred_pattern.extraction_method,
                    },
                    'cookie_analysis': {
                        'auth_tokens': cookie_analysis.auth_tokens,
                        'critical_cookies': cookie_analysis.critical_cookies,
                        'important_cookies': cookie_analysis.important_cookies,
                        'optional_cookies': cookie_analysis.optional_cookies,
                        'recommendations': cookie_analysis.recommendations,
                    },
                }
            except Exception as e:
                intelligent_analysis = {'error': str(e)}

        # Use UUID for result_id (thread-safe)
        result_id = str(uuid.uuid4())
        analysis_results[result_id] = {
            'phishlet_filename': phishlet_filename,
            'har_filename': har_filename,
            'issues_found': len(issues),
            'fixes_applied': len(update_result_obj.changes_made),
            'changes_made': update_result_obj.changes_made,
            'warnings': update_result_obj.warnings,
            'issues': issues,
            'intelligent_analysis': intelligent_analysis,
            'comparison_summary': {
                'har_summary': comparison.har_summary,
                'phishlet_summary': comparison.phishlet_summary,
                'recommendations': comparison.recommendations,
            },
            'fixed_path': fixed_path,
            'original_path': phishlet_path,
            'har_data': har_data,  # Store HAR data for AI regeneration
            'created_at': time.time()
        }

        # Note: We keep HAR data in memory for AI regeneration
        # Cleanup HAR file immediately (data is already loaded)
        try:
            os.remove(har_path)
        except OSError as e:
            logger.debug(f"Could not remove HAR temp file {har_path}: {e}")

        return jsonify({
            'success': True,
            'result_id': result_id,
            'issues_found': len(issues),
            'fixes_applied': len(update_result_obj.changes_made),
            'changes_made': update_result_obj.changes_made,
            'warnings': update_result_obj.warnings,
            'issues': issues,
            'intelligent_analysis': intelligent_analysis,
            'comparison_summary': {
                'har_summary': comparison.har_summary,
                'phishlet_summary': comparison.phishlet_summary,
                'recommendations': comparison.recommendations,
            },
        })

    except yaml.YAMLError as e:
        logger.error(f"YAML parsing error in analyze: {e}")
        return jsonify({'error': 'Invalid YAML format in phishlet file'}), 400
    except json.JSONDecodeError as e:
        logger.error(f"JSON parsing error in analyze: {e}")
        return jsonify({'error': 'Invalid JSON format in HAR file'}), 400
    except Exception as e:
        logger.exception(f"Unexpected error in analyze endpoint: {e}")
        return jsonify({'error': 'An internal error occurred during analysis. Check server logs for details.'}), 500

@app.route('/api/download/<result_id>')
def download(result_id):
    """Download fixed phishlet"""
    if result_id not in analysis_results:
        return jsonify({'error': 'Result not found or expired'}), 404

    result = analysis_results[result_id]
    fixed_path = result.get('fixed_path')

    # Verify file still exists
    if not fixed_path or not os.path.exists(fixed_path):
        return jsonify({'error': 'Fixed phishlet file no longer available. Please re-analyze.'}), 404

    return send_file(
        fixed_path,
        as_attachment=True,
        download_name=f"fixed_{result['phishlet_filename']}"
    )

def _trim_text(text: str, max_len: int = 200000) -> tuple[str, bool]:
    """Trim large text blobs for prompt safety."""
    if len(text) <= max_len:
        return text, False
    return text[:max_len] + "\n... [truncated]", True

def _summarize_har(traffic_data: dict) -> dict:
    """Generate a compact summary for prompts from HAR-derived traffic data."""
    summary = {
        'unique_hosts': traffic_data.get('unique_hosts', []),
        'form_submissions': [],
        'detected_auth_tokens': traffic_data.get('detected_auth_tokens', []),
        'cookies_captured': {},
    }

    for form in traffic_data.get('form_submissions', [])[:10]:
        summary['form_submissions'].append({
            'url': form.get('url'),
            'content_type': form.get('content_type'),
            'detected_username_field': form.get('detected_username_field'),
            'detected_password_field': form.get('detected_password_field'),
        })

    cookies = traffic_data.get('cookies_captured', {}) or {}
    for domain, cookie_map in cookies.items():
        if isinstance(cookie_map, dict):
            summary['cookies_captured'][domain] = list(cookie_map.keys())

    return summary

def _build_manus_update_prompt(old_yaml: str, live_yaml: str, har_text: str, har_summary: dict, har_truncated: bool) -> str:
    """Build Manus prompt to update old phishlet using live YAML + HAR evidence."""
    trunc_note = "The HAR content below was truncated due to size." if har_truncated else "The HAR content below is complete."

    return f"""# Phishlet Update Task

You are an expert in Evilginx3 phishlet development. Update the OLD phishlet YAML using the NEW live-session YAML and the HAR capture.

## Instructions
1. Use the live-session YAML as the best reflection of current login behavior.
2. Use the HAR capture to verify hosts, auth tokens, cookies, and login endpoints.
3. Preserve any manual overrides or customizations from the old YAML unless contradicted by live YAML/HAR.
4. Output a complete, updated phishlet YAML.
5. Provide a short changelog of what was updated.

## OLD Phishlet YAML (baseline)
```yaml
{old_yaml}
```

## NEW Phishlet YAML (from live session)
```yaml
{live_yaml}
```

## HAR Summary (derived from the provided HAR file)
```json
{json.dumps(har_summary, indent=2)}
```

## HAR File Content
{trunc_note}
```json
{har_text}
```
"""

@app.route('/api/validate', methods=['POST'])
def validate():
    """Validate and regenerate phishlet using Manus AI"""
    try:
        data = request.json
        if not data:
            return jsonify({'error': 'Invalid JSON request'}), 400
        
        result_id = data.get('result_id')
        manus_api_key = data.get('manus_api_key')

        if not result_id or result_id not in analysis_results:
            return jsonify({'error': 'Invalid result ID'}), 400

        if not manus_api_key:
            return jsonify({'error': 'Manus API key required'}), 400

        result = analysis_results[result_id]
        fixed_path = result.get('fixed_path')

        # Verify file still exists
        if not fixed_path or not os.path.exists(fixed_path):
            return jsonify({'error': 'Phishlet file no longer available. Please re-analyze.'}), 404

        # Use intelligent AI refiner if available
        if INTELLIGENT_MODULES_AVAILABLE:
            # Read phishlet with explicit encoding
            with open(fixed_path, 'r', encoding='utf-8') as f:
                phishlet_content = f.read()
            
            # Check if we have HAR data stored
            har_data = result.get('har_data')
            
            # Use AI refiner
            ai_result = refine_with_ai(
                phishlet_content, 
                api_key=manus_api_key,
                traffic_data={'har_data': har_data} if har_data else None
            )
            
            if not ai_result.success:
                return jsonify({
                    'success': False,
                    'error': ai_result.error or 'AI refinement failed',
                    'message': 'AI could not process the request'
                }), 500
                
            # Store task info for reference
            result['manus_task_id'] = ai_result.task_id
            result['manus_task_url'] = ai_result.task_url
            result['manus_share_url'] = ai_result.share_url
            
            return jsonify({
                'success': True,
                'task_id': ai_result.task_id,
                'task_url': ai_result.task_url,
                'share_url': ai_result.share_url,
                'message': ai_result.analysis or 'Task created successfully. View progress in Manus AI.',
                'has_regenerated': False, # Async process
                'analysis': ai_result.analysis,
                'issues': [],
                'testing_notes': ''
            })
        else:
            # Intelligent modules not available - AI refinement requires them
            return jsonify({
                'success': False,
                'error': 'AI refinement requires intelligent modules. Please ensure all modules are installed.',
                'message': 'Validation feature not available'
            }), 503

    except Exception as e:
        logger.exception(f"Unexpected error in validate endpoint: {e}")
        return jsonify({'error': 'An internal error occurred during validation. Check server logs for details.'}), 500


@app.route('/api/ai/update', methods=['POST'])
def ai_update():
    """Create Manus AI task to update old phishlet using live YAML + HAR"""
    if not INTELLIGENT_MODULES_AVAILABLE:
        return jsonify({'error': 'AI update requires intelligent modules.'}), 503

    try:
        manus_api_key = request.form.get('manus_api_key') or app_config.get('manus_api_key')
        if not manus_api_key:
            return jsonify({'error': 'Manus API key required'}), 400

        old_file = request.files.get('old_phishlet')
        live_file = request.files.get('live_yaml')
        har_file = request.files.get('har')

        if not old_file or not live_file or not har_file:
            return jsonify({'error': 'Missing required files: old_phishlet, live_yaml, and har are required.'}), 400

        old_yaml = old_file.read().decode('utf-8', errors='ignore')
        live_yaml = live_file.read().decode('utf-8', errors='ignore')
        har_text_raw = har_file.read().decode('utf-8', errors='ignore')

        # Parse HAR JSON for summary
        try:
            har_json = json.loads(har_text_raw)
        except json.JSONDecodeError:
            return jsonify({'error': 'Invalid HAR JSON file'}), 400

        har_summary = {}
        if 'traffic_data_from_har' in globals() and traffic_data_from_har:
            try:
                traffic_data = traffic_data_from_har(har_json)
                har_summary = _summarize_har(traffic_data)
            except Exception as e:
                logger.warning(f"Failed to summarize HAR: {e}")
                har_summary = {}

        har_text, har_truncated = _trim_text(har_text_raw)

        prompt = _build_manus_update_prompt(
            old_yaml=old_yaml,
            live_yaml=live_yaml,
            har_text=har_text,
            har_summary=har_summary,
            har_truncated=har_truncated,
        )

        refiner = AIPhishletRefiner(api_key=manus_api_key)
        task_response = refiner.create_task(prompt)

        if not task_response.success:
            error_msg = task_response.error or 'Manus AI task creation failed'
            error_l = error_msg.lower()
            if '401' in error_l or 'invalid token' in error_l:
                return jsonify({
                    'error': 'Manus API rejected the key. Verify your Manus token and try again.',
                    'details': error_msg
                }), 401
            return jsonify({'error': error_msg}), 500

        return jsonify({
            'success': True,
            'task_id': task_response.task_id,
            'task_url': task_response.task_url,
            'share_url': task_response.share_url,
            'message': task_response.analysis or 'Task created successfully. View progress in Manus AI.'
        })

    except Exception as e:
        logger.exception(f"Unexpected error in ai_update endpoint: {e}")
        return jsonify({'error': 'An internal error occurred during AI update. Check server logs for details.'}), 500


@app.route('/api/download/ai/<result_id>')
def download_ai_regenerated(result_id):
    """Download AI-regenerated phishlet"""
    if result_id not in analysis_results:
        return jsonify({'error': 'Result not found or expired'}), 404

    result = analysis_results[result_id]
    ai_fixed_path = result.get('ai_fixed_path')

    if not ai_fixed_path or not os.path.exists(ai_fixed_path):
        return jsonify({'error': 'AI-regenerated phishlet not available. Run AI validation first.'}), 404

    return send_file(
        ai_fixed_path,
        as_attachment=True,
        download_name=f"ai_regenerated_{result['phishlet_filename']}"
    )

@app.route('/api/config', methods=['GET', 'POST'])
def config():
    """Get or set configuration"""
    if request.method == 'POST':
        config_data = request.json
        if not config_data:
            return jsonify({'error': 'Invalid JSON request'}), 400

        # Update only allowed config keys (don't allow arbitrary keys)
        allowed_keys = {'manus_api_key', 'openai_api_key'}
        updated_keys = []

        for key in allowed_keys:
            if key in config_data:
                app_config[key] = config_data[key]
                updated_keys.append(key)

        if not updated_keys:
            return jsonify({
                'success': False,
                'error': f'No valid config keys provided. Allowed: {list(allowed_keys)}'
            }), 400

        logger.info(f"Config updated: {updated_keys}")
        return jsonify({
            'success': True,
            'updated_keys': updated_keys
        })
    else:
        # Return current config (only indicate if keys are set, don't expose values)
        return jsonify({
            'manus_api_key_set': bool(app_config.get('manus_api_key')),
            'openai_api_key_set': bool(app_config.get('openai_api_key'))
        })

# ============================================================================
# LIVE TRAFFIC ANALYSIS ENDPOINTS
# ============================================================================

@app.route('/api/live/start', methods=['POST'])
def live_start():
    """Start a new live traffic analysis session with optional old phishlet comparison"""
    if not LIVE_ANALYZER_AVAILABLE:
        error_message = 'Live traffic analyzer not available. Please install Playwright: pip install playwright && playwright install chromium'
        if isinstance(PLAYWRIGHT_STATUS, dict) and PLAYWRIGHT_STATUS.get('message'):
            error_message = PLAYWRIGHT_STATUS['message']
        return jsonify({
            'error': error_message
        }), 503

    try:
        # Handle both JSON and form data (for file upload)
        if request.is_json:
            target_url = request.json.get('target_url') if request.json else None
            headless = request.json.get('headless', False) if request.json else False
            old_phishlet_data = None
        else:
            # Form data with optional file upload
            target_url = request.form.get('target_url')
            headless = request.form.get('headless', 'false').lower() == 'true'
            
            # Check for optional old phishlet file
            old_phishlet_data = None
            if 'old_phishlet' in request.files:
                old_phishlet_file = request.files['old_phishlet']
                if old_phishlet_file.filename:
                    try:
                        old_phishlet_content = old_phishlet_file.read().decode('utf-8')
                        parser_cls = globals().get('PhishletParser')
                        if MODULES_AVAILABLE and parser_cls is not None:
                            parser = parser_cls()
                            old_phishlet_data = parser.parse(old_phishlet_content)
                        else:
                            loaded = yaml.safe_load(old_phishlet_content)
                            old_phishlet_data = loaded if isinstance(loaded, dict) else None
                        logger.info(f"Old phishlet loaded for comparison: {old_phishlet_file.filename}")
                    except Exception as e:
                        logger.warning(f"Failed to parse old phishlet: {e}")
                        # Continue without old phishlet - it's optional

        if not target_url:
            return jsonify({'error': 'target_url is required'}), 400

        # Validate URL
        if not target_url.startswith(('http://', 'https://')):
            target_url = f'https://{target_url}'

        # Generate session ID
        session_id = str(uuid.uuid4())

        # Create new session
        session = LiveAnalysisSession(session_id, headless=headless)
        live_sessions[session_id] = {
            'session': session,
            'created_at': time.time(),
            'target_url': target_url,
            'status': 'starting',
            'old_phishlet_data': old_phishlet_data  # Store for comparison
        }

        # Start session in background thread with isolated event loop
        def run_session():
            """Run async session in isolated thread with dedicated event loop."""
            # Create isolated event loop for this thread
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                loop.run_until_complete(session.start(target_url))
                live_sessions[session_id]['status'] = 'waiting_for_auth'
            except Exception as e:
                logger.exception(f"Error in live session {session_id}: {e}")
                live_sessions[session_id]['status'] = 'error'
                live_sessions[session_id]['error'] = str(e)
            finally:
                # Clean up the event loop properly
                try:
                    loop.run_until_complete(loop.shutdown_asyncgens())
                finally:
                    loop.close()

        thread = threading.Thread(target=run_session, daemon=True, name=f"live-session-{session_id[:8]}")
        thread.start()

        return jsonify({
            'success': True,
            'session_id': session_id,
            'message': 'Live analysis session started. Browser will open shortly.',
            'target_url': target_url,
            'has_old_phishlet': old_phishlet_data is not None
        })

    except Exception as e:
        logger.exception(f"Error starting live analysis session: {e}")
        return jsonify({'error': 'Failed to start live analysis session. Check server logs.'}), 500


@app.route('/api/live/status/<session_id>')
def live_status(session_id):
    """Get status of a live analysis session"""
    if session_id not in live_sessions:
        return jsonify({'error': 'Session not found'}), 404

    session_data = live_sessions[session_id]
    session = session_data.get('session')

    if session is None:
        return jsonify({'error': 'Session object not found'}), 404

    status = session.get_status()
    status['session_status'] = session_data.get('status', 'unknown')
    status['target_url'] = session_data.get('target_url', '')

    if session_data.get('error'):
        status['error'] = session_data['error']

    # Also expose whether the analyzer has observed evidence of authentication.
    # This does not auto-stop capture; it's purely UI feedback.
    status['auth_observed'] = bool(status.get('auth_observed', False))

    return jsonify(status)


@app.route('/api/live/stop/<session_id>', methods=['POST'])
def live_stop(session_id):
    """Stop a live analysis session and get results"""
    if session_id not in live_sessions:
        return jsonify({'error': 'Session not found'}), 404

    session_data = live_sessions[session_id]
    session = session_data.get('session')

    if session is None:
        return jsonify({'error': 'Session object not found'}), 404

    try:
        # Run stop and analyze in background with isolated event loop
        def run_analysis():
            """Run async analysis in isolated thread with dedicated event loop."""
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                live_sessions[session_id]['status'] = 'analyzing'
                result = loop.run_until_complete(session.stop_and_analyze())
                live_sessions[session_id]['status'] = 'completed'
                live_sessions[session_id]['result'] = result.to_dict()
            except Exception as e:
                logger.exception(f"Error analyzing session {session_id}: {e}")
                live_sessions[session_id]['status'] = 'error'
                live_sessions[session_id]['error'] = str(e)
            finally:
                # Clean up the event loop properly
                try:
                    loop.run_until_complete(loop.shutdown_asyncgens())
                finally:
                    loop.close()

        thread = threading.Thread(target=run_analysis, daemon=True, name=f"analyze-{session_id[:8]}")
        thread.start()
        thread.join(timeout=30)  # Wait up to 30 seconds

        if session_data.get('result'):
            return jsonify({
                'success': True,
                'session_id': session_id,
                'result': session_data['result']
            })
        else:
            return jsonify({
                'success': True,
                'session_id': session_id,
                'message': 'Analysis in progress. Check status endpoint.',
                'status': session_data.get('status', 'analyzing')
            })

    except Exception as e:
        logger.exception(f"Error stopping live analysis session {session_id}: {e}")
        return jsonify({'error': 'Failed to stop analysis session. Check server logs.'}), 500


@app.route('/api/live/result/<session_id>')
def live_result(session_id):
    """Get the analysis result for a completed session"""
    if session_id not in live_sessions:
        return jsonify({'error': 'Session not found'}), 404

    session_data = live_sessions[session_id]

    if session_data.get('status') != 'completed':
        return jsonify({
            'error': 'Analysis not complete',
            'status': session_data.get('status', 'unknown')
        }), 400

    result = session_data.get('result')
    if not result:
        return jsonify({'error': 'No result available'}), 404

    return jsonify({
        'success': True,
        'session_id': session_id,
        'result': result
    })


@app.route('/api/live/compare/<session_id>')
def live_compare(session_id):
    """Compare live analysis results with old phishlet for insights"""
    if session_id not in live_sessions:
        return jsonify({'error': 'Session not found'}), 404

    session_data = live_sessions[session_id]
    
    if session_data.get('status') != 'completed':
        return jsonify({
            'error': 'Analysis not complete',
            'status': session_data.get('status', 'unknown')
        }), 400

    old_phishlet_data = session_data.get('old_phishlet_data')
    if not old_phishlet_data:
        return jsonify({'error': 'No old phishlet data available for comparison'}), 404

    result = session_data.get('result')
    if not result:
        return jsonify({'error': 'No live analysis result available'}), 404

    try:
        # Convert live result to traffic data for updater
        if not MODULES_AVAILABLE:
            return jsonify({'error': 'Analysis modules not available'}), 503
            
        # Build list of hosts and cookies from live result
        har_hosts = result.get('unique_hosts', [])
        har_cookies = {}
        
        # Convert cookies_captured format to updater format
        cookies_captured = result.get('cookies_captured', {})
        for domain, cookies in cookies_captured.items():
            if isinstance(cookies, dict):
                har_cookies[domain] = list(cookies.keys())
        
        # Use updater's direct HAR analysis method
        updater = PhishletUpdater()
        update_result = updater.update_from_har_analysis(
            old_phishlet_data, 
            har_hosts, 
            har_cookies
        )

        # Build comparison insights
        insights = {
            'changes_made': update_result.changes_made,
            'warnings': update_result.warnings,
            'hosts_added': [h for h in har_hosts if h not in [ph.get('domain', '') for ph in old_phishlet_data.get('proxy_hosts', [])]],
            'cookies_added': har_cookies,
        }

        return jsonify({
            'success': True,
            'session_id': session_id,
            'has_old_phishlet': True,
            'comparison': insights
        })

    except Exception as e:
        logger.exception(f"Error comparing live results with old phishlet: {e}")
        return jsonify({'error': 'Failed to compare with old phishlet'}), 500


@app.route('/api/live/generate-phishlet/<session_id>', methods=['POST'])
def live_generate_phishlet(session_id):
    """Generate phishlet YAML from live analysis results"""
    if session_id not in live_sessions:
        return jsonify({'error': 'Session not found'}), 404

    session_data = live_sessions[session_id]
    session = session_data.get('session')

    if session is None:
        return jsonify({'error': 'Session object not found'}), 404
    
    if not session.result:
        return jsonify({'error': 'No analysis result available'}), 400

    try:
        # Support both JSON and multipart form-data (for optional authenticated HAR upload)
        if request.is_json:
            data = request.json or {}
            phishlet_name = data.get('name')
            use_old_as_baseline = data.get('use_old_as_baseline', True)
            auth_har_file = None
        else:
            phishlet_name = request.form.get('name')
            use_old_as_baseline = str(request.form.get('use_old_as_baseline', 'true')).lower() == 'true'
            auth_har_file = request.files.get('auth_har')

        # Check if we have an old phishlet to use as baseline
        old_phishlet_data = session_data.get('old_phishlet_data')
        
        if old_phishlet_data and use_old_as_baseline and MODULES_AVAILABLE:
            # Update the old phishlet with new findings from live analysis
            logger.info(f"Using old phishlet as baseline for session {session_id}")
            
            # Build list of hosts and cookies from live result
            har_hosts = session.result.unique_hosts
            har_cookies = {}
            
            # Convert cookies_captured format to updater format
            for domain, cookies in session.result.cookies_captured.items():
                if isinstance(cookies, dict):
                    har_cookies[domain] = list(cookies.keys())
            
            # Use updater's direct HAR analysis method
            updater = PhishletUpdater()
            update_result = updater.update_from_har_analysis(
                old_phishlet_data, 
                har_hosts, 
                har_cookies
            )
            
            # Convert updated phishlet to YAML
            parser = PhishletParser()
            yaml_content = parser.to_yaml(update_result.updated_phishlet)
            
            generation_method = 'updated_from_baseline'
            changes_made = update_result.changes_made
            warnings = update_result.warnings
        else:
            # Generate fresh phishlet from scratch
            logger.info(f"Generating fresh phishlet for session {session_id}")

            # Optional: merge authenticated HAR traffic with live capture before generation.
            if auth_har_file and auth_har_file.filename and INTELLIGENT_MODULES_AVAILABLE:
                try:
                    from phishcreator.modules.traffic_merger import merge_traffic_data

                    # Read HAR json
                    har_data = json.load(auth_har_file.stream)
                    har_traffic = traffic_data_from_har(har_data)

                    # Build live traffic_data shape
                    live_traffic = {
                        'unique_hosts': session.result.unique_hosts,
                        'all_requests': session.result.all_requests,
                        'all_responses': session.result.all_responses,
                        'form_submissions': session.result.form_submissions,
                        'cookies_captured': session.result.cookies_captured,
                        'storage_state': session.result.storage_state,
                        'detected_proxy_hosts': session.result.detected_proxy_hosts,
                        'detected_auth_tokens': session.result.detected_auth_tokens,
                        'detected_login_url': session.result.detected_login_url,
                        'detected_credentials': session.result.detected_credentials,
                        'warnings': session.result.warnings,
                    }

                    merged_traffic = merge_traffic_data(live_traffic, har_traffic)

                    # Use dynamic generator directly for merged traffic
                    from phishcreator.modules.dynamic_phishlet_generator import generate_phishlet
                    target_domain = session.analyzer.target_domain or 'example.com'
                    gen = generate_phishlet(target_domain, merged_traffic, phishlet_name)
                    yaml_content = gen.phishlet_yaml
                    generation_method = 'generated_from_live_plus_har'
                    changes_made = []
                    warnings = gen.warnings
                except Exception as e:
                    logger.warning(f"Failed to merge authenticated HAR, falling back to live-only: {e}")
                    yaml_content = session.generate_phishlet(phishlet_name)
                    generation_method = 'generated_fresh'
                    changes_made = []
                    warnings = []
            else:
                yaml_content = session.generate_phishlet(phishlet_name)
                generation_method = 'generated_fresh'
                changes_made = []
                warnings = []

        # Store for download
        unique_id = str(uuid.uuid4())[:8]
        filename = f"live_generated_{phishlet_name or 'phishlet'}_{unique_id}.yaml"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(yaml_content)

        # Store path in session for download
        session_data['generated_phishlet_path'] = filepath
        session_data['generated_phishlet_filename'] = filename
        
        # Record generation attempt in learning engine
        if learning_engine and session.result:
            try:
                # Create a preliminary test result (success=True for generation)
                # In a real scenario, we would update this after actual testing
                test_result = PhishletTestResult(
                    phishlet_name=phishlet_name or 'generated',
                    target_domain=session.analyzer.target_domain or 'unknown',
                    auth_type=session.result.auth_flow_type,
                    success=True, # Assumed successful generation
                    credential_capture=bool(session.result.detected_credentials),
                    cookie_capture=bool(session.result.detected_auth_tokens),
                    confidence_score=session.result.confidence
                )
                learning_engine.record_test_result(test_result)
            except Exception as e:
                logger.warning(f"Failed to record learning data: {e}")

        return jsonify({
            'success': True,
            'session_id': session_id,
            'filename': filename,
            'generation_method': generation_method,
            'changes_made': changes_made,
            'warnings': warnings,
            'used_baseline': old_phishlet_data is not None and use_old_as_baseline,
            'used_authenticated_har': bool(auth_har_file and getattr(auth_har_file, 'filename', '')),
            'yaml_preview': yaml_content[:2000] + '...' if len(yaml_content) > 2000 else yaml_content
        })

    except Exception as e:
        logger.exception(f"Error generating phishlet for session {session_id}: {e}")
        return jsonify({'error': 'Failed to generate phishlet. Check server logs.'}), 500


@app.route('/api/live/download/<session_id>')
def live_download(session_id):
    """Download generated phishlet from live analysis"""
    if session_id not in live_sessions:
        return jsonify({'error': 'Session not found'}), 404

    session_data = live_sessions[session_id]
    filepath = session_data.get('generated_phishlet_path')
    filename = session_data.get('generated_phishlet_filename', 'generated_phishlet.yaml')

    if not filepath or not os.path.exists(filepath):
        return jsonify({'error': 'Generated phishlet not available. Generate first.'}), 404

    return send_file(
        filepath,
        as_attachment=True,
        download_name=filename
    )


@app.route('/api/live/sessions')
def live_sessions_list():
    """List all live analysis sessions"""
    sessions_list = []
    current_time = time.time()

    for session_id, session_data in list(live_sessions.items()):
        age = current_time - session_data.get('created_at', 0)
        sessions_list.append({
            'session_id': session_id,
            'status': session_data.get('status', 'unknown'),
            'target_url': session_data.get('target_url', ''),
            'age_seconds': int(age),
            'has_result': session_data.get('result') is not None
        })

    return jsonify({
        'sessions': sessions_list,
        'live_analyzer_available': LIVE_ANALYZER_AVAILABLE,
        'playwright_status': PLAYWRIGHT_STATUS
    })


# ============================================================================
# COMBINED ANALYSIS ENDPOINT (HAR + Live)
# ============================================================================

@app.route('/api/combined-analyze', methods=['POST'])
def combined_analyze():
    """
    Combined analysis endpoint that can work with:
    1. Traditional HAR file upload
    2. Live traffic analysis results
    3. Both combined for comprehensive analysis
    """
    try:
        result_id = str(uuid.uuid4())
        issues = []
        fixes_applied = 0

        # Check for live session result
        live_session_id = request.form.get('live_session_id') or (request.json or {}).get('live_session_id')
        if live_session_id and live_session_id in live_sessions:
            session_data = live_sessions[live_session_id]
            live_result = session_data.get('result')

            if live_result:
                # Convert live analysis result to issues format
                for host in live_result.get('detected_proxy_hosts', []):
                    issues.append({
                        'type': 'detected_proxy_host',
                        'severity': 'critical' if host.get('is_landing') else 'important',
                        'description': f"Detected proxy host: {host.get('_original_host', host.get('domain'))}",
                        'fixed': True,
                        'source': 'live_analysis'
                    })

                for token in live_result.get('detected_auth_tokens', []):
                    issues.append({
                        'type': 'detected_auth_token',
                        'severity': token.get('_priority', 'important'),
                        'description': f"Detected auth token: {token.get('keys', ['unknown'])[0]}",
                        'fixed': True,
                        'source': 'live_analysis'
                    })

                creds = live_result.get('detected_credentials', {})
                if creds.get('username'):
                    issues.append({
                        'type': 'detected_credential',
                        'severity': 'critical',
                        'description': f"Detected username field: {creds['username']}",
                        'fixed': True,
                        'source': 'live_analysis'
                    })
                if creds.get('password'):
                    issues.append({
                        'type': 'detected_credential',
                        'severity': 'critical',
                        'description': f"Detected password field: {creds['password']}",
                        'fixed': True,
                        'source': 'live_analysis'
                    })

                for warning in live_result.get('warnings', []):
                    issues.append({
                        'type': 'warning',
                        'severity': 'optional',
                        'description': warning,
                        'fixed': False,
                        'source': 'live_analysis'
                    })

                fixes_applied = len([i for i in issues if i.get('fixed')])

        # Store result
        analysis_results[result_id] = {
            'issues_found': len(issues),
            'fixes_applied': fixes_applied,
            'issues': issues,
            'live_session_id': live_session_id,
            'created_at': time.time()
        }

        return jsonify({
            'success': True,
            'result_id': result_id,
            'issues_found': len(issues),
            'fixes_applied': fixes_applied,
            'issues': issues
        })

    except Exception as e:
        logger.exception(f"Error in combined analysis: {e}")
        return jsonify({'error': 'Combined analysis failed. Check server logs.'}), 500


@app.route('/api/status')
def status():
    """Return service status"""
    return jsonify({
        'status': 'running',
        'modules_available': MODULES_AVAILABLE,
        'live_analyzer_available': LIVE_ANALYZER_AVAILABLE,
        'intelligent_modules_available': INTELLIGENT_MODULES_AVAILABLE,
        'playwright_status': PLAYWRIGHT_STATUS,
        'version': '2.1.0'
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5050))
    print(f"Starting PhishCreator Pro on port {port}")
    print(f"Modules available: {MODULES_AVAILABLE}")
    print(f"Live Traffic Analyzer available: {LIVE_ANALYZER_AVAILABLE}")
    print(f"Playwright status: {PLAYWRIGHT_STATUS}")
    print(f"Intelligent Modules available: {INTELLIGENT_MODULES_AVAILABLE}")
    app.run(host='0.0.0.0', port=port, debug=False)
