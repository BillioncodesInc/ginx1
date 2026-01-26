#!/usr/bin/env python3
"""phishcreator.modules.har_traffic_extractor

Utilities to convert HAR files into the lightweight `traffic_data` structure
used by the intelligent modules:

- auth_flow_classifier.classify_auth_flow
- intelligent_credential_extractor.extract_credentials
- smart_cookie_analyzer.analyze_cookies

The goal is *not* a perfect HAR parser, but a best-effort extraction that:
- extracts request/response URL/method/headers
- extracts POST bodies (text or params)
- identifies likely credential submissions
- aggregates cookies set/used across hosts

This enables `/api/analyze` (HAR upload) to run the same intelligence pipeline
as the live Playwright capture.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs

# Import shared constants
try:
    from phishcreator.modules.constants import USERNAME_PATTERNS, PASSWORD_PATTERNS
    CONSTANTS_AVAILABLE = True
except ImportError:
    try:
        from constants import USERNAME_PATTERNS, PASSWORD_PATTERNS
        CONSTANTS_AVAILABLE = True
    except ImportError:
        CONSTANTS_AVAILABLE = False
        USERNAME_PATTERNS = None
        PASSWORD_PATTERNS = None


def _lower_headers(headers: List[Dict[str, str]] | Dict[str, str] | None) -> Dict[str, str]:
    if not headers:
        return {}
    if isinstance(headers, dict):
        return {str(k).lower(): str(v) for k, v in headers.items()}
    out: Dict[str, str] = {}
    for h in headers:
        name = str(h.get("name", "")).strip()
        value = str(h.get("value", "")).strip()
        if name:
            out[name.lower()] = value
    return out


def _parse_post_data(post_data: Dict[str, Any] | None) -> Tuple[str, str, Dict[str, Any]]:
    """Return (content_type, text, fields).

    fields is a dict representation when it can be extracted (from params,
    x-www-form-urlencoded, or JSON).
    """
    if not post_data:
        return "", "", {}

    mime = str(post_data.get("mimeType", "") or "")
    text = str(post_data.get("text", "") or "")

    # params (standard HAR format for form submissions)
    params = post_data.get("params")
    if isinstance(params, list) and params:
        fields: Dict[str, Any] = {}
        for p in params:
            name = p.get("name")
            if not name:
                continue
            fields[str(name)] = p.get("value")
        return mime, text, fields

    # Try to parse x-www-form-urlencoded from text
    if "application/x-www-form-urlencoded" in mime and text:
        try:
            parsed = parse_qs(text, keep_blank_values=True)
            fields = {k: (v[0] if len(v) == 1 else v) for k, v in parsed.items()}
            return mime, text, fields
        except Exception:
            return mime, text, {}

    # Try JSON
    if "application/json" in mime and text:
        try:
            return mime, text, json.loads(text)
        except Exception:
            return mime, text, {}

    return mime, text, {}


def _detect_credential_keys(fields: Any) -> Tuple[Optional[str], Optional[str]]:
    """Best-effort detection of username/password keys from a dict-like payload."""
    if not isinstance(fields, dict):
        return None, None

    # Use shared constants or fallback to defaults
    username_patterns = [p.lower() for p in USERNAME_PATTERNS] if USERNAME_PATTERNS else [
        "username",
        "user",
        "email",
        "login",
        "account",
        "identifier",
        "loginfmt",
        "userprincipalname",
    ]
    password_patterns = [p.lower() for p in PASSWORD_PATTERNS] if PASSWORD_PATTERNS else [
        "password", "passwd", "pass", "pwd", "pin", "passcode"
    ]

    def walk(obj: Any, prefix: str = ""):
        if isinstance(obj, dict):
            for k, v in obj.items():
                key = str(k)
                path = f"{prefix}.{key}" if prefix else key
                yield path, key, v
                yield from walk(v, path)
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                path = f"{prefix}[{i}]"
                yield from walk(v, path)

    user_key = None
    pass_key = None

    for path, key, value in walk(fields):
        key_l = key.lower()
        if user_key is None and any(p in key_l for p in username_patterns):
            user_key = path
        if pass_key is None and any(p in key_l for p in password_patterns):
            pass_key = path
        if user_key and pass_key:
            break

    return user_key, pass_key


def traffic_data_from_har(har_data: Dict[str, Any]) -> Dict[str, Any]:
    """Convert HAR json dict to `traffic_data` expected by intelligent modules."""

    entries = har_data.get("log", {}).get("entries", []) or []

    all_requests: List[Dict[str, Any]] = []
    all_responses: List[Dict[str, Any]] = []
    form_submissions: List[Dict[str, Any]] = []

    cookies_captured: Dict[str, Dict[str, Any]] = {}
    unique_hosts = set()

    for entry in entries:
        req = entry.get("request", {}) or {}
        res = entry.get("response", {}) or {}

        url = str(req.get("url", "") or "")
        method = str(req.get("method", "GET") or "GET")

        parsed = urlparse(url) if url else None
        host = parsed.netloc if parsed else ""
        if host:
            unique_hosts.add(host)

        req_headers = _lower_headers(req.get("headers"))
        post_data = req.get("postData")
        content_type, post_text, post_fields = _parse_post_data(post_data)

        request_obj = {
            "url": url,
            "method": method,
            "headers": req_headers,
            "post_data": post_text,
        }
        all_requests.append(request_obj)

        # request cookies
        for c in req.get("cookies", []) or []:
            name = c.get("name")
            if not name or not host:
                continue
            cookies_captured.setdefault(host, {})[str(name)] = {
                "name": str(name),
                "value": c.get("value"),
                "domain": host,
                "path": c.get("path"),
            }

        # response
        res_headers = _lower_headers(res.get("headers"))
        all_responses.append(
            {
                "url": url,
                "status": int(res.get("status", 0) or 0),
                "headers": res_headers,
            }
        )

        # response cookies
        for c in res.get("cookies", []) or []:
            name = c.get("name")
            if not name or not host:
                continue
            cookies_captured.setdefault(host, {})[str(name)] = {
                "name": str(name),
                "value": c.get("value"),
                "domain": c.get("domain") or host,
                "path": c.get("path"),
                "httpOnly": bool(c.get("httpOnly")),
                "secure": bool(c.get("secure")),
                "sameSite": c.get("sameSite"),
                "expires": c.get("expires"),
            }

        # detect submissions
        if method.upper() == "POST" and (post_fields or post_text):
            detected_user, detected_pass = _detect_credential_keys(post_fields)

            form_submissions.append(
                {
                    "url": url,
                    "method": method,
                    "content_type": content_type,
                    "fields": post_fields if post_fields else {"raw": post_text},
                    "detected_username_field": detected_user,
                    "detected_password_field": detected_pass,
                }
            )

    # Best-effort capture of storage-like tokens is not possible from HAR alone.
    # But we can still pass an empty storage_state to keep the shape consistent.

    return {
        "unique_hosts": sorted(unique_hosts),
        "all_requests": all_requests,
        "all_responses": all_responses,
        "form_submissions": form_submissions,
        "cookies_captured": cookies_captured,
        "storage_state": {"localStorage": {}, "sessionStorage": {}, "captured_at": None},
        # optional fields used by generator (may be filled by live analyzer)
        "detected_proxy_hosts": [],
        "detected_auth_tokens": [],
        "detected_login_url": "",
        "detected_credentials": {},
        "warnings": [],
    }
