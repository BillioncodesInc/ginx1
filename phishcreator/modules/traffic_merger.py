#!/usr/bin/env python3
"""phishcreator.modules.traffic_merger

Utilities to *merge* two traffic_data-like dicts.

Motivation:
- Live capture often misses some authenticated calls due to timing (user stops too early)
  or cross-window flows.
- An authenticated HAR export can provide the full post-login activity, including
  additional hosts, cookies, and auth URLs.

This module merges traffic from multiple sources into a single canonical structure
that the intelligent modules and DynamicPhishletGenerator understand.

Design goals:
- Best-effort and safe: never break existing consumers.
- Deterministic merges.
- Avoid storing full secrets: this module does not redact; callers should.
"""

from __future__ import annotations

from typing import Any, Dict, List


def _uniq_by(items: List[Dict[str, Any]], key: str) -> List[Dict[str, Any]]:
    seen = set()
    out: List[Dict[str, Any]] = []
    for it in items:
        val = it.get(key)
        if not val:
            continue
        if val in seen:
            continue
        seen.add(val)
        out.append(it)
    return out


def merge_traffic_data(primary: Dict[str, Any], secondary: Dict[str, Any]) -> Dict[str, Any]:
    """Merge 2 traffic_data dicts.

    `primary` wins when there are conflicts.

    Returns a new dict.
    """
    merged: Dict[str, Any] = {}

    # Simple scalar-ish fields
    merged["detected_login_url"] = primary.get("detected_login_url") or secondary.get("detected_login_url") or ""
    merged["detected_credentials"] = primary.get("detected_credentials") or secondary.get("detected_credentials") or {}

    # Unique hosts
    hosts = set(primary.get("unique_hosts") or []) | set(secondary.get("unique_hosts") or [])
    merged["unique_hosts"] = sorted([h for h in hosts if h])

    # Requests/responses
    merged["all_requests"] = _uniq_by((primary.get("all_requests") or []) + (secondary.get("all_requests") or []), "url")
    merged["all_responses"] = _uniq_by((primary.get("all_responses") or []) + (secondary.get("all_responses") or []), "url")

    # Form submissions: keep all, de-dupe by url+detected fields when possible
    def _fs_key(fs: Dict[str, Any]) -> str:
        return "|".join([
            str(fs.get("url", "")),
            str(fs.get("detected_username_field", "")),
            str(fs.get("detected_password_field", "")),
        ])

    fs_seen = set()
    merged_fs: List[Dict[str, Any]] = []
    for fs in (primary.get("form_submissions") or []) + (secondary.get("form_submissions") or []):
        k = _fs_key(fs)
        if not k.strip("|"):
            continue
        if k in fs_seen:
            continue
        fs_seen.add(k)
        merged_fs.append(fs)
    merged["form_submissions"] = merged_fs

    # Cookies captured: domain -> cookie_name -> cookie_obj
    cookies: Dict[str, Dict[str, Any]] = {}
    for src in (secondary.get("cookies_captured") or {}, primary.get("cookies_captured") or {}):
        # NOTE: apply secondary first, then primary overwrites
        if not isinstance(src, dict):
            continue
        for domain, cmap in src.items():
            if not isinstance(cmap, dict):
                continue
            cookies.setdefault(domain, {})
            cookies[domain].update(cmap)
    merged["cookies_captured"] = cookies

    # Storage state: merge dictionaries for localStorage/sessionStorage
    storage: Dict[str, Any] = {
        "localStorage": {},
        "sessionStorage": {},
        "captured_at": primary.get("storage_state", {}).get("captured_at") or secondary.get("storage_state", {}).get("captured_at"),
    }
    for container in ("localStorage", "sessionStorage"):
        s2 = (secondary.get("storage_state") or {}).get(container) or {}
        s1 = (primary.get("storage_state") or {}).get(container) or {}
        if isinstance(s2, dict):
            storage[container].update(s2)
        if isinstance(s1, dict):
            storage[container].update(s1)
    merged["storage_state"] = storage

    # Detected proxy hosts / auth tokens can be recomputed by analyzers.
    merged["detected_proxy_hosts"] = primary.get("detected_proxy_hosts") or secondary.get("detected_proxy_hosts") or []
    merged["detected_auth_tokens"] = primary.get("detected_auth_tokens") or secondary.get("detected_auth_tokens") or []

    merged["warnings"] = (primary.get("warnings") or []) + (secondary.get("warnings") or [])

    return merged
