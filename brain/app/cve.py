"""Heuristic CVE correlation.

The engine discloses software versions in its findings (Server headers, SSH
banners, JS library filenames, …). This module extracts those product/version
pairs and matches them against a curated set of well-known vulnerabilities,
flagging any detected version below the fixed release.

It is deliberately conservative (equal versions are treated as safe) and
explicitly heuristic — a match is a strong signal to verify, not a proof of
exploitability. The database lives in one place (`VULN_DB`) so it's easy to
extend or later swap for a live feed (NVD/OSV).
"""

from __future__ import annotations

import re

from .models import CVEMatch, Finding

# Curated known-vulnerable ranges for commonly-fingerprinted software.
VULN_DB: list[dict] = [
    {"product": "nginx", "fixed_in": "1.20.1", "severity": "high",
     "cves": ["CVE-2021-23017"], "summary": "Off-by-one in the DNS resolver (1-byte memory overwrite)."},
    {"product": "apache", "fixed_in": "2.4.51", "severity": "critical",
     "cves": ["CVE-2021-42013"], "summary": "Path traversal to RCE in mod_cgi (2.4.49/2.4.50)."},
    {"product": "openssh", "fixed_in": "9.3", "severity": "critical",
     "cves": ["CVE-2023-38408"], "summary": "RCE via forwarded ssh-agent PKCS#11 provider."},
    {"product": "openssh", "fixed_in": "8.5", "severity": "medium",
     "cves": ["CVE-2021-28041"], "summary": "Double-free in ssh-agent."},
    {"product": "php", "fixed_in": "8.1.0", "severity": "high",
     "cves": ["EOL"], "summary": "PHP 7.x is end-of-life and unpatched; upgrade to a supported 8.x branch."},
    {"product": "openssl", "fixed_in": "1.1.1t", "severity": "high",
     "cves": ["CVE-2023-0286"], "summary": "X.400 address type confusion in GENERAL_NAME_cmp."},
    {"product": "jquery", "fixed_in": "3.5.0", "severity": "medium",
     "cves": ["CVE-2020-11022", "CVE-2020-11023"], "summary": "XSS via jQuery.htmlPrefilter with untrusted HTML."},
    {"product": "bootstrap", "fixed_in": "4.3.1", "severity": "medium",
     "cves": ["CVE-2019-8331"], "summary": "XSS in tooltip/popover data-template."},
    {"product": "wordpress", "fixed_in": "6.0.3", "severity": "medium",
     "cves": ["multiple"], "summary": "Multiple XSS/SQLi fixes; keep core auto-updated."},
]

# product -> regex capturing a version from evidence/detail text.
PRODUCT_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("nginx", re.compile(r"nginx/(\d+\.\d+(?:\.\d+)?)", re.I)),
    ("apache", re.compile(r"apache(?:/| )(\d+\.\d+(?:\.\d+)?)", re.I)),
    ("php", re.compile(r"php/(\d+\.\d+(?:\.\d+)?)", re.I)),
    ("openssh", re.compile(r"openssh[_/](\d+\.\d+(?:p\d+)?(?:\.\d+)?)", re.I)),
    ("openssl", re.compile(r"openssl/(\d+\.\d+\.\d+[a-z]?)", re.I)),
    ("jquery", re.compile(r"jquery[-/ v]{0,3}(\d+\.\d+\.\d+)", re.I)),
    ("bootstrap", re.compile(r"bootstrap[-/ v]{0,3}(\d+\.\d+\.\d+)", re.I)),
    ("wordpress", re.compile(r"wordpress[ /]?(\d+\.\d+(?:\.\d+)?)", re.I)),
]


def _version_tuple(v: str) -> tuple[int, ...]:
    return tuple(int(n) for n in re.findall(r"\d+", v)[:4])


def _is_older(detected: str, fixed: str) -> bool:
    """True if detected < fixed (numeric components only; conservative)."""
    return _version_tuple(detected) < _version_tuple(fixed)


def _detect(findings: list[Finding]) -> dict[str, str]:
    """Return {product: version} extracted from finding text (first hit wins)."""
    found: dict[str, str] = {}
    for f in findings:
        haystack = " ".join(filter(None, [f.evidence, f.detail, f.title]))
        for product, pattern in PRODUCT_PATTERNS:
            if product in found:
                continue
            m = pattern.search(haystack)
            if m:
                found[product] = m.group(1)
    return found


def correlate(findings: list[Finding]) -> list[CVEMatch]:
    """Match detected software versions against the vulnerability database."""
    detected = _detect(findings)
    matches: list[CVEMatch] = []
    for entry in VULN_DB:
        product = entry["product"]
        version = detected.get(product)
        if version and _is_older(version, entry["fixed_in"]):
            matches.append(
                CVEMatch(
                    product=product,
                    version=version,
                    fixed_in=entry["fixed_in"],
                    severity=entry["severity"],
                    cves=entry["cves"],
                    summary=entry["summary"],
                )
            )
    # Worst first.
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    matches.sort(key=lambda m: order.get(m.severity, 4))
    return matches
