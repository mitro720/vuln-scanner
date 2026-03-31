"""
Mass Assignment Detection
OWASP A01:2021 - Broken Access Control
"""

import requests
import json
from typing import List, Dict, Any
from urllib.parse import urlparse


# Admin-level fields that should never be user-settable
PRIVILEGED_FIELDS = [
    'role', 'admin', 'is_admin', 'is_superuser', 'is_staff',
    'permissions', 'user_role', 'account_type', 'plan',
    'verified', 'active', 'status', 'credit', 'balance',
    'price', 'discount', 'discount_rate', 'access_level',
]


class MassAssignmentModule:
    def __init__(self, target_url: str, http_client: Any = None):
        self.target_url = target_url
        
        # Inject custom HttpClient if provided
        if http_client:
            self.http = http_client
        else:
            self.http = requests.Session()
            self.http.headers.update({
                'User-Agent': 'SecureScan/1.0',
                'Content-Type': 'application/json'
            })

    def _get_api_endpoints(self, urls: List[str]) -> List[str]:
        """Filter to likely API endpoints"""
        return [u for u in urls if any(k in u for k in ['/api/', '/v1/', '/v2/', '/rest/', '/user', '/profile', '/account', '/register', '/update'])]

    def test_endpoint(self, url: str) -> List[Dict[str, Any]]:
        """Attempt to send privileged fields to API endpoint"""
        findings = []
        payload = {field: 'true' for field in PRIVILEGED_FIELDS[:5]}
        payload['role'] = 'admin'
        payload['is_admin'] = True

        for method in ('POST', 'PUT', 'PATCH'):
            try:
                resp = self.http.request(
                    method, url,
                    data=json.dumps(payload),
                    timeout=8
                )
                # If server returns 200 and echoes any privileged field back in response
                try:
                    resp_data = resp.json()
                    reflected = [f for f in PRIVILEGED_FIELDS if f in str(resp_data)]
                    if resp.status_code in (200, 201) and reflected:
                        findings.append({
                            "name": "Potential Mass Assignment Vulnerability",
                            "severity": "high",
                            "owasp_category": "A01:2021",
                            "url": url,
                            "confidence": 72,
                            "technique": f"JSON {method} with Privileged Fields",
                            "evidence": {
                                "method": method,
                                "privileged_fields_sent": list(payload.keys()),
                                "fields_reflected_in_response": reflected,
                                "status_code": resp.status_code
                            },
                            "poc": f"curl -X {method} '{url}' -H 'Content-Type: application/json' -d '{json.dumps(payload)}'",
                            "remediation": "Use an explicit allowlist of fields that can be set by users. Never bind request body directly to model objects."
                        })
                        break
                except Exception:
                    pass
            except Exception:
                continue

        return findings

    def scan(self, urls: List[str]) -> List[Dict[str, Any]]:
        all_findings = []
        api_endpoints = self._get_api_endpoints(urls)
        for url in api_endpoints:
            all_findings.extend(self.test_endpoint(url))
        return all_findings
