"""
Insecure Direct Object Reference (IDOR) Detection
OWASP A01:2021 - Broken Access Control
"""

import requests
import re
from typing import List, Dict, Any
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


class IDORModule:
    def __init__(self, target_url: str, http_client: Any = None):
        self.target_url = target_url
        
        # Inject custom HttpClient if provided
        if http_client:
            self.http = http_client
        else:
            self.http = requests.Session()
            self.http.headers.update({'User-Agent': 'SecureScan/1.0'})

    def _fuzz_id(self, original_id: str) -> List[str]:
        """Generate adjacent IDs for IDOR testing"""
        candidates = []
        try:
            n = int(original_id)
            candidates += [str(n + 1), str(n - 1), str(n + 100), '0', '1', '2']
        except ValueError:
            pass
        # Common IDOR bypass values
        candidates += ['../1', '%2e%2e/1', '0', 'null', 'undefined']
        return candidates

    def test_url_param_idor(self, url: str) -> List[Dict[str, Any]]:
        """Check URL query params for IDOR (id, user_id, account, etc.)"""
        findings = []
        id_pattern = re.compile(r'^(id|user_?id|account_?id|order_?id|doc_?id|file_?id|record_?id|uid|pid|rid)$', re.I)

        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        id_params = {k: v for k, v in params.items() if id_pattern.match(k)}

        if not id_params:
            return findings

        try:
            baseline = self.http.get(url, timeout=8, allow_redirects=True)
            baseline_status = baseline.status_code
            baseline_len = len(baseline.text)
        except Exception:
            return findings

        for param, values in id_params.items():
            original = values[0]
            for fuzz_id in self._fuzz_id(original):
                test_params = {**{k: v[0] for k, v in params.items()}, param: fuzz_id}
                test_url = urlunparse(parsed._replace(query=urlencode(test_params)))
                try:
                    resp = self.http.get(test_url, timeout=8, allow_redirects=True)
                    # IDOR signal: same 200 status but different content from baseline
                    if resp.status_code == 200 and baseline_status == 200:
                        diff = abs(len(resp.text) - baseline_len)
                        if diff > 200 and '<error' not in resp.text.lower() and 'not found' not in resp.text.lower():
                            findings.append({
                                "name": "Potential IDOR (Insecure Direct Object Reference)",
                                "severity": "high",
                                "owasp_category": "A01:2021",
                                "url": test_url,
                                "parameter": param,
                                "confidence": 70,
                                "technique": "Parameter ID Fuzzing",
                                "evidence": {
                                    "original_id": original,
                                    "fuzzed_id": fuzz_id,
                                    "original_response_len": baseline_len,
                                    "fuzzed_response_len": len(resp.text),
                                    "difference": diff
                                },
                                "poc": f"curl '{test_url}'",
                                "remediation": "Implement server-side authorization checks for every object access. Use indirect object references (e.g., hashed IDs) and enforce ownership validation."
                            })
                            break
                except Exception:
                    continue

        return findings

    def test_path_idor(self, url: str) -> List[Dict[str, Any]]:
        """Check path segments for numeric IDs (e.g., /users/1234)"""
        findings = []
        parsed = urlparse(url)
        path_parts = parsed.path.split('/')
        numeric_indices = [i for i, p in enumerate(path_parts) if p.isdigit()]

        if not numeric_indices:
            return findings

        try:
            baseline = self.http.get(url, timeout=8)
            baseline_status = baseline.status_code
            baseline_len = len(baseline.text)
        except Exception:
            return findings

        for idx in numeric_indices:
            original_id = path_parts[idx]
            for fuzz_id in self._fuzz_id(original_id)[:4]:
                new_parts = list(path_parts)
                new_parts[idx] = fuzz_id
                new_path = '/'.join(new_parts)
                test_url = urlunparse(parsed._replace(path=new_path))
                try:
                    resp = self.http.get(test_url, timeout=8)
                    if resp.status_code == 200 and baseline_status == 200:
                        diff = abs(len(resp.text) - baseline_len)
                        if diff > 150:
                            findings.append({
                                "name": "Potential IDOR via Path Parameter",
                                "severity": "high",
                                "owasp_category": "A01:2021",
                                "url": test_url,
                                "confidence": 65,
                                "technique": "Path Segment Fuzzing",
                                "evidence": {
                                    "original_path": parsed.path,
                                    "fuzzed_path": new_path,
                                    "original_id": original_id,
                                    "fuzzed_id": fuzz_id,
                                    "content_diff": diff
                                },
                                "poc": f"curl '{test_url}'",
                                "remediation": "Enforce resource ownership checks on every request. Never rely solely on the ID in the URL."
                            })
                            break
                except Exception:
                    continue

        return findings

    def scan(self, urls: List[str]) -> List[Dict[str, Any]]:
        all_findings = []
        for url in urls:
            all_findings.extend(self.test_url_param_idor(url))
            all_findings.extend(self.test_path_idor(url))
        return all_findings
