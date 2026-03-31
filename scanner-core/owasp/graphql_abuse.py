"""
GraphQL Abuse Detection
OWASP A05:2021 - Security Misconfiguration
"""

import requests
import json
from typing import List, Dict, Any
from urllib.parse import urlparse


GRAPHQL_PATHS = [
    '/graphql',
    '/api/graphql',
    '/graphql/v1',
    '/v1/graphql',
    '/query',
    '/gql',
]

INTROSPECTION_QUERY = '{"query":"{__schema{types{name}}}"}'
BATCH_QUERY = '[{"query":"{__typename}"},{"query":"{__typename}"}]'


class GraphQLAbuseModule:
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

    def _get_base(self) -> str:
        parsed = urlparse(self.target_url)
        return f"{parsed.scheme}://{parsed.netloc}"

    def test_introspection(self) -> List[Dict[str, Any]]:
        """Check if GraphQL introspection is enabled (schema leak)"""
        findings = []
        base = self._get_base()

        for path in GRAPHQL_PATHS:
            endpoint = base + path
            try:
                resp = self.http.post(endpoint, data=INTROSPECTION_QUERY, timeout=8)
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        if '__schema' in str(data) or 'types' in str(data):
                            findings.append({
                                "name": "GraphQL Introspection Enabled",
                                "severity": "medium",
                                "owasp_category": "A05:2021",
                                "url": endpoint,
                                "confidence": 95,
                                "technique": "GraphQL Introspection Query",
                                "evidence": {
                                    "endpoint": endpoint,
                                    "schema_exposed": True,
                                    "response_snippet": str(data)[:400]
                                },
                                "poc": f"curl -X POST '{endpoint}' -H 'Content-Type: application/json' -d '{INTROSPECTION_QUERY}'",
                                "remediation": "Disable GraphQL introspection in production. Use schema allowlisting and depth limiting."
                            })
                    except Exception:
                        pass
            except Exception:
                continue

        return findings

    def test_batching(self) -> List[Dict[str, Any]]:
        """Check if GraphQL query batching is enabled (can be used to bypass rate limits)"""
        findings = []
        base = self._get_base()

        for path in GRAPHQL_PATHS:
            endpoint = base + path
            try:
                resp = self.http.post(endpoint, data=BATCH_QUERY, timeout=8)
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        if isinstance(data, list) and len(data) > 1:
                            findings.append({
                                "name": "GraphQL Query Batching Enabled",
                                "severity": "low",
                                "owasp_category": "A05:2021",
                                "url": endpoint,
                                "confidence": 85,
                                "technique": "GraphQL Batch Request",
                                "evidence": {
                                    "endpoint": endpoint,
                                    "batch_response_count": len(data)
                                },
                                "poc": f"curl -X POST '{endpoint}' -H 'Content-Type: application/json' -d '{BATCH_QUERY}'",
                                "remediation": "Disable query batching or enforce strict rate limits per batch request."
                            })
                    except Exception:
                        pass
            except Exception:
                continue

        return findings

    def scan(self, urls: List[str]) -> List[Dict[str, Any]]:
        findings = []
        findings.extend(self.test_introspection())
        findings.extend(self.test_batching())
        return findings
