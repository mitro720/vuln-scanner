"""
Subdomain Takeover Detection
OWASP A05:2021 - Security Misconfiguration
"""

import requests
import dns.resolver
from typing import List, Dict, Any


# Fingerprints from EdOverflow's bug bounty list
TAKEOVER_FINGERPRINTS = {
    'github.io': 'There isn\'t a GitHub Pages site here.',
    'herokuapp.com': 'No such app',
    's3.amazonaws.com': 'NoSuchBucket',
    'amazonaws.com': 'NoSuchBucket',
    'windows.net': 'The specified bucket does not exist',
    'surge.sh': 'project not found',
    'strikingly.com': 'page not found',
    'bitbucket.io': 'Repository not found',
    'zendesk.com': 'Help Center Closed',
    'ghost.io': 'The thing you were looking for is no longer here',
    'wpengine.com': 'The site you were looking for couldn\'t be found',
    'pantheon.io': '404 error unknown site!',
    'fastly.net': 'Fastly error: unknown domain',
    'myshopify.com': 'Sorry, this shop is currently unavailable.',
    'readme.io': 'Project dont exist',
    'statuspage.io': 'You are being redirected...',
    'tumblr.com': 'Whatever you were looking for doesn\'t currently exist at this address',
    'wordpress.com': 'Do you want to register',
    'intercom.help': 'Uh oh. That page doesn\'t exist.',
}


class SubdomainTakeoverModule:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'SecureScan/1.0'})

    def _resolve_cname(self, domain: str) -> List[str]:
        try:
            answers = dns.resolver.resolve(domain, 'CNAME')
            return [str(r.target).rstrip('.') for r in answers]
        except Exception:
            return []

    def scan(self, urls: List[str]) -> List[Dict[str, Any]]:
        """Scan unique subdomains for takeover fingerprints"""
        findings = []
        
        # Extract unique HTTP(s) origins
        from urllib.parse import urlparse
        domains = set()
        for u in urls:
            try:
                domains.add(urlparse(u).netloc.split(':')[0])
            except:
                pass

        for domain in domains:
            try:
                # 1. Check if it returns a known 404/error signature
                try:
                    resp = self.session.get(f"http://{domain}", timeout=5)
                    resp_text = resp.text
                except requests.exceptions.RequestException:
                    continue

                cnames = self._resolve_cname(domain)

                # 2. Match potential takeover candidates
                for provider_domain, fingerprint in TAKEOVER_FINGERPRINTS.items():
                    # If the CNAME points to a known provider OR the content matches the fingerprint
                    points_to_provider = any(provider_domain in c for c in cnames)
                    content_matches = fingerprint in resp_text

                    if content_matches and (points_to_provider or not cnames):
                        findings.append({
                            "name": "Subdomain Takeover",
                            "severity": "critical",
                            "owasp_category": "A05:2021",
                            "url": f"http://{domain}",
                            "confidence": 95 if points_to_provider else 75,
                            "technique": "CNAME Fingerprinting",
                            "evidence": {
                                "domain": domain,
                                "cnames": cnames,
                                "provider": provider_domain,
                                "fingerprint_matched": fingerprint
                            },
                            "poc": f"dig CNAME {domain} +short && curl -s http://{domain} | grep -i '{fingerprint}'",
                            "remediation": f"Remove the DNS record pointing to {provider_domain} or claim the resource at the provider."
                        })
                        break
            except Exception:
                continue

        return findings
