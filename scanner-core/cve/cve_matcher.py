"""
CVE Matcher
Matches detected services against CVE database
"""

from typing import Dict, List, Optional, Any
from .cve_client import CVEClient
from .version_detector import VersionDetector
import re

class CVEMatcher:
    """Matches services to CVEs"""
    
    def __init__(self, cve_provider: str = 'nvd'):
        """
        Initialize CVE matcher
        
        Args:
            cve_provider: 'nvd', 'vulners', or 'both'
        """
        self.cve_client = CVEClient(provider=cve_provider)
        self.version_detector = VersionDetector()
        
        # Known CVE mappings for common vulnerable versions
        # This is a small curated list for quick matching
        self.known_vulnerabilities = {
            'apache': {
                '2.4.49': ['CVE-2021-41773', 'CVE-2021-42013'],
                '2.4.50': ['CVE-2021-42013'],
                '2.4.48': ['CVE-2021-40438'],
            },
            'openssh': {
                '7.4': ['CVE-2018-15473'],
                '7.7': ['CVE-2019-6109', 'CVE-2019-6111'],
            },
            'nginx': {
                '1.18.0': ['CVE-2021-23017'],
            }
        }
    
    def match_service(self, service_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Match a service to CVEs
        
        Args:
            service_info: Dictionary with 'service', 'version', 'product', 'banner'
        
        Returns:
            List of CVE findings
        """
        findings = []
        
        product = service_info.get('product', '').lower()
        version = service_info.get('version')
        
        if not product or not version:
            return findings
        
        # First, check known vulnerabilities for quick matching
        known_cves = self._check_known_vulnerabilities(product, version)
        
        # Then, query API for additional CVEs
        api_cves = self._query_cve_api(product, version)
        
        # Combine and deduplicate
        all_cve_ids = list(set(known_cves + api_cves))
        
        # Fetch full details for each CVE
        for cve_id in all_cve_ids:
            cve_data = self.cve_client.get_cve(cve_id)
            if cve_data:
                finding = self._create_finding(service_info, cve_data)
                findings.append(finding)
        
        return findings
    
    def _check_known_vulnerabilities(self, product: str, version: str) -> List[str]:
        """Check against known vulnerability database"""
        cve_ids = []
        
        if product in self.known_vulnerabilities:
            product_vulns = self.known_vulnerabilities[product]
            
            # Exact version match
            if version in product_vulns:
                cve_ids.extend(product_vulns[version])
            
            # Check version ranges (simplified - exact match for now)
            # TODO: Implement proper version comparison
        
        return cve_ids
    
    def _query_cve_api(self, product: str, version: str) -> List[str]:
        """Query CVE API for software version"""
        try:
            # Use Vulners for software version search if available
            cve_ids = self.cve_client.search_by_software(product, version)
            return cve_ids
        except Exception as e:
            print(f"⚠️  Error querying CVE API: {e}")
            return []
    
    def _create_finding(self, service_info: Dict[str, Any], cve_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a finding from service and CVE data"""
        
        # Map CVE severity to our severity levels
        severity = cve_data.get('severity', 'medium')
        
        # Calculate confidence based on match type
        confidence = 90  # High confidence for version matches
        
        # Generate description
        description = f"{cve_data.get('description', 'No description available')}"
        
        # Generate remediation advice
        remediation = self._generate_remediation(service_info, cve_data)
        
        return {
            'name': f"{cve_data['cve_id']} - {service_info.get('product', 'Unknown').title()} Vulnerability",
            'cve_id': cve_data['cve_id'],
            'severity': severity,
            'confidence': confidence,
            'cvss_score': cve_data.get('cvss_score'),
            'cvss_vector': cve_data.get('cvss_vector'),
            'epss_score': cve_data.get('epss_score'),
            'epss_percentile': cve_data.get('epss_percentile'),
            'description': description,
            'service': service_info.get('service'),
            'port': service_info.get('port'),
            'version': service_info.get('version'),
            'product': service_info.get('product'),
            'evidence': {
                'banner': service_info.get('banner'),
                'detected_version': service_info.get('version'),
                'cve_source': cve_data.get('source', 'unknown')
            },
            'remediation': remediation,
            'references': cve_data.get('references', []),
            'cwe_ids': cve_data.get('cwe_ids', []),
            'published_date': cve_data.get('published_date'),
            'owasp_category': self._map_cwe_to_owasp(cve_data.get('cwe_ids', []))
        }
    
    def _generate_remediation(self, service_info: Dict[str, Any], cve_data: Dict[str, Any]) -> str:
        """Generate remediation advice"""
        product = service_info.get('product', 'the software')
        version = service_info.get('version', 'unknown')
        
        remediation = f"Update {product} from version {version} to the latest patched version. "
        remediation += f"Review the CVE details at https://nvd.nist.gov/vuln/detail/{cve_data['cve_id']} "
        remediation += "for specific patch information and affected version ranges."
        
        return remediation
    
    def _map_cwe_to_owasp(self, cwe_ids: List[str]) -> Optional[str]:
        """Map CWE IDs to OWASP Top 10 categories"""
        # Simplified mapping - expand as needed
        cwe_to_owasp = {
            'CWE-89': 'A03',   # SQL Injection
            'CWE-79': 'A03',   # XSS
            'CWE-78': 'A03',   # Command Injection
            'CWE-22': 'A01',   # Path Traversal
            'CWE-434': 'A04',  # File Upload
            'CWE-918': 'A10',  # SSRF
            'CWE-287': 'A07',  # Authentication
            'CWE-798': 'A07',  # Hard-coded Credentials
            'CWE-352': 'A01',  # CSRF
            'CWE-611': 'A05',  # XXE
        }
        
        for cwe_id in cwe_ids:
            if cwe_id in cwe_to_owasp:
                return cwe_to_owasp[cwe_id]
        
        return None
    
    def match_services_batch(self, services: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Match multiple services to CVEs
        
        Args:
            services: List of service dictionaries
        
        Returns:
            List of all CVE findings
        """
        all_findings = []
        
        for service in services:
            findings = self.match_service(service)
            all_findings.extend(findings)
        
        return all_findings


if __name__ == "__main__":
    # Test CVE matching
    matcher = CVEMatcher(cve_provider='nvd')
    
    # Test with known vulnerable Apache version
    service = {
        'service': 'HTTP',
        'port': 80,
        'product': 'apache',
        'version': '2.4.49',
        'banner': 'Apache/2.4.49 (Unix)'
    }
    
    print(f"Testing CVE matching for Apache 2.4.49...")
    findings = matcher.match_service(service)
    
    print(f"\nFound {len(findings)} CVEs:")
    for finding in findings:
        print(f"  - {finding['cve_id']}: {finding['severity'].upper()} (CVSS: {finding['cvss_score']})")
        print(f"    {finding['description'][:100]}...")
