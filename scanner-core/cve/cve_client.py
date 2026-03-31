"""
CVE API Client Module
Provides integration with CVE databases (NVD and Vulners)
"""

import os
import time
import requests
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import json

class RateLimiter:
    """Simple rate limiter for API calls"""
    def __init__(self, max_calls: int, time_window: int):
        self.max_calls = max_calls
        self.time_window = time_window  # in seconds
        self.calls = []
    
    def wait_if_needed(self):
        """Wait if rate limit would be exceeded"""
        now = time.time()
        # Remove old calls outside the time window
        self.calls = [call_time for call_time in self.calls if now - call_time < self.time_window]
        
        if len(self.calls) >= self.max_calls:
            # Wait until the oldest call expires
            sleep_time = self.time_window - (now - self.calls[0]) + 0.1
            if sleep_time > 0:
                print(f"⏳ Rate limit reached, waiting {sleep_time:.1f}s...")
                time.sleep(sleep_time)
                self.calls = []
        
        self.calls.append(now)


class NVDClient:
    """Client for NIST NVD API v2.0"""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv('NVD_API_KEY')
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        
        # Rate limits: 5 req/30s without key, 50 req/30s with key
        max_calls = 50 if self.api_key else 5
        self.rate_limiter = RateLimiter(max_calls=max_calls, time_window=30)
        
        self.session = requests.Session()
        if self.api_key:
            self.session.headers.update({'apiKey': self.api_key})
    
    def get_cve_by_id(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        Fetch CVE details by CVE ID
        
        Args:
            cve_id: CVE identifier (e.g., "CVE-2021-44228")
        
        Returns:
            Dictionary with CVE details or None if not found
        """
        self.rate_limiter.wait_if_needed()
        
        try:
            params = {'cveId': cve_id}
            response = self.session.get(self.base_url, params=params, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            
            if data.get('totalResults', 0) == 0:
                return None
            
            cve_item = data['vulnerabilities'][0]['cve']
            
            # Extract CVSS score (prefer v3.1, fallback to v3.0, then v2.0)
            cvss_score = None
            cvss_vector = None
            severity = None
            
            metrics = cve_item.get('metrics', {})
            
            if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                cvss_data = metrics['cvssMetricV31'][0]['cvssData']
                cvss_score = cvss_data.get('baseScore')
                cvss_vector = cvss_data.get('vectorString')
                severity = cvss_data.get('baseSeverity', '').lower()
            elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
                cvss_data = metrics['cvssMetricV30'][0]['cvssData']
                cvss_score = cvss_data.get('baseScore')
                cvss_vector = cvss_data.get('vectorString')
                severity = cvss_data.get('baseSeverity', '').lower()
            elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                cvss_data = metrics['cvssMetricV2'][0]['cvssData']
                cvss_score = cvss_data.get('baseScore')
                cvss_vector = cvss_data.get('vectorString')
                # Map v2 score to severity
                if cvss_score >= 7.0:
                    severity = 'high'
                elif cvss_score >= 4.0:
                    severity = 'medium'
                else:
                    severity = 'low'
            
            # Extract description
            descriptions = cve_item.get('descriptions', [])
            description = next((d['value'] for d in descriptions if d['lang'] == 'en'), '')
            
            # Extract references
            references = []
            for ref in cve_item.get('references', []):
                references.append({
                    'url': ref.get('url'),
                    'source': ref.get('source'),
                    'tags': ref.get('tags', [])
                })
            
            # Extract CWE IDs
            cwe_ids = []
            weaknesses = cve_item.get('weaknesses', [])
            for weakness in weaknesses:
                for desc in weakness.get('description', []):
                    if desc.get('lang') == 'en':
                        cwe_ids.append(desc.get('value'))
            
            return {
                'cve_id': cve_id,
                'description': description,
                'cvss_score': cvss_score,
                'cvss_vector': cvss_vector,
                'severity': severity,
                'published_date': cve_item.get('published'),
                'last_modified_date': cve_item.get('lastModified'),
                'references': references,
                'cwe_ids': cwe_ids,
                'source': 'nvd'
            }
            
        except requests.exceptions.RequestException as e:
            print(f"❌ NVD API error for {cve_id}: {e}")
            return None
        except (KeyError, IndexError, json.JSONDecodeError) as e:
            print(f"❌ Error parsing NVD response for {cve_id}: {e}")
            return None
    
    def search_by_keyword(self, keyword: str, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Search CVEs by keyword
        
        Args:
            keyword: Search term
            limit: Maximum number of results
        
        Returns:
            List of CVE dictionaries
        """
        self.rate_limiter.wait_if_needed()
        
        try:
            params = {
                'keywordSearch': keyword,
                'resultsPerPage': min(limit, 100)
            }
            response = self.session.get(self.base_url, params=params, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            results = []
            
            for vuln in data.get('vulnerabilities', []):
                cve_item = vuln['cve']
                cve_id = cve_item['id']
                
                # Get basic info (full details can be fetched separately if needed)
                descriptions = cve_item.get('descriptions', [])
                description = next((d['value'] for d in descriptions if d['lang'] == 'en'), '')
                
                results.append({
                    'cve_id': cve_id,
                    'description': description[:200] + '...' if len(description) > 200 else description
                })
            
            return results
            
        except requests.exceptions.RequestException as e:
            print(f"❌ NVD API search error: {e}")
            return []


class VulnersClient:
    """Client for Vulners API"""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv('VULNERS_API_KEY')
        self.base_url = "https://vulners.com/api/v3"
        self.session = requests.Session()
        
        # Vulners doesn't have strict rate limits but we'll be conservative
        self.rate_limiter = RateLimiter(max_calls=10, time_window=60)
    
    def get_cve_by_id(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        Fetch CVE details by CVE ID (free, doesn't consume credits)
        
        Args:
            cve_id: CVE identifier (e.g., "CVE-2021-44228")
        
        Returns:
            Dictionary with CVE details or None if not found
        """
        self.rate_limiter.wait_if_needed()
        
        try:
            url = f"{self.base_url}/search/id/"
            params = {
                'id': cve_id,
                'apiKey': self.api_key
            }
            
            response = self.session.get(url, params=params, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            
            if data.get('result') != 'OK':
                return None
            
            doc = data['data']['documents'].get(cve_id)
            if not doc:
                return None
            
            return {
                'cve_id': cve_id,
                'description': doc.get('description', ''),
                'cvss_score': doc.get('cvss', {}).get('score'),
                'cvss_vector': doc.get('cvss', {}).get('vector'),
                'severity': self._map_cvss_to_severity(doc.get('cvss', {}).get('score')),
                'published_date': doc.get('published'),
                'last_modified_date': doc.get('modified'),
                'references': doc.get('references', []),
                'cwe_ids': doc.get('cwe', []),
                'source': 'vulners'
            }
            
        except requests.exceptions.RequestException as e:
            print(f"❌ Vulners API error for {cve_id}: {e}")
            return None
        except (KeyError, json.JSONDecodeError) as e:
            print(f"❌ Error parsing Vulners response for {cve_id}: {e}")
            return None
    
    def search_by_software(self, software: str, version: str) -> List[str]:
        """
        Search for CVEs affecting a specific software version (costs 3 credits)
        
        Args:
            software: Software name (e.g., "apache")
            version: Version string (e.g., "2.4.49")
        
        Returns:
            List of CVE IDs
        """
        if not self.api_key:
            print("⚠️  Vulners API key required for software version search")
            return []
        
        self.rate_limiter.wait_if_needed()
        
        try:
            url = f"{self.base_url}/burp/software/"
            data = {
                'software': software,
                'version': version,
                'type': 'software',
                'apiKey': self.api_key
            }
            
            response = self.session.post(url, json=data, timeout=10)
            response.raise_for_status()
            
            result = response.json()
            
            if result.get('result') != 'OK':
                return []
            
            # Extract CVE IDs from vulnerabilities
            cve_ids = []
            for vuln in result.get('data', {}).get('search', []):
                cve_list = vuln.get('cvelist', [])
                cve_ids.extend(cve_list)
            
            return list(set(cve_ids))  # Remove duplicates
            
        except requests.exceptions.RequestException as e:
            print(f"❌ Vulners software search error: {e}")
            return []
    
    def _map_cvss_to_severity(self, score: Optional[float]) -> str:
        """Map CVSS score to severity level"""
        if score is None:
            return 'unknown'
        if score >= 9.0:
            return 'critical'
        elif score >= 7.0:
            return 'high'
        elif score >= 4.0:
            return 'medium'
        else:
            return 'low'


class CVEClient:
    """
    Unified CVE client that can use multiple providers
    """
    
    def __init__(self, provider: str = 'nvd'):
        """
        Initialize CVE client
        
        Args:
            provider: 'nvd', 'vulners', or 'both'
        """
        self.provider = provider.lower()
        self.cache = {}  # Simple in-memory cache
        self.cache_ttl = int(os.getenv('CVE_CACHE_TTL', '86400'))  # 24 hours default
        
        if self.provider in ['nvd', 'both']:
            self.nvd = NVDClient()
        
        if self.provider in ['vulners', 'both']:
            self.vulners = VulnersClient()
    
    def get_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        Get CVE details with caching
        
        Args:
            cve_id: CVE identifier
        
        Returns:
            CVE details dictionary or None
        """
        # Check cache
        if cve_id in self.cache:
            cached_data, timestamp = self.cache[cve_id]
            if time.time() - timestamp < self.cache_ttl:
                return cached_data
        
        # Fetch from API
        cve_data = None
        
        if self.provider == 'nvd':
            cve_data = self.nvd.get_cve_by_id(cve_id)
        elif self.provider == 'vulners':
            cve_data = self.vulners.get_cve_by_id(cve_id)
        elif self.provider == 'both':
            # Try NVD first, fallback to Vulners
            cve_data = self.nvd.get_cve_by_id(cve_id)
            if not cve_data:
                cve_data = self.vulners.get_cve_by_id(cve_id)
        
        # Cache result
        if cve_data:
            # Fetch EPSS score
            epss_data = self.get_epss(cve_id)
            if epss_data:
                cve_data['epss_score'] = epss_data.get('epss')
                cve_data['epss_percentile'] = epss_data.get('percentile')
                
            self.cache[cve_id] = (cve_data, time.time())
        
        return cve_data
    
    def get_epss(self, cve_id: str) -> Optional[Dict[str, str]]:
        """Fetch EPSS score from FIRST.org API"""
        try:
            url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get('data') and len(data['data']) > 0:
                    item = data['data'][0]
                    return {
                        'epss': float(item.get('epss', 0)),
                        'percentile': float(item.get('percentile', 0))
                    }
        except Exception as e:
            print(f"⚠️  Error fetching EPSS for {cve_id}: {e}")
        return None
    
    def search_by_software(self, software: str, version: str) -> List[str]:
        """
        Search for CVEs by software version (Vulners only)
        
        Args:
            software: Software name
            version: Version string
        
        Returns:
            List of CVE IDs
        """
        if self.provider in ['vulners', 'both']:
            return self.vulners.search_by_software(software, version)
        else:
            print("⚠️  Software version search requires Vulners API")
            return []
