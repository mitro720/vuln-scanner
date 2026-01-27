"""
Advanced API Endpoint Discovery Module
Discovers API endpoints using multiple techniques
"""

import requests
import re
from bs4 import BeautifulSoup
from typing import List, Set, Dict, Any
from urllib.parse import urljoin, urlparse
import json


class APIDiscovery:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.endpoints = set()
        self.parsed_base = urlparse(base_url)
        
        # Common API paths
        self.common_api_paths = [
            '/api', '/api/v1', '/api/v2', '/api/v3',
            '/rest', '/rest/v1', '/rest/v2',
            '/graphql', '/gql',
            '/api/users', '/api/auth', '/api/login',
            '/api/products', '/api/orders', '/api/customers',
            '/api/admin', '/api/config', '/api/settings',
            '/v1', '/v2', '/v3',
            '/api/docs', '/api/swagger', '/swagger',
            '/api-docs', '/docs', '/documentation',
            '/openapi.json', '/swagger.json', '/api.json',
            '/.well-known/openapi', '/.well-known/api',
            '/api/health', '/api/status', '/api/ping',
            '/api/search', '/api/query',
            '/webhooks', '/api/webhooks',
            '/oauth', '/oauth2', '/api/oauth',
            '/api/payments', '/api/transactions',
            '/api/notifications', '/api/messages',
            '/api/files', '/api/upload', '/api/download',
            '/api/reports', '/api/analytics',
            '/api/dashboard', '/api/metrics',
        ]
        
        # API documentation paths
        self.doc_paths = [
            '/swagger-ui.html', '/swagger-ui',
            '/api/swagger-ui.html', '/api/swagger-ui',
            '/docs', '/api/docs', '/api-docs',
            '/redoc', '/api/redoc',
            '/graphiql', '/graphql-playground',
            '/api/explorer', '/explorer',
            '/api.html', '/api/index.html',
        ]
        
    def probe_common_paths(self) -> Set[str]:
        """Probe common API paths"""
        found_endpoints = set()
        
        print("[*] Probing common API paths...")
        
        for path in self.common_api_paths:
            url = urljoin(self.base_url, path)
            
            try:
                response = requests.get(url, timeout=5, allow_redirects=False)
                
                # Check if endpoint exists
                if response.status_code in [200, 201, 301, 302, 401, 403]:
                    found_endpoints.add(url)
                    print(f"[+] Found API endpoint: {url} [{response.status_code}]")
                    
                    # Check for API documentation
                    if 'application/json' in response.headers.get('Content-Type', ''):
                        self.analyze_json_response(response.text, url)
                        
            except:
                pass
                
        return found_endpoints
        
    def find_api_docs(self) -> Dict[str, Any]:
        """Find API documentation endpoints"""
        docs_found = {}
        
        print("[*] Searching for API documentation...")
        
        for path in self.doc_paths:
            url = urljoin(self.base_url, path)
            
            try:
                response = requests.get(url, timeout=5)
                
                if response.status_code == 200:
                    docs_found[url] = {
                        'type': self.detect_doc_type(response.text, url),
                        'status': response.status_code
                    }
                    print(f"[+] Found API docs: {url}")
                    
                    # Parse Swagger/OpenAPI spec
                    if 'swagger' in url.lower() or 'openapi' in url.lower():
                        self.parse_swagger_spec(url)
                        
            except:
                pass
                
        return docs_found
        
    def detect_doc_type(self, content: str, url: str) -> str:
        """Detect type of API documentation"""
        content_lower = content.lower()
        
        if 'swagger' in content_lower or 'swagger-ui' in url.lower():
            return 'Swagger/OpenAPI'
        elif 'graphiql' in content_lower or 'graphql' in url.lower():
            return 'GraphQL'
        elif 'redoc' in content_lower:
            return 'ReDoc'
        elif 'postman' in content_lower:
            return 'Postman Collection'
        else:
            return 'Unknown'
            
    def parse_swagger_spec(self, spec_url: str):
        """Parse Swagger/OpenAPI specification"""
        try:
            response = requests.get(spec_url, timeout=10)
            
            if response.status_code == 200:
                try:
                    spec = response.json()
                    
                    # Extract paths from OpenAPI spec
                    if 'paths' in spec:
                        for path in spec['paths'].keys():
                            endpoint = urljoin(self.base_url, path)
                            self.endpoints.add(endpoint)
                            print(f"[+] Found endpoint in spec: {endpoint}")
                            
                except json.JSONDecodeError:
                    pass
                    
        except Exception as e:
            print(f"Error parsing Swagger spec: {str(e)}")
            
    def analyze_javascript(self, html: str, page_url: str) -> Set[str]:
        """Extract API endpoints from JavaScript code"""
        found_endpoints = set()
        
        # Regex patterns for API endpoints
        patterns = [
            r'["\']/(api|rest|v\d+)/[a-zA-Z0-9/_-]+["\']',
            r'fetch\(["\']([^"\']+)["\']',
            r'axios\.[a-z]+\(["\']([^"\']+)["\']',
            r'\$\.ajax\({[^}]*url:\s*["\']([^"\']+)["\']',
            r'XMLHttpRequest.*open\(["\'][A-Z]+["\']\s*,\s*["\']([^"\']+)["\']',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, html)
            for match in matches:
                # Handle tuple results from regex groups
                endpoint = match[0] if isinstance(match, tuple) else match
                
                # Clean and validate endpoint
                endpoint = endpoint.strip('\'"')
                if endpoint.startswith('/') or endpoint.startswith('http'):
                    full_url = urljoin(self.base_url, endpoint)
                    
                    # Only include if it's from the same domain
                    if urlparse(full_url).netloc == self.parsed_base.netloc:
                        found_endpoints.add(full_url)
                        
        return found_endpoints
        
    def analyze_json_response(self, json_text: str, source_url: str):
        """Analyze JSON response for additional endpoints"""
        try:
            data = json.loads(json_text)
            
            # Look for URL patterns in JSON
            def extract_urls(obj, depth=0):
                if depth > 5:  # Prevent infinite recursion
                    return
                    
                if isinstance(obj, dict):
                    for key, value in obj.items():
                        if isinstance(value, str) and ('url' in key.lower() or 'href' in key.lower() or 'link' in key.lower()):
                            if value.startswith('/') or value.startswith('http'):
                                full_url = urljoin(self.base_url, value)
                                if urlparse(full_url).netloc == self.parsed_base.netloc:
                                    self.endpoints.add(full_url)
                        else:
                            extract_urls(value, depth + 1)
                elif isinstance(obj, list):
                    for item in obj:
                        extract_urls(item, depth + 1)
                        
            extract_urls(data)
            
        except:
            pass
            
    def crawl_for_apis(self, start_url: str = None, max_depth: int = 2) -> Set[str]:
        """Crawl website to find API endpoints in JavaScript"""
        if not start_url:
            start_url = self.base_url
            
        found_endpoints = set()
        visited = set()
        to_visit = [(start_url, 0)]
        
        print("[*] Crawling for API endpoints in JavaScript...")
        
        while to_visit:
            url, depth = to_visit.pop(0)
            
            if url in visited or depth > max_depth:
                continue
                
            visited.add(url)
            
            try:
                response = requests.get(url, timeout=10)
                
                if response.status_code == 200 and 'text/html' in response.headers.get('Content-Type', ''):
                    # Extract API endpoints from JavaScript
                    js_endpoints = self.analyze_javascript(response.text, url)
                    found_endpoints.update(js_endpoints)
                    
                    # Find more pages to crawl
                    soup = BeautifulSoup(response.text, 'html.parser')
                    for link in soup.find_all('a', href=True):
                        next_url = urljoin(url, link['href'])
                        if urlparse(next_url).netloc == self.parsed_base.netloc:
                            to_visit.append((next_url, depth + 1))
                            
            except:
                pass
                
        return found_endpoints
        
    def discover(self, methods: List[str] = None) -> Dict[str, Any]:
        """
        Run API discovery using specified methods
        
        Args:
            methods: List of methods to use. Options:
                - 'common_paths'
                - 'documentation'
                - 'javascript'
                - 'all' (default)
        """
        if not methods or 'all' in methods:
            methods = ['common_paths', 'documentation', 'javascript']
            
        print(f"\n[*] Starting API discovery for {self.base_url}")
        print(f"[*] Using methods: {', '.join(methods)}\n")
        
        api_docs = {}
        
        # Run selected methods
        if 'common_paths' in methods:
            common_endpoints = self.probe_common_paths()
            self.endpoints.update(common_endpoints)
            
        if 'documentation' in methods:
            api_docs = self.find_api_docs()
            
        if 'javascript' in methods:
            js_endpoints = self.crawl_for_apis()
            self.endpoints.update(js_endpoints)
            
        # Categorize endpoints
        categorized = self.categorize_endpoints(list(self.endpoints))
        
        print(f"\n[+] Found {len(self.endpoints)} unique API endpoints")
        
        return {
            'base_url': self.base_url,
            'endpoints': sorted(list(self.endpoints)),
            'count': len(self.endpoints),
            'documentation': api_docs,
            'categorized': categorized,
            'methods_used': methods
        }
        
    def categorize_endpoints(self, endpoints: List[str]) -> Dict[str, List[str]]:
        """Categorize endpoints by type"""
        categories = {
            'auth': [],
            'users': [],
            'admin': [],
            'data': [],
            'files': [],
            'other': []
        }
        
        for endpoint in endpoints:
            endpoint_lower = endpoint.lower()
            
            if any(x in endpoint_lower for x in ['auth', 'login', 'oauth', 'token']):
                categories['auth'].append(endpoint)
            elif any(x in endpoint_lower for x in ['user', 'account', 'profile']):
                categories['users'].append(endpoint)
            elif any(x in endpoint_lower for x in ['admin', 'config', 'settings']):
                categories['admin'].append(endpoint)
            elif any(x in endpoint_lower for x in ['file', 'upload', 'download', 'media']):
                categories['files'].append(endpoint)
            elif any(x in endpoint_lower for x in ['product', 'order', 'customer', 'data']):
                categories['data'].append(endpoint)
            else:
                categories['other'].append(endpoint)
                
        return {k: v for k, v in categories.items() if v}  # Remove empty categories
