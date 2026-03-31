"""
SecureScan - Heuristic Blind Parameter Discovery
Detects hidden parameters (e.g., debug, admin, test) using response divergence analysis.
"""

import logging
import random
import string
import json
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, urlencode, parse_qs

# High-value hidden parameters for fuzzing
COMMON_PARAMS = [
    "debug", "admin", "test", "dev", "load", "file", "page", "id", "user", "config", "log", "cmd",
    "exec", "shell", "root", "secret", "token", "key", "access", "auth", "profile", "settings",
    "internal", "private", "hidden", "beta", "version", "source", "view", "show", "edit", "delete",
    "update", "create", "api_key", "password", "email", "username", "account", "sysadmin", "system",
    "maintenance", "backup", "db", "database", "query", "sql", "params", "options", "action", "mode",
    "type", "format", "callback", "redirect", "url", "path", "dest", "target", "env", "var", "debug_mode"
]

class ParamDiscovery:
    def __init__(self, target_url: str, http_client=None, config: Dict[str, Any] = None):
        self.target_url = target_url
        self.http = http_client
        self.config = config or {}
        self.discovered_params = {} # url -> list of discovered params
        
    def _generate_random_string(self, length=8):
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

    def _get_baseline(self, url: str) -> Dict[str, Any]:
        """Establish a baseline for a given URL with a dummy parameter"""
        dummy_key = f"ss_dummy_{self._generate_random_string(4)}"
        dummy_val = self._generate_random_string(8)
        
        # We add a dummy param to ensure we're comparing against a parameterized version
        separator = "&" if "?" in url else "?"
        baseline_url = f"{url}{separator}{dummy_key}={dummy_val}"
        
        response = self.http.get(baseline_url)
        if not response:
            return None
            
        return {
            "status_code": response.status_code,
            "length": len(response.content),
            "headers_count": len(response.headers),
            "words_count": len(response.text.split()),
            "lines_count": len(response.text.splitlines()),
            "content": response.text
        }

    def _is_different(self, current: Dict[str, Any], baseline: Dict[str, Any]) -> bool:
        """Heuristic check to see if the response significantly diverged from baseline"""
        if not current or not baseline:
            return False
            
        # 1. Status code change is a major indicator
        if current["status_code"] != baseline["status_code"]:
            return True
            
        # 2. Response length change (more than 1% or 5 bytes)
        length_diff = abs(current["length"] - baseline["length"])
        if length_diff > 5 and (length_diff / (baseline["length"] or 1)) > 0.01:
            return True
            
        # 3. Headers count change
        if current["headers_count"] != baseline["headers_count"]:
            return True
            
        # 4. Content structure change (words/lines)
        if abs(current["words_count"] - baseline["words_count"]) > 2:
            return True
            
        return False

    def discover(self, urls: List[str]) -> Dict[str, List[str]]:
        """Run heuristic discovery on a list of URLs"""
        results = {}
        
        for url in urls[:15]: # Limit to top 15 pages for performance
            try:
                found = self.discover_on_url(url)
                if found:
                    results[url] = found
            except Exception as e:
                logging.error(f"Error in ParamDiscovery for {url}: {str(e)}")
                
        self.discovered_params = results
        return results

    def discover_on_url(self, url: str) -> List[str]:
        """Perform heuristic detection on a single URL"""
        baseline = self._get_baseline(url)
        if not baseline:
            return []
            
        discovered = []
        
        # Step 1: Bulk Probe (Send params in batches of 20 to find divergence)
        batch_size = 20
        batches = [COMMON_PARAMS[i:i + batch_size] for i in range(0, len(COMMON_PARAMS), batch_size)]
        
        for batch in batches:
            query_params = {p: self._generate_random_string(4) for p in batch}
            separator = "&" if "?" in url else "?"
            probe_url = f"{url}{separator}{urlencode(query_params)}"
            
            response = self.http.get(probe_url)
            if not response:
                continue
                
            current = {
                "status_code": response.status_code,
                "length": len(response.content),
                "headers_count": len(response.headers),
                "words_count": len(response.text.split()),
                "lines_count": len(response.text.splitlines())
            }
            
            # If the batch caused a change, find the specific parameter(s)
            if self._is_different(current, baseline):
                active_params = self._narrow_down(url, batch, baseline)
                discovered.extend(active_params)
                
        return list(set(discovered))

    def _narrow_down(self, url: str, params: List[str], baseline: Dict[str, Any]) -> List[str]:
        """Binary search or individual probing to find the exact active parameters"""
        if len(params) == 1:
            return params
            
        mid = len(params) // 2
        left_half = params[:mid]
        right_half = params[mid:]
        
        active = []
        
        for half in [left_half, right_half]:
            query_params = {p: self._generate_random_string(4) for p in half}
            separator = "&" if "?" in url else "?"
            probe_url = f"{url}{separator}{urlencode(query_params)}"
            
            response = self.http.get(probe_url)
            if response:
                current = {
                    "status_code": response.status_code,
                    "length": len(response.content),
                    "headers_count": len(response.headers),
                    "words_count": len(response.text.split()),
                    "lines_count": len(response.text.splitlines())
                }
                if self._is_different(current, baseline):
                    active.extend(self._narrow_down(url, half, baseline))
                    
        return active

if __name__ == "__main__":
    # Quick test harness (mock http)
    class MockHttp:
        def get(self, url):
            print(f"DEBUG: GET {url}")
            from collections import namedtuple
            Response = namedtuple('Response', ['status_code', 'content', 'headers', 'text'])
            
            # Simulate 'debug' and 'admin' reacting
            if "debug=" in url or "admin=" in url:
                return Response(200, b"Changed Content (Debug Mode)", {"X-Debug": "True"}, "Changed Content (Debug Mode)")
            return Response(200, b"Normal Content", {"Server": "Mock"}, "Normal Content")

    pd = ParamDiscovery("http://example.com", http_client=MockHttp())
    found = pd.discover_on_url("http://example.com/api")
    print(f"Discovered: {found}")
