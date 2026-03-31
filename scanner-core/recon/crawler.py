"""
SecureScan - Web Crawler / Spider
Leverages Katana (Go tool) to crawl a target web application
and build an attack surface graph.
"""

import sys
import os
import json
import time
from urllib.parse import urlparse
from typing import Dict, List, Any, Set, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.tool_runner import ToolRunner

def _normalize(url: str) -> str:
    """Strip fragment and trailing slash so duplicates collapse."""
    p = urlparse(url)
    path = p.path.rstrip('/') or '/'
    query = p.query
    return f"{p.scheme}://{p.netloc}{path}{'?' + query if query else ''}"

def _classify(url: str) -> str:
    """Return node type: page | api | static"""
    ext = os.path.splitext(urlparse(url).path)[1].lower()
    static_exts = {'.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg',
                   '.ico', '.woff', '.woff2', '.ttf', '.eot', '.pdf', '.zip'}
    if ext in static_exts:
        return 'static'
    api_patterns = ['/api/', '/v1/', '/v2/', '/v3/', '/graphql', '/rest/', '/json', '/rpc']
    if any(p in url.lower() for p in api_patterns):
        return 'api'
    return 'page'

class WebCrawler:
    def __init__(self, target_url: str, max_depth: int = 3, max_pages: int = 150):
        self.seed = target_url.rstrip('/')
        self.base_origin = f"{urlparse(target_url).scheme}://{urlparse(target_url).netloc}"
        self.max_depth = max_depth
        self.max_pages = max_pages
        
        # User-Agent for crawler
        self.ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

        self.nodes: Dict[str, Dict] = {}
        self.edges: List[Dict] = []
        self.forms: List[Dict] = []
        self._edge_set: Set[Tuple[str, str]] = set()

    def _add_node(self, url: str, node_type: str, depth: int, status: int = 0) -> str:
        nid = _normalize(url)
        if nid not in self.nodes:
            self.nodes[nid] = {
                'id': nid,
                'url': nid,
                'type': node_type,
                'depth': depth,
                'status_code': status,
                'title': '',
                'is_root': nid == _normalize(self.seed),
            }
        return nid

    def _add_edge(self, src: str, dst: str):
        if not src or not dst: return
        key = (src, dst)
        if key not in self._edge_set and src != dst:
            self._edge_set.add(key)
            self.edges.append({'source': src, 'target': dst})

    def crawl(self, extra_headers: Dict[str, str] = None, on_url=None) -> Dict[str, Any]:
        start = time.time()
        
        # Ensure seed node is added
        seed_id = self._add_node(self.seed, 'page', 0, 200)

        if not ToolRunner.is_installed("katana"):
            print("[-] katana not found in PATH! Web crawling will be skipped.")
            return self._build_result(start)

        print(f"[*] Starting Katana crawler on {self.seed}")
        cmd = [
            "katana",
            "-u", self.seed,
            "-d", str(self.max_depth),
            "-jc",           # js parsing
            "-c", "10",      # concurrency
            "-silent",
            "-jsonl"
        ]
        
        # Add headers if provided (propagate UA and Auth)
        if extra_headers:
            for k, v in extra_headers.items():
                cmd.extend(["-H", f"{k}: {v}"])
        else:
            cmd.extend(["-H", f"User-Agent: {self.ua}"])

        # Read JSON stream from Katana
        for data in ToolRunner.run_command_json_stream(cmd):
            try:
                # Katana 'request' object usually has the URL
                req = data.get('request', {})
                resp = data.get('response', {})
                url = req.get('endpoint', '')
                
                if not url or not url.startswith('http'):
                    continue
                    
                # Enforcement of max_pages
                if len(self.nodes) >= self.max_pages:
                    continue
                    
                status = resp.get('status_code', 0)
                source = req.get('source', '')
                
                # Default to seed if source is missing or not a full URL
                if not source or not source.startswith('http'):
                    source = self.seed
                    
                ntype = _classify(url)
                
                # Add discovered node
                nid = self._add_node(url, ntype, 1, status)
                
                if on_url:
                    on_url(url, ntype, status)

                # Try to add an edge from source -> node
                sid = _normalize(source)
                if sid in self.nodes:
                    self._add_edge(sid, nid)
                else:
                    self._add_edge(seed_id, nid)
                    
            except Exception as e:
                pass

        return self._build_result(start)

    def _build_result(self, start_time: float) -> Dict[str, Any]:
        elapsed = round(time.time() - start_time, 2)
        
        type_counts = {}
        urls = []
        for n in self.nodes.values():
            t = n['type']
            type_counts[t] = type_counts.get(t, 0) + 1
            if t not in ('static', 'external'):
                urls.append(n['url'])

        return {
            'seed': self.seed,
            'nodes': list(self.nodes.values()),
            'edges': self.edges,
            # We skip detailed form extraction for now as katana doesn't easily emit DOM form details
            'forms': [],
            'urls': urls,
            'stats': {
                'total_nodes': len(self.nodes),
                'total_edges': len(self.edges),
                'total_forms': 0,
                'elapsed_seconds': elapsed,
                'pages_visited': len(self.nodes),
                **type_counts,
            }
        }

if __name__ == "__main__":
    crawler = WebCrawler("http://example.com")
    print(json.dumps(crawler.crawl(), indent=2))
