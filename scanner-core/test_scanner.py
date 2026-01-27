import sys
sys.path.insert(0, '.')

from core.engine import ScanEngine

# Test scanner with a known vulnerable site
config = {
    "owasp": True,
    "subdomain": False,
    "waf": False,
    "port_scan": False,
    "crawl": True
}

engine = ScanEngine("http://testphp.vulnweb.com", config)
result = engine.run()

print("\n=== SCAN RESULT ===")
print(f"Status: {result['status']}")
print(f"Findings: {result['findings_count']}")
print(f"Metadata: {result.get('metadata', {})}")
