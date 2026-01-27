import sys
import os

# Add scanner-core to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'scanner-core'))

from core.engine import ScanEngine

# Test the scanner with a vulnerable URL
target = "http://testphp.vulnweb.com/artists.php?artist=1"
config = {"subdomain": False, "port_scan": False, "crawl": False}

print(f"Testing scanner with: {target}")
engine = ScanEngine(target, config)
result = engine.run()

print(f"\nResult: {result}")
print(f"Findings count: {result.get('findings_count', 0)}")

