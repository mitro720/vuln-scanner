import sys
import os

# Add scanner-core to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'scanner-core'))

from core.engine import ScanEngine

# Test with BASE URL (no parameters) - scanner should crawl and discover parameterized URLs
target = "http://testphp.vulnweb.com"
config = {}  # Enable all features (crawling is on by default)

print(f"Testing scanner with BASE URL: {target}")
print("Scanner should crawl, discover URLs with parameters, and test them...")
print("-" * 60)

engine = ScanEngine(target, config)
result = engine.run()

print("\n" + "=" * 60)
print(f"Result: {result.get('status')}")
print(f"Findings count: {result.get('findings_count', 0)}")
print(f"URLs discovered: {len(result.get('metadata', {}).get('discovered_urls', []))}")
print("=" * 60)

if result.get('findings_count', 0) > 0:
    print("\n✅ SUCCESS! Scanner found vulnerabilities on a base URL!")
else:
    print("\n❌ No findings - check if crawler discovered parameterized URLs")
    discovered = result.get('metadata', {}).get('discovered_urls', [])
    if discovered:
        print(f"\n Discovered {len(discovered)} URLs:")
        for url in discovered[:10]:  # Show first 10
            print(f"   - {url}")
