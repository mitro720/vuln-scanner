"""
CVE Integration Test
Tests the complete CVE detection workflow
"""

import sys
import os

# Add scanner-core to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'scanner-core'))

from cve.cve_client import CVEClient, NVDClient
from cve.version_detector import VersionDetector
from cve.cve_matcher import CVEMatcher

def test_nvd_client():
    """Test NVD API client"""
    print("\n" + "="*60)
    print("TEST 1: NVD Client - Fetching CVE-2021-44228 (Log4Shell)")
    print("="*60)
    
    client = NVDClient()
    cve_data = client.get_cve_by_id("CVE-2021-44228")
    
    if cve_data:
        print(f"✅ CVE ID: {cve_data['cve_id']}")
        print(f"✅ Severity: {cve_data['severity'].upper()}")
        print(f"✅ CVSS Score: {cve_data['cvss_score']}")
        print(f"✅ Description: {cve_data['description'][:100]}...")
        return True
    else:
        print("❌ Failed to fetch CVE data")
        return False

def test_version_detector():
    """Test version detection"""
    print("\n" + "="*60)
    print("TEST 2: Version Detector - Detecting example.com HTTP version")
    print("="*60)
    
    detector = VersionDetector()
    result = detector.detect_version("example.com", 80, "HTTP")
    
    print(f"Version: {result.get('version', 'Not detected')}")
    print(f"Banner: {result.get('banner', 'Not detected')}")
    print(f"Product: {result.get('product', 'Not detected')}")
    
    return True

def test_cve_matcher():
    """Test CVE matching for known vulnerable version"""
    print("\n" + "="*60)
    print("TEST 3: CVE Matcher - Testing Apache 2.4.49 (known vulnerable)")
    print("="*60)
    
    matcher = CVEMatcher(cve_provider='nvd')
    
    # Test with known vulnerable Apache version
    service_info = {
        'service': 'HTTP',
        'port': 80,
        'product': 'apache',
        'version': '2.4.49',
        'banner': 'Apache/2.4.49 (Unix)'
    }
    
    print(f"Testing service: {service_info['product']} {service_info['version']}")
    findings = matcher.match_service(service_info)
    
    if findings:
        print(f"\n✅ Found {len(findings)} CVE(s):")
        for finding in findings:
            print(f"\n  CVE: {finding['cve_id']}")
            print(f"  Severity: {finding['severity'].upper()}")
            print(f"  CVSS: {finding.get('cvss_score', 'N/A')}")
            print(f"  Description: {finding['description'][:100]}...")
        return True
    else:
        print("⚠️  No CVEs found (this might be due to API rate limiting or network issues)")
        return False

def test_integration():
    """Test complete integration"""
    print("\n" + "="*60)
    print("TEST 4: Full Integration - Port scan + Version detection + CVE matching")
    print("="*60)
    
    from recon.port_scanner import PortScanner
    
    # Scan a well-known host
    target = "scanme.nmap.org"
    print(f"\nScanning {target}...")
    
    scanner = PortScanner(target)
    # Scan only a few common ports for speed
    results = scanner.scan(ports=[22, 80, 443], detect_version=True)
    
    print(f"\nFound {results['total_open']} open port(s):")
    
    for port_info in results['open_ports']:
        print(f"\n  Port {port_info['port']}: {port_info['service']}")
        if port_info.get('version'):
            print(f"    Version: {port_info['version']}")
        if port_info.get('product'):
            print(f"    Product: {port_info['product']}")
        if port_info.get('banner'):
            print(f"    Banner: {port_info['banner'][:50]}...")
    
    # Try CVE matching on detected services
    if results['open_ports']:
        print("\n  Checking for CVEs...")
        matcher = CVEMatcher(cve_provider='nvd')
        
        all_findings = []
        for port_info in results['open_ports']:
            if port_info.get('version') or port_info.get('product'):
                findings = matcher.match_service(port_info)
                all_findings.extend(findings)
        
        if all_findings:
            print(f"\n  ✅ Found {len(all_findings)} CVE vulnerability(ies)")
        else:
            print(f"\n  ℹ️  No CVEs found for detected versions")
    
    return True

def main():
    """Run all tests"""
    print("\n" + "="*60)
    print("CVE INTEGRATION TEST SUITE")
    print("="*60)
    print("\nThis test suite verifies CVE database integration")
    print("Note: Tests require internet connection and may be rate-limited")
    
    tests = [
        ("NVD Client", test_nvd_client),
        ("Version Detector", test_version_detector),
        ("CVE Matcher", test_cve_matcher),
        ("Full Integration", test_integration),
    ]
    
    results = []
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"\n❌ Test failed with error: {e}")
            results.append((test_name, False))
    
    # Summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status}: {test_name}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 All tests passed!")
    else:
        print("\n⚠️  Some tests failed. Check output above for details.")

if __name__ == "__main__":
    main()
