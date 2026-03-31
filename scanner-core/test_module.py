import sys
import os
import json
import logging
from typing import Dict, List, Any

# Root detection
def get_scanner_root():
    current = os.path.abspath(__file__)
    for _ in range(5):
        parent = os.path.dirname(current)
        basename = os.path.basename(parent)
        
        # If we are inside 'core', the scanner root is the parent of 'core'
        if basename == "core":
            return os.path.dirname(parent)
            
        # If we are in 'scanner-core', this is the root
        if basename == "scanner-core":
            return parent
            
        current = parent
    return os.path.dirname(os.path.abspath(__file__))

root = get_scanner_root()
if root not in sys.path:
    sys.path.insert(0, root)

from core.http_client import HttpClient
import importlib
import inspect

def run_module_test(target_url: str, module_path: str, class_name: str, discovery_urls: List[str] = None):
    print(f"\n{'='*60}")
    print(f">>> DEBUGGING MODULE: {module_path}.{class_name}")
    print(f"[*] Target: {target_url}")
    print(f"{'='*60}\n")

    # Initialize shared HttpClient
    http = HttpClient({"request_delay": 0.3, "random_jitter": True})
    
    # Discovery (Simulated or provided)
    urls_to_test = discovery_urls or [target_url]
    print(f"[?] URLs to test: {len(urls_to_test)}")
    for u in urls_to_test:
        print(f"   - {u}")
    print("")

    try:
        # Load and initialize module
        module = importlib.import_module(module_path)
        scanner_class = getattr(module, class_name)
        
        # Check if scanner accepts http_client
        sig = inspect.signature(scanner_class.__init__)
        if 'http_client' in sig.parameters:
            print(f"[+] Module '{class_name}' supports shared HttpClient injection.")
            module_inst = scanner_class(target_url, http_client=http)
        else:
            print(f"[!] Module '{class_name}' does NOT support HttpClient injection. Using internal Session.")
            module_inst = scanner_class(target_url)

        # Run scan
        print(f"[*] Starting scan sequence...")
        scan_sig = inspect.signature(module_inst.scan)
        
        results = []
        if 'urls' in scan_sig.parameters:
            results = module_inst.scan(urls_to_test)
        else:
            results = module_inst.scan()

        print(f"\n[!] SCAN COMPLETE: Found {len(results)} findings.\n")

        for i, f in enumerate(results):
            sev = f.get('severity','').upper()
            print(f"{i+1}. [{sev}] {f.get('name')}")
            print(f"   URL: {f.get('url')}")
            if f.get('parameter'): print(f"   Param: {f.get('parameter')}")
            print("")

    except Exception as e:
        print(f"\n❌ FATAL ERROR in Debug Module: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python test_module.py <target_url> <module_path> <class_name> [urls_json]")
        print("Example: python test_module.py http://testaspnet.vulnweb.com owasp.a03_xss XSSModule")
        sys.exit(1)
        
    target = sys.argv[1]
    mod_path = sys.argv[2]
    cls_name = sys.argv[3]
    
    extra_urls = None
    if len(sys.argv) > 4:
        raw_urls = sys.argv[4]
        try:
            extra_urls = json.loads(raw_urls)
        except:
            # Fallback to comma separated
            extra_urls = [u.strip() for u in raw_urls.split(',') if u.strip()]
        
    run_module_test(target, mod_path, cls_name, extra_urls)
