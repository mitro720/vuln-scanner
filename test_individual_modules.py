import requests
import time
import sys

TARGET = "https://juice-shop.herokuapp.com"

MODULES_TO_TEST = [
    "XSS", 
    "SQL Injection", 
    "Server-Side Template Injection",
    "NoSQL Injection",
    "Command Injection",
    "LDAP Injection",
    "XXE",
    "CRLF Injection",
    "IDOR",
    "JWT",
    "Mass Assignment",
    "A01: Access Control",
    "CORS",
    "Host Header Injection",
    "Rate Limit Bypass",
    "SSRF",
    "GraphQL Abuse",
    "Open Redirect",
    "HTTP Request Smuggling"
]

print(f"Starting sequential module test against {TARGET}...")

results_summary = {}

for module in MODULES_TO_TEST:
    print(f"\n[{module}] Starting test...")
    try:
        resp = requests.post("http://localhost:5000/api/scans", json={
            "target_url": TARGET,
            "scan_type": "full",
            "config": {
                "owasp": True, 
                "crawl": True, # Needed to populate parameters
                "cve_detection": False, 
                "port_scan": False, 
                "subdomain": False, 
                "waf": False, 
                "sensitive_files": False, 
                "cms_fingerprint": False,
                "visual_survey": False, 
                "api_discovery": False, 
                "nuclei_fallback": False,
                "module_timeout": 60,
                "request_delay": 0.1,
                "modules": [module]
            },
            "phase": "all" # Needs to be all to include recon/crawl first to fuzz
        })
        
        if not resp.ok:
            print(f"[{module}] Failed to start:", resp.text)
            continue
            
        data = resp.json().get('data', {})
        scan_id = data.get('id')
        print(f"[{module}] Scan ID: {scan_id}")
        
        # Poll
        status = 'running'
        for i in range(120): # Up to 10 minutes per module
            time.sleep(5)
            status_resp = requests.get(f"http://localhost:5000/api/scans/{scan_id}")
            if status_resp.ok:
                status_data = status_resp.json().get('data', {})
                status = status_data.get('status')
                prog = status_data.get('progress')
                phase = status_data.get('current_phase')
                print(f"  [{module}] {i*5}s: Status={status} Prog={prog}% Phase={phase}")
                if status in ['completed', 'failed', 'stopped']:
                    break
            else:
                break
                
        # Get findings
        findings_resp = requests.get(f"http://localhost:5000/api/scans/{scan_id}/findings")
        if findings_resp.ok:
            findings = findings_resp.json().get('data', [])
            results_summary[module] = len(findings)
            print(f"[{module}] Completed. Total findings: {len(findings)}")
            for f in findings:
                sev = f.get('severity', '?').upper()
                print(f"   -> [{sev}] {f.get('name')}")
        else:
            print(f"[{module}] Completed, but failed to get findings.")
            results_summary[module] = -1
            
    except Exception as e:
        print(f"[{module}] Test failed locally: {e}")

print("\n" + "="*40)
print("FINAL MODULE RESULTS SUMMARY")
print("="*40)
for m, c in results_summary.items():
    print(f"{m.ljust(30)} : {c} findings")
