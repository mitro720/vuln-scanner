import requests
import time

TARGET = "https://juice-shop.herokuapp.com"

print(f"Starting scan via backend API against {TARGET}...")
try:
    resp = requests.post("http://localhost:5000/api/scans", json={
        "target_url": TARGET,
        "scan_type": "full",
        "config": {"owasp": True, "crawl": False, "cve_detection": False, "port_scan": False, 
                   "subdomain": False, "waf": True, "sensitive_files": False, "cms_fingerprint": False,
                   "visual_survey": False, "api_discovery": False, "nuclei_fallback": False,
                   "module_timeout": 180, "request_delay": 0.2},
        "phase": "owasp"
    })
    
    if not resp.ok:
        print("Failed to start scan:", resp.text)
        exit(1)
        
    data = resp.json().get('data', {})
    scan_id = data.get('id')
    print(f"Started scan with ID: {scan_id}")
except Exception as e:
    print("Backend check failed:", e)
    exit(1)

# Poll for completion (up to 5 minutes)
for i in range(60):
    time.sleep(5)
    status_resp = requests.get(f"http://localhost:5000/api/scans/{scan_id}")
    if status_resp.ok:
        status_data = status_resp.json().get('data', {})
        phase = status_data.get('current_phase', '?')
        print(f"  [{i*5:>3}s] Status: {status_data.get('status')} | Progress: {status_data.get('progress')}% | Phase: {phase}")
        if status_data.get('status') in ['completed', 'failed', 'stopped']:
            break
    else:
        print("Status check error", status_resp.text)

print("\n" + "="*60)
print("SCAN RESULTS")
print("="*60)
findings_resp = requests.get(f"http://localhost:5000/api/scans/{scan_id}/findings")
if findings_resp.ok:
    findings = findings_resp.json().get('data', [])
    print(f"\nTotal findings: {len(findings)}\n")
    for f in findings:
        sev = f.get('severity', '?').upper()
        icon = "🔴" if sev == "CRITICAL" else "🟠" if sev == "HIGH" else "🟡" if sev == "MEDIUM" else "🔵"
        try:
            print(f" {icon} [{sev:>8}] {f.get('name')} — {f.get('url', '')[:80]}")
        except UnicodeEncodeError:
            # Fallback for Windows terminals without emoji support
            print(f" [*] [{sev:>8}] {f.get('name')} - {f.get('url', '')[:80]}")
else:
    print("Failed to get findings:", findings_resp.text)
