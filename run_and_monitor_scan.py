import requests
import time
import sys

TARGET = "https://juice-shop.herokuapp.com"
API_BASE = "http://localhost:5000/api"

def start_scan():
    print(f"Initializing scan for {TARGET}...")
    try:
        payload = {
            "target_url": TARGET,
            "scan_type": "full",
            "config": {
                "owasp": True,
                "crawl": True,
                "cve_detection": True,
                "port_scan": True,
                "subdomain": False,
                "waf": True
            }
        }
        resp = requests.post(f"{API_BASE}/scans", json=payload)
        if resp.status_code != 201 and resp.status_code != 200:
            print(f"Error starting scan: {resp.status_code} - {resp.text}")
            return None
        
        data = resp.json().get('data', {})
        scan_id = data.get('id')
        print(f"Scan started successfully. ID: {scan_id}")
        return scan_id
    except Exception as e:
        print(f"Connection error: {e}")
        return None

def monitor_scan(scan_id):
    if not scan_id:
        return
    
    print(f"Monitoring scan {scan_id}...")
    last_progress = -1
    last_phase = ""
    
    # Monitor for about 5 minutes or until completion
    for _ in range(60):
        try:
            resp = requests.get(f"{API_BASE}/scans/{scan_id}")
            if resp.status_code == 200:
                data = resp.json().get('data', {})
                status = data.get('status')
                progress = data.get('progress', 0)
                phase = data.get('current_phase', 'unknown')
                
                if progress != last_progress or phase != last_phase:
                    print(f"Status: {status} | Progress: {progress}% | Phase: {phase}")
                    last_progress = progress
                    last_phase = phase
                
                if status in ['completed', 'failed', 'stopped']:
                    print(f"Scan finished with status: {status}")
                    
                    # Fetch findings
                    findings_resp = requests.get(f"{API_BASE}/scans/{scan_id}/findings")
                    if findings_resp.status_code == 200:
                        findings = findings_resp.json().get('data', [])
                        print(f"Total findings: {len(findings)}")
                        for f in findings:
                            print(f" - [{f.get('severity')}] {f.get('name')}")
                    break
            else:
                print(f"Error fetching status: {resp.status_code}")
        except Exception as e:
            print(f"Monitoring error: {e}")
            
        time.sleep(10)

if __name__ == "__main__":
    sid = start_scan()
    if sid:
        monitor_scan(sid)
    else:
        print("Failed to start scan.")
