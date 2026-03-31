import requests
import time
import uuid

# We will start a scan on localhost:3000 where our vulnerable python app is running
scan_id = str(uuid.uuid4())

print(f"Starting scan {scan_id}...")
resp = requests.post("http://localhost:8000/scan/start", json={
    "scan_id": scan_id,
    "target_url": "http://localhost:3000/vuln",
    "config": {"owasp": True, "crawl": False, "cve_detection": False},
    "phase": "all"
})
print("Result:", resp.json())

# Wait a little for it to run
for _ in range(5):
    time.sleep(1)
    status = requests.get(f"http://localhost:8000/scan/status/{scan_id}").json()
    print("Status:", status)
    if status.get('status') in ['completed', 'failed']:
        break

print("Checking backend for findings...")
# Localhost 5000 is the backend
try:
    findings_resp = requests.get(f"http://localhost:5000/api/scans/{scan_id}")
    print("Backend scan details:", findings_resp.json())
except Exception as e:
    print("Backend check failed:", e)
