import requests
import json

response = requests.post('http://localhost:8000/scan/start', json={
    "scan_id": "debug-999",
    "target_url": "http://testphp.vulnweb.com/",
    "phase": "vuln_only",
    "config": {
        "targets": ["http://testphp.vulnweb.com/"],
        "modules": ["Server-Side Template Injection", "SQL Injection", "XSS"],
        "owasp": True,
        "cve_detection": False,
        "port_scan": False
    }
})
print("OK")
