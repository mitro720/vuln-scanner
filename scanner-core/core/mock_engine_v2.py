import sys
import json
import time

def emit(prefix, data):
    print(f"{prefix}:{json.dumps(data)}", flush=True)

target_url = sys.argv[1] if len(sys.argv) > 1 else "http://example.com"

# 1. Recon
emit("PROGRESS", {"phase": "reconnaissance", "progress": 5, "message": "[Recon] Starting passive reconnaissance..."})
time.sleep(0.5)
emit("PROGRESS", {"phase": "reconnaissance", "progress": 10, "message": "[Tech Fingerprint] Detected: ASP.NET, jQuery | Server: IIS"})
time.sleep(0.5)

# 2. Discovery
emit("PROGRESS", {"phase": "web_crawling", "progress": 35, "message": "Crawling web application..."})
time.sleep(0.5)
emit("PROGRESS", {"phase": "web_crawling", "progress": 40, "message": "Discovered 50 URLs, 5 forms"})
time.sleep(0.5)

# 3. Finding
emit("FINDING", {
    "name": "SQL Injection",
    "severity": "high",
    "url": f"{target_url}/search?id=1",
    "owasp_category": "A03:2021-Injection",
    "confidence": 100
})

# 4. Error
emit("PROGRESS", {"phase": "visual_survey", "progress": 47, "message": "Capturing screenshots..."})
emit("ERROR", {"error": "Visual survey failed: No module named 'selenium'"})

# 5. Result
result = {
    "status": "completed",
    "findings_count": 1,
    "metadata": {
        "technologies": {"technologies": ["ASP.NET", "jQuery"], "server": "IIS"},
        "waf": {"waf_detected": False},
        "ports": {"open_ports": [{"port": 80, "service": "http"}]},
        "crawl": {"stats": {"total_nodes": 50, "total_edges": 120}},
        "report_path": "reports/test_report.pdf"
    }
}
emit("RESULT", result)
