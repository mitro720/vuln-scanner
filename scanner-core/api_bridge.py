"""
API Bridge - Connects Python scanner to Node.js backend
"""

import sys
import os
import json
import subprocess
import requests
from flask import Flask, request, jsonify
from flask_cors import CORS
import threading
import signal
import time

# ── Force UTF-8 I/O on Windows (cp1252 can't handle emoji in print statements) ──
os.environ['PYTHONIOENCODING'] = 'utf-8'
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
sys.stderr.reconfigure(encoding='utf-8', errors='replace')


app = Flask(__name__)

# Enhanced CORS configuration
CORS(app, resources={r"/*": {
    "origins": ["http://localhost:5173", "http://localhost:5174", "http://localhost:5000", "http://localhost:5001"],
    "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    "allow_headers": ["Content-Type", "Authorization"],
    "supports_credentials": True
}})

# Store active scans
active_scans = {}

# Backend API Configuration
BACKEND_URL = os.environ.get('BACKEND_URL', 'http://localhost:5001')
print(f"📡 Backend Reporting URL: {BACKEND_URL}")

SCANNER_HEADERS = {'x-scanner-api-key': os.environ.get('SCANNER_API_KEY', 'secure-scanner-key')}

# Map internal phase names to human-readable display names
PHASE_NAMES = {
    "initialization": "INITIALIZATION",
    "reconnaissance": "RECONNAISSANCE",
    "web_crawling": "DISCOVERY & CRAWLING",
    "visual_survey": "VISUAL SURVEY",
    "network_scanning": "NETWORK SCANNING",
    "vulnerability_detection": "VULNERABILITY SCAN",
    "cve_detection": "CVE MATCHING",
    "completed": "SCAN COMPLETED"
}


def run_scan(scan_id, target_url, config, phase="all", user_id=None):
    """Run scanner in subprocess"""
    try:
        # Get the scanner-core directory path
        scanner_core_dir = os.path.dirname(os.path.abspath(__file__))
        
        # Run scanner
        cmd = [
            sys.executable,
            'core/engine.py',
            target_url,
            json.dumps(config),
            phase
        ]
        
        print(f"🔧 Running {phase} scanner from directory: {scanner_core_dir}")
        print(f"🔧 Command: {' '.join(cmd)}\n")
        
        # Platform-aware process group creation
        kwargs = {}
        if sys.platform != 'win32':
            kwargs['preexec_fn'] = os.setsid
        else:
            kwargs['creationflags'] = subprocess.CREATE_NEW_PROCESS_GROUP
        
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            cwd=scanner_core_dir,
            **kwargs
        )
        
        active_scans[scan_id] = {
            'process': process,
            'status': 'running',
            'user_id': user_id,
            'logs': [],
            'findings_summary': { 'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0 }
        }
        
        # Read output line by line
        current_phase = None
        last_sync_time = time.time()
        
        for line in process.stdout:
            line = line.strip()
            if not line: continue
            
            # Helper to sync logs periodically
            def sync_logs(force=False):
                nonlocal last_sync_time
                if force or (time.time() - last_sync_time > 2.0):
                    try:
                        # Only send the most recent 100 logs to keep DB/UI snappy
                        log_snapshot = active_scans[scan_id]['logs'][-100:]
                        requests.put(
                            f'{BACKEND_URL}/api/scans/{scan_id}',
                            headers=SCANNER_HEADERS,
                            json={'metadata': {'logs': log_snapshot}},
                            timeout=10
                        )
                        last_sync_time = time.time()
                    except: pass

            if line.startswith('PROGRESS:'):
                try:
                    data = json.loads(line[9:])
                    phase = data.get('phase')
                    msg = data.get('message', '')
                    prog = data.get('progress', 0)
                    
                    if phase != current_phase:
                        current_phase = phase
                    
                    print(f"  [{prog:>2}%] {msg}")

                    # Update scan progress and sync logs
                    requests.put(
                        f'{BACKEND_URL}/api/scans/{scan_id}',
                        headers=SCANNER_HEADERS,
                        json={
                            'progress': prog, 
                            'current_phase': phase,
                            'metadata': {'logs': active_scans[scan_id]['logs'][-100:]}
                        }
                    )
                except Exception as e:
                    print(f"  [??%] {line}")
            
            elif line.startswith('METADATA:'):
                try:
                    data = json.loads(line[9:])
                    # Sync metadata update to backend
                    requests.put(
                        f'{BACKEND_URL}/api/scans/{scan_id}',
                        headers=SCANNER_HEADERS,
                        json={'metadata': data}
                    )
                    print(f"  [meta] Updated: {list(data.keys())}")
                except Exception as e:
                    print(f"  [meta] Error: {str(e)}")
                
            elif line.startswith('FINDING:'):
                try:
                    data = json.loads(line[8:])
                    severity = data.get('severity', 'info').upper()
                    score = data.get('cvss_score', 0.0)
                    sev_icon = "🔴" if severity == "CRITICAL" else "🟠" if severity == "HIGH" else "🟡" if severity == "MEDIUM" else "🔵"
                    
                    print(f"\n  {sev_icon}  {severity} (Score: {score}): {data.get('name')}")
                    
                    # Log the finding to the internal buffer too
                    active_scans[scan_id]['logs'].append(f"FINDING: {data.get('name')} ({severity})")
                    
                    # Update summary
                    sev_key = severity.lower()
                    if sev_key in active_scans[scan_id]['findings_summary']:
                        active_scans[scan_id]['findings_summary'][sev_key] += 1
                    else:
                        active_scans[scan_id]['findings_summary'][sev_key] = 1

                    # Save finding to database via backend API
                    evidence_payload = data.get('evidence', {})
                    requests.post(
                        f'{BACKEND_URL}/api/findings',
                        headers=SCANNER_HEADERS,
                        json={
                            'scan_id': scan_id,
                            'user_id': active_scans[scan_id].get('user_id'),
                            'name': data.get('name'),
                            'severity': data.get('severity'),
                            'owasp_category': data.get('owasp_category'),
                            'url': data.get('url'),
                            'confidence': data.get('confidence'),
                            'evidence': evidence_payload,
                            'poc': data.get('poc'),
                            'remediation': data.get('remediation')
                        }
                    )
                except Exception as e:
                    print(f"   ❌ Error saving finding: {e}")

            elif line.startswith('CRAWLER_GRAPH:'):
                # ... graph handling (omitted for brevity, keeping existing logic)
                try:
                    data = json.loads(line[14:])
                    requests.post(
                        f'{BACKEND_URL}/api/crawl',
                        headers=SCANNER_HEADERS,
                        json={
                            'target_url': target_url,
                            'scan_id': scan_id,
                            'nodes': data.get('nodes'),
                            'edges': data.get('edges'),
                            'forms': data.get('forms', []),
                            'stats': data.get('stats', {})
                        },
                        timeout=10
                    )
                except: pass

            elif line.startswith('WARNING:'):
                active_scans[scan_id]['logs'].append(f"WARNING: {line[8:]}")
                sync_logs()
                
            elif line.startswith('ERROR:'):
                error_content = line[6:].strip()
                active_scans[scan_id]['logs'].append(f"ERROR: {error_content}")
                
                # Try to parse as JSON to see if it's a structured engine error
                # Regular Python logging (e.g., ERROR:root:HTTP Request failed) shouldn't fail the entire scan
                is_fatal = False
                try:
                    json.loads(error_content)
                    is_fatal = True  # It's a structured error from emit_error()
                except ValueError:
                    if "CRITICAL:" in line or "FATAL:" in line:
                        is_fatal = True
                        
                if is_fatal:
                    active_scans[scan_id]['status'] = 'failed'
                    requests.put(f'{BACKEND_URL}/api/scans/{scan_id}', headers=SCANNER_HEADERS, json={'status': 'failed'})
                else:
                    sync_logs()
                
            elif line.startswith('RESULT:'):
                # ... final result handling
                try:
                    data = json.loads(line[7:])
                    meta = data.get('metadata', {})
                    # Include logs in final metadata
                    meta['logs'] = active_scans[scan_id]['logs']
                    summary = active_scans[scan_id].get('findings_summary', {})
                    
                    requests.put(
                        f'{BACKEND_URL}/api/scans/{scan_id}',
                        headers=SCANNER_HEADERS,
                        json={
                            'status': 'completed',
                            'progress': 100,
                            'metadata': meta,
                            'findings_count': data.get('findings_count', 0),
                            'critical_count': summary.get('critical', 0),
                            'high_count': summary.get('high', 0),
                            'medium_count': summary.get('medium', 0),
                            'low_count': summary.get('low', 0),
                            'info_count': summary.get('info', 0),
                        }
                    )
                except: pass
            else:
                # Capture raw engine logs
                clean_log = line.replace('[ENGINE LOG] ', '').strip()
                if clean_log:
                    timestamp = time.strftime("%H:%M:%S")
                    active_scans[scan_id]['logs'].append(f"[{timestamp}] {clean_log}")
                    sync_logs()
                
        process.wait()
        
    except Exception as e:
        print(f"Error running scan: {str(e)}")
        if scan_id in active_scans:
            active_scans[scan_id]['status'] = 'failed'


@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'ok',
        'message': 'Scanner API is running'
    })


@app.route('/scan/start', methods=['POST'])
def start_scan():
    """Start a new scan"""
    data = request.json
    scan_id = data.get('scan_id')
    user_id = data.get('user_id')
    target_url = data.get('target_url')
    config = data.get('config', {})
    phase = data.get('phase', 'all')
    
    print("\n" + "="*60)
    print(f"🔍 NEW SCAN REQUEST")
    print(f"   Scan ID: {scan_id}")
    print(f"   Target: {target_url}")
    print(f"   Phase: {phase}")
    print(f"   Config: {config}")
    print("="*60 + "\n")
    
    if not scan_id or not target_url:
        return jsonify({'error': 'Missing scan_id or target_url'}), 400
        
    # Start scan in background thread
    thread = threading.Thread(
        target=run_scan,
        args=(scan_id, target_url, config, phase, user_id)
    )
    thread.daemon = True
    thread.start()
    
    print(f"✅ Scan thread started for scan_id: {scan_id}\n")
    
    return jsonify({
        'success': True,
        'scan_id': scan_id,
        'status': 'started'
    })


@app.route('/scan/status/<scan_id>', methods=['GET'])
def scan_status(scan_id):
    """Get scan status"""
    if scan_id not in active_scans:
        return jsonify({'error': 'Scan not found'}), 404
        
    return jsonify({
        'scan_id': scan_id,
        'status': active_scans[scan_id]['status']
    })


@app.route('/scan/stop/<scan_id>', methods=['POST'])
def stop_scan(scan_id):
    """Stop an active scan"""
    if scan_id not in active_scans:
        return jsonify({'error': 'Scan not found or already finished'}), 404
        
    scan_info = active_scans[scan_id]
    process = scan_info.get('process')
    
    if process and process.poll() is None:
        try:
            print(f"🛑 Stopping scan {scan_id}...")
            # Platform-aware process termination
            if sys.platform != 'win32':
                os.killpg(os.getpgid(process.pid), signal.SIGTERM)
            else:
                process.terminate()
            
            # Allow a moment for cleanup
            time.sleep(1)
            if process.poll() is None:
                if sys.platform != 'win32':
                    os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                else:
                    process.kill()
            
            active_scans[scan_id]['status'] = 'stopped'
            
            # Notify backend
            try:
                requests.put(
                    f'{BACKEND_URL}/api/scans/{scan_id}',
                    headers=SCANNER_HEADERS,
                    json={'status': 'stopped', 'progress': 0}
                )
            except Exception as e:
                print(f"   ⚠️ Error notifying backend of stop: {e}")
                
            return jsonify({'success': True, 'message': 'Scan stopped successfully'})
        except Exception as e:
            return jsonify({'error': f"Failed to stop scan: {str(e)}"}), 500
    else:
        return jsonify({'error': 'Scan is not running'}), 400


@app.route('/crawl', methods=['POST'])
def crawl_target():
    """Crawl a target URL and return the attack surface graph."""
    data = request.json
    target_url = data.get('target_url')
    max_depth   = int(data.get('max_depth', 3))
    max_pages   = int(data.get('max_pages', 150))

    if not target_url:
        return jsonify({'error': 'target_url is required'}), 400

    print(f"\n🕷️  CRAWL REQUEST: {target_url}  (depth={max_depth}, max={max_pages})")

    try:
        scanner_core_dir = os.path.dirname(os.path.abspath(__file__))
        if scanner_core_dir not in sys.path:
            sys.path.insert(0, scanner_core_dir)

        from recon.crawler import WebCrawler
        crawler = WebCrawler(target_url, max_depth=max_depth, max_pages=max_pages)
        graph = crawler.crawl()
        print(f"✅ Crawl complete: {graph['stats']['total_nodes']} nodes, {graph['stats']['total_edges']} edges")
        return jsonify(graph)
    except Exception as e:
        print(f"❌ Crawl error: {e}")
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    print("""
========================================
   SecureScan Python API Bridge
   
   Server running on: http://localhost:8000
   Ready to process scan requests
========================================
    """)
    app.run(host='0.0.0.0', port=8000, debug=True)

