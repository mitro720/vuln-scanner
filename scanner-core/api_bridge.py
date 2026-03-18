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

# ── Force UTF-8 I/O on Windows (cp1252 can't handle emoji in print statements) ──
os.environ['PYTHONIOENCODING'] = 'utf-8'
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
sys.stderr.reconfigure(encoding='utf-8', errors='replace')


app = Flask(__name__)

# Enhanced CORS configuration
CORS(app, resources={r"/*": {
    "origins": ["http://localhost:5173", "http://localhost:5174", "http://localhost:5000"],
    "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    "allow_headers": ["Content-Type", "Authorization"],
    "supports_credentials": True
}})

# Store active scans
active_scans = {}

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


def run_scan(scan_id, target_url, config, phase="all"):
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
        
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            cwd=scanner_core_dir
        )
        
        active_scans[scan_id] = {
            'process': process,
            'status': 'running'
        }
        
        # Read output line by line
        current_phase = None
        
        for line in process.stdout:
            line = line.strip()
            if not line: continue
            
            if line.startswith('PROGRESS:'):
                try:
                    data = json.loads(line[9:])
                    phase = data.get('phase')
                    msg = data.get('message', '')
                    prog = data.get('progress', 0)
                    
                    # Print header if phase has changed
                    if phase != current_phase:
                        display_name = PHASE_NAMES.get(phase, phase.upper())
                        print(f"\n{'─'*10} {display_name} {'─'*10}")
                        current_phase = phase
                    
                    # Clean the message if it already has the phase prefix (e.g. [Recon])
                    # engine.py often includes bracketed prefixes; we can leave them or clean them.
                    # Given the user wants "details for recon", keeping the message as is works well.
                    print(f"  [{prog:>2}%] {msg}")

                    # Update scan progress in database via backend API
                    requests.put(
                        f'http://localhost:5000/api/scans/{scan_id}',
                        json={'progress': prog, 'current_phase': phase}
                    )
                except Exception as e:
                    # Fallback to raw if JSON fails
                    print(f"  [??%] {line}")
                
            elif line.startswith('FINDING:'):
                try:
                    data = json.loads(line[8:])
                    severity = data.get('severity', 'info').upper()
                    score = data.get('cvss_score', 0.0)
                    sev_icon = "🔴" if severity == "CRITICAL" else "🟠" if severity == "HIGH" else "🟡" if severity == "MEDIUM" else "🔵"
                    
                    print(f"\n  {sev_icon}  {severity} (Score: {score}): {data.get('name')}")
                    print(f"      Target: {data.get('url')}")
                    if data.get('owasp_category'):
                        print(f"      Scope:  {data.get('owasp_category')}")

                    # Save finding to database via backend API
                    evidence_payload = data.get('evidence', {})
                    if isinstance(evidence_payload, dict) and data.get('technique'):
                        evidence_payload['detected_technique'] = data.get('technique')

                    requests.post(
                        'http://localhost:5000/api/findings',
                        json={
                            'scan_id': scan_id,
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
                try:
                    data = json.loads(line[14:])
                    # Sync with backend to populate the "Attack Surface" view
                    requests.post(
                        'http://localhost:5000/api/crawl',
                        json={
                            'target_url': target_url,
                            'scan_id': scan_id,
                            'nodes': data.get('nodes'),
                            'edges': data.get('edges'),
                            'forms': data.get('forms', []),
                            'stats': data.get('stats', {})
                        }
                    )
                except Exception as e:
                    print(f"   ❌ Error saving crawler graph: {e}")

            elif line.startswith('ERROR:'):
                try:
                    data = json.loads(line[6:])
                    print(f"\n  ❌ ERROR: {data.get('error')}")
                    active_scans[scan_id]['status'] = 'failed'
                    requests.put(f'http://localhost:5000/api/scans/{scan_id}', json={'status': 'failed'})
                except:
                    print(f"  ❌ RAW ERROR: {line}")
                
            elif line.startswith('RESULT:'):
                try:
                    data = json.loads(line[7:])
                    print(f"\n{'='*50}")
                    print(f"✨ SCAN COMPLETED FOR: {target_url}")
                    print(f"📊 Findings Count: {data.get('findings_count', 0)}")
                    
                    meta = data.get('metadata', {})
                    if meta:
                        print(f"🔍 Discovery Summary:")
                        if 'technologies' in meta:
                            techs = meta['technologies'].get('technologies', [])
                            if techs: print(f"   • Tech Stack: {', '.join(techs)}")
                            if 'server' in meta['technologies']: print(f"   • Server:     {meta['technologies']['server']}")
                        
                        if 'waf' in meta:
                            waf_data = meta['waf']
                            status = "Protected" if waf_data.get('waf_detected') else "None detected"
                            wafs = f" ({', '.join(waf_data.get('wafs', []))})" if waf_data.get('wafs') else ""
                            print(f"   • WAF Status: {status}{wafs}")
                        
                        if 'ports' in meta:
                            ports = meta['ports'].get('open_ports', [])
                            if ports:
                                p_list = [f"{p['port']}/{p['service']}" for p in ports]
                                print(f"   • Open Ports: {', '.join(p_list)}")
                        
                        if 'crawl' in meta:
                            stats = meta['crawl'].get('stats', {})
                            print(f"   • Attack Surface: {stats.get('total_nodes', 0)} nodes / {stats.get('total_edges', 0)} edges")

                    if 'report_path' in meta:
                        print(f"📄 Report: {meta['report_path']}")
                    print(f"{'='*50}\n")

                    active_scans[scan_id]['status'] = 'completed'
                    requests.put(
                        f'http://localhost:5000/api/scans/{scan_id}',
                        json={
                            'status': 'completed',
                            'progress': 100,
                            'metadata': meta,
                            'findings_count': data.get('findings_count', 0),
                        }
                    )
                except Exception as e:
                    print(f"  Result processed with error: {e}")

                
        process.wait()
        
    except Exception as e:
        print(f"Error running scan: {str(e)}")
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
        args=(scan_id, target_url, config, phase)
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
            # On Windows, we might need taskkill to ensure the whole process tree is killed
            import subprocess
            subprocess.run(['taskkill', '/F', '/T', '/PID', str(process.pid)], capture_output=True)
            
            active_scans[scan_id]['status'] = 'stopped'
            
            # Notify backend
            try:
                requests.put(
                    f'http://localhost:5000/api/scans/{scan_id}',
                    json={'status': 'stopped', 'progress': 0}
                )
            except:
                pass
                
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

