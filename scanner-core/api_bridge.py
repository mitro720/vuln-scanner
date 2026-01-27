"""
API Bridge - Connects Python scanner to Node.js backend
"""

import sys
import json
import os
import subprocess
import requests
from flask import Flask, request, jsonify
from flask_cors import CORS
import threading

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


def run_scan(scan_id, target_url, config):
    """Run scanner in subprocess"""
    try:
        # Get the scanner-core directory path
        scanner_core_dir = os.path.dirname(os.path.abspath(__file__))
        
        # Run scanner
        cmd = [
            sys.executable,
            'core/engine.py',
            target_url,
            json.dumps(config)
        ]
        
        print(f"🔧 Running scanner from directory: {scanner_core_dir}")
        print(f"🔧 Command: {' '.join(cmd)}\n")
        
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            cwd=scanner_core_dir  # CRITICAL: Set working directory to scanner-core
        )
        
        active_scans[scan_id] = {
            'process': process,
            'status': 'running'
        }
        
        # Read output line by line
        for line in process.stdout:
            line = line.strip()
            
            if line.startswith('PROGRESS:'):
                data = json.loads(line[9:])
                print(f"Progress: {data}")
                # TODO: Update scan progress in database via backend API
                try:
                    requests.put(
                        f'http://localhost:5000/api/scans/{scan_id}',
                        json={'progress': data['progress'], 'current_phase': data['phase']}
                    )
                except:
                    pass
                
            elif line.startswith('FINDING:'):
                data = json.loads(line[8:])
                print(f"\n🎯 FINDING DETECTED: {data.get('name')}")
                print(f"   Severity: {data.get('severity')}")
                print(f"   URL: {data.get('url')}")
                # Save finding to database via backend API
                try:
                    response = requests.post(
                        'http://localhost:5000/api/findings',
                        json={
                            'scan_id': scan_id,
                            'name': data.get('name'),
                            'severity': data.get('severity'),
                            'owasp_category': data.get('owasp_category'),
                            'url': data.get('url'),
                            'confidence': data.get('confidence'),
                            'technique': data.get('technique'),
                            'evidence': data.get('evidence'),
                            'poc': data.get('poc'),
                            'remediation': data.get('remediation')
                        }
                    )
                    if response.ok:
                        print(f"   ✅ Finding saved to database")
                    else:
                        print(f"   ❌ Failed to save finding: {response.status_code} - {response.text}")
                except Exception as e:
                    print(f"   ❌ Error saving finding: {e}")
                
            elif line.startswith('ERROR:'):
                data = json.loads(line[6:])
                print(f"Error: {data}")
                active_scans[scan_id]['status'] = 'failed'
                try:
                    requests.put(
                        f'http://localhost:5000/api/scans/{scan_id}',
                        json={'status': 'failed'}
                    )
                except:
                    pass
                
            elif line.startswith('RESULT:'):
                data = json.loads(line[7:])
                print(f"Result: {data}")
                active_scans[scan_id]['status'] = 'completed'
                try:
                    requests.put(
                        f'http://localhost:5000/api/scans/{scan_id}',
                        json={'status': 'completed', 'progress': 100}
                    )
                except:
                    pass
                
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
    
    print("\n" + "="*60)
    print(f"🔍 NEW SCAN REQUEST")
    print(f"   Scan ID: {scan_id}")
    print(f"   Target: {target_url}")
    print(f"   Config: {config}")
    print("="*60 + "\n")
    
    if not scan_id or not target_url:
        return jsonify({'error': 'Missing scan_id or target_url'}), 400
        
    # Start scan in background thread
    thread = threading.Thread(
        target=run_scan,
        args=(scan_id, target_url, config)
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


if __name__ == '__main__':
    print("""
========================================
   SecureScan Python API Bridge
   
   Server running on: http://localhost:8000
   Ready to process scan requests
========================================
    """)
    app.run(host='0.0.0.0', port=8000, debug=True)
