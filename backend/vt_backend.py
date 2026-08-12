#!/usr/bin/env python3
"""
BOUGG - VirusTotal Backend for Render
"""

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import requests
import hashlib
import time
import os
from datetime import datetime
import json

app = Flask(__name__, static_folder='../', static_url_path='')
CORS(app)

# Get API key from environment variable
VT_API_KEY = os.environ.get('0caee396efcd2b1d519789dcf1ba2083d9ca503d1dff27292b3cf327c28c340b', '')
VT_API_URL = "https://www.virustotal.com/api/v3"

def calculate_hash(file_content):
    """Calculate file hashes"""
    return {
        'md5': hashlib.md5(file_content).hexdigest(),
        'sha1': hashlib.sha1(file_content).hexdigest(),
        'sha256': hashlib.sha256(file_content).hexdigest()
    }

@app.route('/')
def serve_frontend():
    """Serve the main HTML page"""
    return send_from_directory('..', 'index.html')

@app.route('/<path:path>')
def serve_static(path):
    """Serve static files (CSS, JS)"""
    return send_from_directory('..', path)

@app.route('/api/scan', methods=['POST'])
def scan_file():
    """Main scanning endpoint"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if not VT_API_KEY:
        return jsonify({'error': 'VirusTotal API key not configured'}), 500
    
    try:
        file_content = file.read()
        filename = file.filename
        hashes = calculate_hash(file_content)
        sha256 = hashes['sha256']
        
        headers = {"x-apikey": VT_API_KEY}
        
        # Check VirusTotal database
        response = requests.get(
            f"{VT_API_URL}/files/{sha256}",
            headers=headers
        )
        
        if response.status_code == 200:
            data = response.json()
            stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            return jsonify({
                'success': True,
                'filename': filename,
                'hashes': hashes,
                'source': 'VirusTotal Database',
                'stats': stats,
                'is_malware': stats.get('malicious', 0) > 0,
                'detection_ratio': f"{stats.get('malicious', 0)}/{sum(stats.values())}",
                'scan_date': datetime.now().isoformat()
            })
        
        # Upload and scan new file
        files = {'file': (filename, file_content)}
        upload = requests.post(
            f"{VT_API_URL}/files",
            headers=headers,
            files=files
        )
        
        if upload.status_code != 200:
            return jsonify({'error': 'Upload failed'}), 500
        
        analysis_id = upload.json().get('data', {}).get('id')
        
        # Wait for results
        for attempt in range(20):
            time.sleep(2)
            result = requests.get(
                f"{VT_API_URL}/analyses/{analysis_id}",
                headers=headers
            )
            
            if result.status_code == 200:
                data = result.json()
                status = data.get('data', {}).get('attributes', {}).get('status')
                
                if status == 'completed':
                    stats = data.get('data', {}).get('attributes', {}).get('stats', {})
                    return jsonify({
                        'success': True,
                        'filename': filename,
                        'hashes': hashes,
                        'source': 'VirusTotal Scan',
                        'stats': stats,
                        'is_malware': stats.get('malicious', 0) > 0,
                        'detection_ratio': f"{stats.get('malicious', 0)}/{sum(stats.values())}",
                        'scan_date': datetime.now().isoformat()
                    })
        
        return jsonify({'error': 'Analysis timeout'}), 408
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'api_key_configured': bool(VT_API_KEY),
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/stats', methods=['GET'])
def stats():
    """Get VirusTotal API stats"""
    if not VT_API_KEY:
        return jsonify({'error': 'API key not configured'}), 500
    
    headers = {"x-apikey": VT_API_KEY}
    
    try:
        # Check API key validity
        response = requests.get(
            f"{VT_API_URL}/user/overview",
            headers=headers
        )
        
        if response.status_code == 200:
            data = response.json()
            return jsonify({
                'success': True,
                'api_quota': '4 requests per minute (free tier)',
                'api_available': True
            })
        else:
            return jsonify({'error': 'API key invalid'}), 401
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f"🛡️ BOUGG VirusTotal Backend")
    print(f"📡 Running on port: {port}")
    print(f"🔑 API Key configured: {bool(VT_API_KEY)}")
    print(f"🌐 Serving frontend from: {app.static_folder}")
    app.run(host='0.0.0.0', port=port)
