#!/usr/bin/env python3
from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import hashlib
import time
import os

app = Flask(__name__)
CORS(app)

# Your VirusTotal API Key
VT_API_KEY = "0caee396efcd2b1d519789dcf1ba2083d9ca503d1dff27292b3cf327c28c340b"
VT_API_URL = "https://www.virustotal.com/api/v3"

@app.route('/', methods=['GET'])
def home():
    return jsonify({
        'status': 'running',
        'message': 'BOUGG VirusTotal Backend',
        'endpoints': {
            '/scan': 'POST - Upload and scan files',
            '/api/scan': 'POST - Upload and scan files (alias)',
            '/health': 'GET - Health check'
        }
    })

@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'healthy',
        'api_key_configured': bool(VT_API_KEY)
    })

@app.route('/scan', methods=['POST'])
@app.route('/api/scan', methods=['POST'])
def scan_file():
    """Scan file with VirusTotal"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    try:
        file_content = file.read()
        filename = file.filename
        sha256 = hashlib.sha256(file_content).hexdigest()
        
        headers = {"x-apikey": VT_API_KEY}
        
        # Check VirusTotal
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
                'sha256': sha256,
                'stats': stats,
                'is_malware': stats.get('malicious', 0) > 0,
                'source': 'VirusTotal Database'
            })
        elif response.status_code == 404:
            # Upload and scan
            files = {'file': (filename, file_content)}
            upload = requests.post(
                f"{VT_API_URL}/files",
                headers=headers,
                files=files
            )
            
            if upload.status_code != 200:
                return jsonify({'error': 'Upload failed'}), 500
            
            analysis_id = upload.json().get('data', {}).get('id')
            
            for attempt in range(20):
                time.sleep(2)
                result = requests.get(
                    f"{VT_API_URL}/analyses/{analysis_id}",
                    headers=headers
                )
                if result.status_code == 200:
                    data = result.json()
                    if data.get('data', {}).get('attributes', {}).get('status') == 'completed':
                        stats = data.get('data', {}).get('attributes', {}).get('stats', {})
                        return jsonify({
                            'success': True,
                            'filename': filename,
                            'sha256': sha256,
                            'stats': stats,
                            'is_malware': stats.get('malicious', 0) > 0,
                            'source': 'VirusTotal Scan'
                        })
            
            return jsonify({'error': 'Analysis timeout'}), 408
        else:
            return jsonify({'error': f'VirusTotal error: {response.status_code}'}), 500
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print("🛡️ BOUGG VirusTotal Backend")
    print(f"📡 Running on port: {port}")
    app.run(host='0.0.0.0', port=port)
