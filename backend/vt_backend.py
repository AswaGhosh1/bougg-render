#!/usr/bin/env python3
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import requests
import hashlib
import time
import os

app = Flask(__name__, static_folder='../')
CORS(app)

# BOUGG Security API Key
BOUGG_API_KEY = "0caee396efcd2b1d519789dcf1ba2083d9ca503d1dff27292b3cf327c28c340b"
BOUGG_API_URL = "https://www.virustotal.com/api/v3"

@app.route('/')
def serve_index():
    return send_from_directory('..', 'index.html')

@app.route('/<path:path>')
def serve_static(path):
    return send_from_directory('..', path)

@app.route('/api/health')
def health():
    return jsonify({'status': 'ok', 'message': 'BOUGG Security Engine is running!'})

@app.route('/api/scan', methods=['POST'])
def scan_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    try:
        content = file.read()
        filename = file.filename
        sha256 = hashlib.sha256(content).hexdigest()
        headers = {'x-apikey': BOUGG_API_KEY}
        
        # Get file info
        file_info = {
            'filename': filename,
            'size_bytes': len(content),
            'size_human': f"{len(content) / 1024:.2f} KB" if len(content) < 1048576 else f"{len(content) / 1048576:.2f} MB",
            'md5': hashlib.md5(content).hexdigest(),
            'sha1': hashlib.sha1(content).hexdigest(),
            'sha256': sha256,
            'file_type': filename.split('.')[-1].upper() if '.' in filename else 'Unknown',
            'extension': filename.split('.')[-1].upper() if '.' in filename else 'None'
        }
        
        # Check BOUGG Security Database
        scan_results = None
        try:
            response = requests.get(
                f'{BOUGG_API_URL}/files/{sha256}',
                headers=headers,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                results = data.get('data', {}).get('attributes', {}).get('last_analysis_results', {})
                
                detailed = []
                for engine, result in results.items():
                    if result.get('category') in ['malicious', 'suspicious']:
                        detailed.append({
                            'engine': engine,
                            'category': result.get('category', 'unknown'),
                            'result': result.get('result', 'Detected')
                        })
                
                scan_results = {
                    'stats': stats,
                    'is_malware': stats.get('malicious', 0) > 0,
                    'detailed_results': detailed,
                    'source': 'BOUGG Security Database'
                }
        except:
            pass
        
        return jsonify({
            'success': True,
            'filename': filename,
            'sha256': sha256,
            'file_info': file_info,
            'scan_results': scan_results
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
