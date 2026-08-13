#!/usr/bin/env python3
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import requests
import hashlib
import time
import os

app = Flask(__name__)
CORS(app)

# Get the absolute path to the project root
BASE_DIR = "/home/kali/Projects/Bougg/render-deploy"

BOUGG_API_KEY = "0caee396efcd2b1d519789dcf1ba2083d9ca503d1dff27292b3cf327c28c340b"
BOUGG_API_URL = "https://www.virustotal.com/api/v3"

@app.route('/')
def serve_index():
    return send_from_directory(BASE_DIR, 'index.html')

@app.route('/style.css')
def serve_css():
    return send_from_directory(BASE_DIR, 'style.css', mimetype='text/css')

@app.route('/script.js')
def serve_js():
    return send_from_directory(BASE_DIR, 'script.js', mimetype='application/javascript')

@app.route('/<path:path>')
def serve_static(path):
    return send_from_directory(BASE_DIR, path)

@app.route('/api/health')
def health():
    return jsonify({'status': 'ok', 'message': 'BOUGG Security Engine is running!'})

@app.route('/api/test')
def test():
    import os
    files = {}
    for f in ['index.html', 'style.css', 'script.js']:
        path = os.path.join(BASE_DIR, f)
        files[f] = os.path.exists(path)
    return jsonify({
        'base_dir': BASE_DIR,
        'files': files
    })

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
        except Exception as e:
            print(f"API error: {e}")
        
        return jsonify({
            'success': True,
            'filename': filename,
            'sha256': sha256,
            'file_info': file_info,
            'scan_results': scan_results
        })
        
    except Exception as e:
        print(f"Scan error: {e}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f"🛡️ BOUGG Backend running on port {port}")
    print(f"📁 Serving files from: {BASE_DIR}")
    app.run(host='0.0.0.0', port=port)
