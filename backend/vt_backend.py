#!/usr/bin/env python3
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import requests
import hashlib
import time
import os
import tempfile
from pe_analyzer import PEAnalyzer

app = Flask(__name__, static_folder='../')
CORS(app)

VT_API_KEY = "0caee396efcd2b1d519789dcf1ba2083d9ca503d1dff27292b3cf327c28c340b"
VT_API_URL = "https://www.virustotal.com/api/v3"

@app.route('/')
def serve_index():
    try:
        return send_from_directory('..', 'index.html')
    except Exception as e:
        return f"Error: {str(e)}", 500

@app.route('/style.css')
def serve_css():
    try:
        return send_from_directory('..', 'style.css', mimetype='text/css')
    except Exception as e:
        return f"Error: {str(e)}", 404

@app.route('/script.js')
def serve_js():
    try:
        return send_from_directory('..', 'script.js', mimetype='application/javascript')
    except Exception as e:
        return f"Error: {str(e)}", 404

@app.route('/manifest.json')
def serve_manifest():
    try:
        return send_from_directory('..', 'manifest.json', mimetype='application/json')
    except Exception as e:
        return "Manifest not found", 404

@app.route('/api/health')
def health():
    return {'status': 'ok', 'message': 'BOUGG backend is running!'}

@app.route('/api/scan', methods=['POST'])
def scan_file():
    if 'file' not in request.files:
        return {'error': 'No file uploaded'}, 400
    
    file = request.files['file']
    if file.filename == '':
        return {'error': 'No file selected'}, 400
    
    try:
        content = file.read()
        sha256 = hashlib.sha256(content).hexdigest()
        headers = {'x-apikey': VT_API_KEY}
        
        # Check VirusTotal
        response = requests.get(
            f'{VT_API_URL}/files/{sha256}',
            headers=headers
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
            
            # Do PE analysis
            pe_analysis = None
            if file.filename.lower().endswith(('.exe', '.dll', '.sys', '.ocx', '.cpl', '.scr')):
                with tempfile.NamedTemporaryFile(delete=False, suffix='.exe') as tmp:
                    tmp.write(content)
                    tmp_path = tmp.name
                try:
                    analyzer = PEAnalyzer(tmp_path, content)
                    pe_analysis = analyzer.analyze()
                finally:
                    os.unlink(tmp_path)
            
            return {
                'success': True,
                'filename': file.filename,
                'sha256': sha256,
                'stats': stats,
                'is_malware': stats.get('malicious', 0) > 0,
                'source': 'VirusTotal Database',
                'detailed_results': detailed,
                'pe_analysis': pe_analysis
            }
        elif response.status_code == 404:
            # Upload and scan
            files = {'file': (file.filename, content)}
            upload = requests.post(
                f'{VT_API_URL}/files',
                headers=headers,
                files=files
            )
            
            if upload.status_code != 200:
                return {'error': 'Upload failed'}, 500
            
            analysis_id = upload.json().get('data', {}).get('id')
            
            for _ in range(20):
                time.sleep(2)
                result = requests.get(
                    f'{VT_API_URL}/analyses/{analysis_id}',
                    headers=headers
                )
                if result.status_code == 200:
                    data = result.json()
                    if data.get('data', {}).get('attributes', {}).get('status') == 'completed':
                        stats = data.get('data', {}).get('attributes', {}).get('stats', {})
                        results = data.get('data', {}).get('attributes', {}).get('results', {})
                        
                        detailed = []
                        for engine, result_data in results.items():
                            if result_data.get('category') in ['malicious', 'suspicious']:
                                detailed.append({
                                    'engine': engine,
                                    'category': result_data.get('category', 'unknown'),
                                    'result': result_data.get('result', 'Detected')
                                })
                        
                        # Do PE analysis
                        pe_analysis = None
                        if file.filename.lower().endswith(('.exe', '.dll', '.sys', '.ocx', '.cpl', '.scr')):
                            with tempfile.NamedTemporaryFile(delete=False, suffix='.exe') as tmp:
                                tmp.write(content)
                                tmp_path = tmp.name
                            try:
                                analyzer = PEAnalyzer(tmp_path, content)
                                pe_analysis = analyzer.analyze()
                            finally:
                                os.unlink(tmp_path)
                        
                        return {
                            'success': True,
                            'filename': file.filename,
                            'sha256': sha256,
                            'stats': stats,
                            'is_malware': stats.get('malicious', 0) > 0,
                            'source': 'VirusTotal Scan',
                            'detailed_results': detailed,
                            'pe_analysis': pe_analysis
                        }
            
            return {'error': 'Analysis timeout'}, 408
        else:
            return {'error': f'VirusTotal error: {response.status_code}'}, 500
            
    except Exception as e:
        return {'error': str(e)}, 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
