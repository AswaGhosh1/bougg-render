#!/usr/bin/env python3
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import requests
import hashlib
import time
import os

app = Flask(__name__, static_folder='../')
CORS(app)

VT_API_KEY = "0caee396efcd2b1d519789dcf1ba2083d9ca503d1dff27292b3cf327c28c340b"
VT_API_URL = "https://www.virustotal.com/api/v3"

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve_frontend(path):
    if not path:
        return send_from_directory('..', 'index.html')
    file_path = os.path.join('..', path)
    if os.path.exists(file_path):
        if path.endswith('.css'):
            return send_from_directory('..', path, mimetype='text/css')
        elif path.endswith('.js'):
            return send_from_directory('..', path, mimetype='application/javascript')
        elif path.endswith('.json'):
            return send_from_directory('..', path, mimetype='application/json')
        else:
            return send_from_directory('..', path)
    return f"File not found: {path}", 404

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({'status': 'healthy', 'api_key_configured': bool(VT_API_KEY)})

@app.route('/api/scan', methods=['POST'])
def scan_file():
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

        # Check
        response = requests.get(
            f"{VT_API_URL}/files/{sha256}",
            headers=headers
        )

        if response.status_code == 200:
            data = response.json()
            stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            # Get full analysis results
            results = data.get('data', {}).get('attributes', {}).get('last_analysis_results', {})

            # Format detailed results
            detailed_results = []
            for engine, result in results.items():
                if result.get('category') in ['malicious', 'suspicious']:
                    detailed_results.append({
                        'engine': engine,
                        'category': result.get('category', 'unknown'),
                        'result': result.get('result', 'Detected'),
                        'method': result.get('method', ''),
                        'engine_version': result.get('engine_version', ''),
                        'engine_update': result.get('engine_update', '')
                    })

            return jsonify({
                'success': True,
                'filename': filename,
                'sha256': sha256,
                'stats': stats,
                'is_malware': stats.get('malicious', 0) > 0,
                'source': 'VirusTotal Database',
                'detailed_results': detailed_results,
                'total_engines': len(results)
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
                        # Get results from analysis
                        results = data.get('data', {}).get('attributes', {}).get('results', {})

                        detailed_results = []
                        for engine, result_data in results.items():
                            if result_data.get('category') in ['malicious', 'suspicious']:
                                detailed_results.append({
                                    'engine': engine,
                                    'category': result_data.get('category', 'unknown'),
                                    'result': result_data.get('result', 'Detected'),
                                    'method': result_data.get('method', ''),
                                    'engine_version': result_data.get('engine_version', ''),
                                    'engine_update': result_data.get('engine_update', '')
                                })

                        return jsonify({
                            'success': True,
                            'filename': filename,
                            'sha256': sha256,
                            'stats': stats,
                            'is_malware': stats.get('malicious', 0) > 0,

                            'detailed_results': detailed_results,
                            'total_engines': len(results)
                        })

            return jsonify({'error': 'Analysis timeout'}), 408
        else:
            return jsonify({'error': f' error: {response.status_code}'}), 500

    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)

