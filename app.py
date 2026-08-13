#!/usr/bin/env python3
from flask import Flask, request, jsonify, send_file, send_from_directory
from flask_cors import CORS
import requests
import hashlib
import os
import json

app = Flask(__name__)
CORS(app)

BOUGG_API_KEY = "0caee396efcd2b1d519789dcf1ba2083d9ca503d1dff27292b3cf327c28c340b"
BOUGG_API_URL = "https://www.virustotal.com/api/v3"

# Serve HTML directly
@app.route('/')
def home():
    return '''
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BOUGG - Malware Detection</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f4f7fb; color: #1a1a2e; }
        .container { max-width: 900px; margin: 0 auto; padding: 20px; }
        .header { background: white; padding: 15px 0; box-shadow: 0 2px 20px rgba(0,0,0,0.06); }
        .header-inner { display: flex; justify-content: space-between; align-items: center; max-width: 900px; margin: 0 auto; padding: 0 20px; }
        .logo { display: flex; align-items: center; gap: 10px; font-size: 24px; font-weight: 800; text-decoration: none; }
        .logo-icon { background: linear-gradient(135deg, #33a351, #1a7a34); width: 44px; height: 44px; border-radius: 12px; display: flex; align-items: center; justify-content: center; color: white; font-size: 20px; }
        .logo-text { background: linear-gradient(135deg, #33a351, #1a7a34); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .nav-links { display: flex; gap: 10px; list-style: none; }
        .nav-links a { text-decoration: none; padding: 8px 20px; border-radius: 50px; font-weight: 500; font-size: 14px; color: #6c757d; transition: 0.3s; }
        .nav-links a:hover { background: rgba(51,163,81,0.1); }
        .nav-links a.active { background: #33a351; color: white; }
        .hero { text-align: center; padding: 60px 0 40px; }
        .hero h1 { font-size: 42px; font-weight: 900; margin-bottom: 15px; }
        .hero h1 span { color: #33a351; }
        .hero p { font-size: 18px; color: #6c757d; margin-bottom: 30px; }
        .btn { display: inline-block; padding: 14px 32px; border-radius: 50px; border: none; font-weight: 600; font-size: 15px; cursor: pointer; text-decoration: none; transition: 0.3s; font-family: inherit; }
        .btn-primary { background: linear-gradient(135deg, #33a351, #1a7a34); color: white; box-shadow: 0 4px 25px rgba(51,163,81,0.3); }
        .btn-primary:hover { transform: translateY(-3px); }
        .btn-success { background: #28a745; color: white; }
        .btn-success:hover { background: #218838; }
        .btn-secondary { background: #e9ecef; color: #1a1a2e; }
        .btn-secondary:hover { background: #d5d8dd; }
        .card { background: white; border-radius: 16px; padding: 40px; box-shadow: 0 10px 40px rgba(0,0,0,0.08); margin: 40px 0; text-align: center; }
        .card h2 { font-size: 28px; font-weight: 800; margin-bottom: 10px; }
        .card p { color: #6c757d; margin-bottom: 20px; }
        .upload-zone { border: 3px dashed #e9ecef; border-radius: 16px; padding: 50px 30px; background: #f8f9fa; cursor: pointer; transition: 0.3s; }
        .upload-zone:hover { border-color: #33a351; background: rgba(51,163,81,0.05); }
        .upload-zone .upload-icon { font-size: 48px; display: block; margin-bottom: 10px; }
        .upload-zone input[type="file"] { display: none; }
        .file-info { margin-top: 20px; padding: 20px; background: #f8f9fa; border-radius: 10px; }
        .file-details { display: flex; align-items: center; gap: 15px; background: white; padding: 15px 20px; border-radius: 8px; margin-bottom: 15px; }
        .file-name { font-weight: 600; }
        .file-size { font-size: 13px; color: #6c757d; }
        .scan-result { margin-top: 20px; padding: 30px; border-radius: 16px; text-align: center; }
        .scan-result.safe { background: #d4edda; border: 2px solid #28a745; }
        .scan-result.danger { background: #f8d7da; border: 2px solid #dc3545; }
        .result-icon { font-size: 48px; }
        .result-stats { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 10px; margin: 15px 0; }
        .stat-box { padding: 12px; border-radius: 8px; }
        .stat-box .number { font-size: 22px; font-weight: 700; }
        .stat-box .label { font-size: 12px; font-weight: 500; }
        .analysis-item { display: flex; justify-content: space-between; padding: 8px 12px; background: #f8f9fa; border-radius: 6px; font-size: 14px; }
        .analysis-item .label { font-weight: 600; color: #6c757d; }
        .footer { background: #0f0f1a; color: rgba(255,255,255,0.5); text-align: center; padding: 20px; margin-top: 40px; }
        .page { display: none; animation: fadeUp 0.4s ease; }
        .page.active { display: block; }
        @keyframes fadeUp { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
        .features-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; }
        .feature-card { padding: 25px; border-radius: 16px; background: #f8f9fa; transition: 0.3s; text-align: center; }
        .feature-card:hover { transform: translateY(-5px); box-shadow: 0 20px 60px rgba(0,0,0,0.1); }
        .feature-icon { font-size: 36px; display: block; margin-bottom: 10px; }
        .feature-card h4 { font-size: 18px; font-weight: 700; color: #1a1a2e; }
        .feature-card p { font-size: 14px; color: #6c757d; }
        @media (max-width: 768px) { .hero h1 { font-size: 30px; } .card { padding: 25px; } }
    </style>
</head>
<body>
    <header class="header">
        <div class="header-inner">
            <div class="logo">
                <span class="logo-icon">🛡️</span>
                <span class="logo-text">BOUGG</span>
            </div>
            <ul class="nav-links">
                <li><a href="#home" class="active" onclick="switchPage('home')">Home</a></li>
                <li><a href="#scan" onclick="switchPage('scan')">Scanner</a></li>
                <li><a href="#features" onclick="switchPage('features')">Features</a></li>
            </ul>
        </div>
    </header>

    <div class="container">
        <!-- Home -->
        <div id="home" class="page active">
            <div class="hero">
                <h1>Advanced <span>Malware Detection</span></h1>
                <p>Protect your system from viruses, trojans, ransomware, and zero-day threats with BOUGG's cutting-edge detection engine.</p>
                <a href="#scan" class="btn btn-primary" onclick="switchPage('scan')">🚀 Start Scanning</a>
            </div>
        </div>

        <!-- Scanner -->
        <div id="scan" class="page">
            <div class="card">
                <h2>🔬 BOUGG File Scanner</h2>
                <p>Upload any file to scan with BOUGG's multi-engine security system</p>
                <div class="upload-zone" id="uploadZone">
                    <span class="upload-icon">📤</span>
                    <p>Drop your file here or click to browse</p>
                    <input type="file" id="fileInput">
                    <button class="btn btn-primary" onclick="document.getElementById('fileInput').click()">Choose File</button>
                </div>
                <div id="fileInfo" class="file-info" style="display:none;">
                    <div class="file-details">
                        <span>📄</span>
                        <div>
                            <p class="file-name" id="fileName">-</p>
                            <p class="file-size" id="fileSize">-</p>
                        </div>
                    </div>
                    <button class="btn btn-success" onclick="scanFile()">🔬 Scan File</button>
                </div>
                <div id="scanResult" style="display:none;"></div>
                <div id="fileAnalysis" style="display:none;"></div>
            </div>
        </div>

        <!-- Features -->
        <div id="features" class="page">
            <div class="card">
                <h2>⚡ Powerful Features</h2>
                <p>Enterprise-grade security tools at your fingertips</p>
                <div class="features-grid">
                    <div class="feature-card"><span class="feature-icon">🔍</span><h4>Multi-Engine Scanning</h4><p>Scan with multiple security engines</p></div>
                    <div class="feature-card"><span class="feature-icon">📊</span><h4>Detailed Reports</h4><p>Comprehensive analysis with severity scores</p></div>
                    <div class="feature-card"><span class="feature-icon">🔒</span><h4>Privacy First</h4><p>Your files are scanned securely</p></div>
                    <div class="feature-card"><span class="feature-icon">⚡</span><h4>Real-time Results</h4><p>Instant detection and analysis</p></div>
                </div>
            </div>
        </div>
    </div>

    <footer class="footer">
        <p>&copy; 2026 BOUGG Malware Detection Tool. Made with ❤️</p>
    </footer>

    <script>
        // Navigation
        function switchPage(pageId) {
            document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
            document.getElementById(pageId).classList.add('active');
            document.querySelectorAll('.nav-links a').forEach(a => a.classList.remove('active'));
            document.querySelector('.nav-links a[href="#' + pageId + '"]').classList.add('active');
        }

        // Upload
        document.getElementById('fileInput').addEventListener('change', function() {
            if (this.files.length > 0) {
                var file = this.files[0];
                document.getElementById('fileName').textContent = file.name;
                document.getElementById('fileSize').textContent = (file.size / 1024 / 1024).toFixed(2) + ' MB';
                document.getElementById('fileInfo').style.display = 'block';
                document.getElementById('uploadZone').style.display = 'none';
                document.getElementById('scanResult').style.display = 'none';
            }
        });

        // Scan
        function scanFile() {
            var fileInput = document.getElementById('fileInput');
            var result = document.getElementById('scanResult');
            
            if (!fileInput.files.length) {
                alert('Please select a file first!');
                return;
            }
            
            var file = fileInput.files[0];
            var formData = new FormData();
            formData.append('file', file);
            
            result.style.display = 'block';
            result.innerHTML = '<p style="text-align:center;">🔄 Scanning with BOUGG Security Engine...</p>';
            document.getElementById('fileAnalysis').style.display = 'none';
            
            fetch('/api/scan', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.error) {
                    result.innerHTML = '<p style="color:red;">Error: ' + data.error + '</p>';
                    return;
                }
                
                var scan = data.scan_results || {};
                var stats = scan.stats || {};
                var malicious = stats.malicious || 0;
                var suspicious = stats.suspicious || 0;
                var undetected = stats.undetected || 0;
                var isMalware = scan.is_malware || false;
                
                result.innerHTML = `
                    <div style="padding:20px; border-radius:10px; background:${isMalware ? '#f8d7da' : '#d4edda'}; border:2px solid ${isMalware ? '#dc3545' : '#28a745'}; text-align:center;">
                        <h3>${isMalware ? '⚠️ Malware Detected!' : '✅ File is Safe!'}</h3>
                        <p>${isMalware ? malicious + ' security engines detected threats' : 'No threats detected'}</p>
                        <div class="result-stats">
                            <div class="stat-box" style="background:#dc3545; color:white;"><div class="number">${malicious}</div><div class="label">Malicious</div></div>
                            <div class="stat-box" style="background:#ffc107; color:#333;"><div class="number">${suspicious}</div><div class="label">Suspicious</div></div>
                            <div class="stat-box" style="background:#28a745; color:white;"><div class="number">${undetected}</div><div class="label">Undetected</div></div>
                        </div>
                        <button class="btn btn-secondary" onclick="resetScan()">Scan Another File</button>
                    </div>
                `;
                
                // Show file info
                var info = data.file_info || {};
                var analysisDiv = document.getElementById('fileAnalysis');
                analysisDiv.style.display = 'block';
                analysisDiv.innerHTML = `
                    <div style="background:#f8f9fa; padding:15px; border-radius:8px; margin-top:20px; text-align:left;">
                        <h4>📋 File Information</h4>
                        <div style="display:grid; grid-template-columns:1fr 1fr; gap:10px; font-size:14px;">
                            <div><strong>Filename:</strong> ${info.filename || 'N/A'}</div>
                            <div><strong>Size:</strong> ${info.size_human || 'N/A'}</div>
                            <div><strong>Type:</strong> ${info.file_type || 'Unknown'}</div>
                            <div><strong>MD5:</strong> <span style="font-size:11px;">${info.md5 || 'N/A'}</span></div>
                            <div style="grid-column: span 2;"><strong>SHA256:</strong> <span style="font-size:11px;">${info.sha256 || 'N/A'}</span></div>
                        </div>
                    </div>
                `;
            })
            .catch(function(error) {
                result.innerHTML = '<p style="color:red;">Error connecting to backend. Please try again.</p>';
            });
        }

        function resetScan() {
            document.getElementById('fileInput').value = '';
            document.getElementById('fileInfo').style.display = 'none';
            document.getElementById('uploadZone').style.display = 'block';
            document.getElementById('scanResult').style.display = 'none';
            document.getElementById('fileAnalysis').style.display = 'none';
        }
    </script>
</body>
</html>
    '''

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
        
        # File info
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
        
        # Check security database
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
    app.run(host='0.0.0.0', port=port)
