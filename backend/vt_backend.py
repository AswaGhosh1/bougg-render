#!/usr/bin/env python3
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import requests
import hashlib
import time
import os
import tempfile
import math
from datetime import datetime

app = Flask(__name__, static_folder='../')
CORS(app)

VT_API_KEY = "0caee396efcd2b1d519789dcf1ba2083d9ca503d1dff27292b3cf327c28c340b"
VT_API_URL = "https://www.virustotal.com/api/v3"

# ===== FILE ANALYSIS FUNCTIONS =====

def analyze_file_general(file_content, filename):
    """Perform general analysis on any file"""
    analysis = {
        'file_info': {},
        'hashes': {},
        'entropy': 0,
        'file_type': 'Unknown',
        'is_pe': False
    }
    
    # Calculate hashes
    md5 = hashlib.md5(file_content).hexdigest()
    sha1 = hashlib.sha1(file_content).hexdigest()
    sha256 = hashlib.sha256(file_content).hexdigest()
    
    analysis['hashes'] = {
        'md5': md5,
        'sha1': sha1,
        'sha256': sha256
    }
    
    # File size
    file_size = len(file_content)
    analysis['file_info']['file_size'] = file_size
    analysis['file_info']['file_size_human'] = f"{file_size / 1024:.2f} KB" if file_size < 1048576 else f"{file_size / 1048576:.2f} MB"
    
    # Calculate entropy (randomness)
    if file_content:
        entropy = 0
        for i in range(256):
            count = file_content.count(i)
            if count > 0:
                p = count / file_size
                entropy -= p * math.log2(p)
        analysis['entropy'] = round(entropy, 4)
    
    # Detect file type
    ext = filename.lower().split('.')[-1] if '.' in filename else ''
    analysis['file_type'] = ext.upper() if ext else 'Unknown'
    
    # Check if it's a PE file
    pe_signatures = [b'MZ', b'PE\x00\x00']
    is_pe = False
    if file_content[:2] == b'MZ':
        is_pe = True
        analysis['is_pe'] = True
        analysis['file_type'] = 'PE (Windows Executable)'
        
        # Try to get more PE info
        try:
            import pefile
            with tempfile.NamedTemporaryFile(delete=False, suffix='.exe') as tmp:
                tmp.write(file_content)
                tmp_path = tmp.name
            
            pe = pefile.PE(tmp_path)
            analysis['pe_info'] = {
                'machine': hex(pe.FILE_HEADER.Machine),
                'number_of_sections': pe.FILE_HEADER.NumberOfSections,
                'entry_point': hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
                'image_base': hex(pe.OPTIONAL_HEADER.ImageBase),
                'pe_type': 'PE32' if pe.FILE_HEADER.IMAGE_FILE_32BIT_MACHINE else 'PE64',
                'timestamp': datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp).isoformat() if pe.FILE_HEADER.TimeDateStamp else None
            }
            
            # Analyze sections
            sections = []
            for section in pe.sections:
                name = section.Name.decode().rstrip('\x00')
                entropy = section.get_entropy()
                is_executable = bool(section.Characteristics & 0x20000000)
                is_writeable = bool(section.Characteristics & 0x80000000)
                
                section_data = {
                    'name': name,
                    'entropy': round(entropy, 4),
                    'size': section.SizeOfRawData,
                    'size_human': f"{section.SizeOfRawData / 1024:.2f} KB",
                    'is_executable': is_executable,
                    'is_writeable': is_writeable,
                    'suspicious': entropy > 7.0 or (is_executable and is_writeable)
                }
                sections.append(section_data)
            analysis['pe_sections'] = sections
            
            # Analyze imports
            suspicious_apis = {
                'Process Injection': ['VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread', 'NtCreateThreadEx'],
                'Keylogging': ['GetAsyncKeyState', 'GetKeyState', 'SetWindowsHookExA'],
                'Registry': ['RegSetValueExA', 'RegCreateKeyExA', 'RegOpenKeyExA'],
                'Network': ['InternetOpenA', 'HttpSendRequestA', 'URLDownloadToFileA', 'WinExec'],
                'File': ['CreateFileA', 'WriteFile', 'DeleteFileA'],
                'Service': ['CreateServiceA', 'OpenSCManagerA', 'StartServiceA']
            }
            
            suspicious_found = []
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode() if entry.dll else "Unknown"
                    for imp in entry.imports:
                        if imp.name:
                            func_name = imp.name.decode()
                            for category, apis in suspicious_apis.items():
                                if func_name in apis:
                                    suspicious_found.append({
                                        'function': func_name,
                                        'dll': dll_name,
                                        'category': category
                                    })
            analysis['suspicious_apis'] = suspicious_found
            
            # Risk assessment
            risk_factors = []
            risk_level = 'Low'
            
            if suspicious_found:
                risk_factors.append(f'{len(suspicious_found)} suspicious API calls detected')
                risk_level = 'Medium' if len(suspicious_found) < 5 else 'High'
            
            high_entropy_sections = [s for s in sections if s.get('suspicious') and s['entropy'] > 7.0]
            if high_entropy_sections:
                risk_factors.append('High entropy sections (possible packing/encryption)')
                risk_level = 'High' if risk_level == 'Medium' else 'Medium'
            
            exec_write_sections = [s for s in sections if s.get('is_executable') and s.get('is_writeable')]
            if exec_write_sections:
                risk_factors.append('Executable and writable sections (possible shellcode)')
                risk_level = 'Critical'
            
            # Packer detection
            packers = {
                '.upx0': 'UPX',
                '.upx1': 'UPX',
                '.vmp': 'VMProtect',
                '.themida': 'Themida',
                '.enigma': 'Enigma Protector',
                '.ors': 'Obsidium',
                '.code': 'ASPack',
                '.mackt': 'Armadillo'
            }
            detected_packer = None
            for section in pe.sections:
                name = section.Name.decode().rstrip('\x00').lower()
                for p_name, p_desc in packers.items():
                    if p_name in name:
                        detected_packer = p_desc
                        risk_factors.append(f'Packed with {p_desc}')
                        break
                if detected_packer:
                    break
            
            analysis['packer_detected'] = detected_packer
            analysis['risk_level'] = risk_level
            analysis['risk_factors'] = risk_factors[:5]  # Limit to 5
            
            os.unlink(tmp_path)
            
        except Exception as e:
            analysis['pe_error'] = str(e)
    
    return analysis

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
        filename = file.filename
        sha256 = hashlib.sha256(content).hexdigest()
        headers = {'x-apikey': VT_API_KEY}
        
        # Run general analysis on ALL files
        file_analysis = analyze_file_general(content, filename)
        
        # Check VirusTotal
        response = requests.get(
            f'{VT_API_URL}/files/{sha256}',
            headers=headers,
            timeout=30
        )
        
        vt_results = None
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
            
            vt_results = {
                'stats': stats,
                'is_malware': stats.get('malicious', 0) > 0,
                'detailed_results': detailed,
                'source': 'VirusTotal Database'
            }
        elif response.status_code == 404:
            # Upload and scan
            files = {'file': (filename, content)}
            upload = requests.post(
                f'{VT_API_URL}/files',
                headers=headers,
                files=files,
                timeout=30
            )
            
            if upload.status_code == 200:
                analysis_id = upload.json().get('data', {}).get('id')
                
                for _ in range(15):
                    time.sleep(2)
                    result = requests.get(
                        f'{VT_API_URL}/analyses/{analysis_id}',
                        headers=headers,
                        timeout=30
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
                            
                            vt_results = {
                                'stats': stats,
                                'is_malware': stats.get('malicious', 0) > 0,
                                'detailed_results': detailed,
                                'source': 'VirusTotal Scan'
                            }
                            break
        
        # Combine results
        result_data = {
            'success': True,
            'filename': filename,
            'sha256': sha256,
            'file_analysis': file_analysis,
            'vt_results': vt_results
        }
        
        return jsonify(result_data)
        
    except requests.exceptions.Timeout:
        return {'error': 'VirusTotal API timeout'}, 408
    except Exception as e:
        return {'error': str(e)}, 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
