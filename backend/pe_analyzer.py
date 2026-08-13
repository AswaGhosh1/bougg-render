#!/usr/bin/env python3
"""
PEStudio-Style PE File Analyzer
Performs deep static analysis on Windows executables
"""

import pefile
import hashlib
import os
import json
import math
import re
from datetime import datetime

class PEAnalyzer:
    def __init__(self, file_path, file_content):
        self.file_path = file_path
        self.file_content = file_content
        self.pe = None
        self.results = {
            'file_info': {},
            'hashes': {},
            'sections': [],
            'imports': {},
            'exports': [],
            'suspicious_apis': [],
            'strings': [],
            'indicators': [],
            'risk_factors': [],
            'overall_risk': 'Low',
            'packer_detected': None,
            'pe_headers': {}
        }
    
    def load_pe(self):
        try:
            self.pe = pefile.PE(self.file_path)
            return True
        except Exception as e:
            return False
    
    def analyze_file_info(self):
        if not self.pe:
            return
        
        self.results['file_info'] = {
            'file_size': len(self.file_content),
            'file_size_human': f"{len(self.file_content) / 1024:.2f} KB",
            'pe_type': 'PE32' if self.pe.FILE_HEADER.IMAGE_FILE_32BIT_MACHINE else 'PE64',
            'machine': hex(self.pe.FILE_HEADER.Machine),
            'number_of_sections': self.pe.FILE_HEADER.NumberOfSections,
            'timestamp': datetime.fromtimestamp(self.pe.FILE_HEADER.TimeDateStamp).isoformat() if self.pe.FILE_HEADER.TimeDateStamp else None,
            'characteristics': hex(self.pe.FILE_HEADER.Characteristics),
            'entry_point': hex(self.pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            'image_base': hex(self.pe.OPTIONAL_HEADER.ImageBase)
        }
    
    def calculate_hashes(self):
        md5 = hashlib.md5(self.file_content).hexdigest()
        sha1 = hashlib.sha1(self.file_content).hexdigest()
        sha256 = hashlib.sha256(self.file_content).hexdigest()
        
        self.results['hashes'] = {
            'md5': md5,
            'sha1': sha1,
            'sha256': sha256
        }
    
    def analyze_sections(self):
        if not self.pe:
            return
        
        for section in self.pe.sections:
            name = section.Name.decode().rstrip('\x00')
            entropy = section.get_entropy()
            is_executable = bool(section.Characteristics & 0x20000000)
            is_writeable = bool(section.Characteristics & 0x80000000)
            is_readable = bool(section.Characteristics & 0x40000000)
            
            section_data = {
                'name': name,
                'entropy': round(entropy, 4),
                'size': section.SizeOfRawData,
                'size_human': f"{section.SizeOfRawData / 1024:.2f} KB",
                'virtual_address': hex(section.VirtualAddress),
                'virtual_size': section.Misc_VirtualSize,
                'is_executable': is_executable,
                'is_writeable': is_writeable,
                'is_readable': is_readable,
                'suspicious': False,
                'risk_reasons': []
            }
            
            # Check for suspicious characteristics
            if entropy > 7.0:
                section_data['suspicious'] = True
                section_data['risk_reasons'].append('High entropy (packed/encrypted)')
                self.results['risk_factors'].append(f'Section "{name}" has high entropy (packed)')
            
            if is_executable and is_writeable:
                section_data['suspicious'] = True
                section_data['risk_reasons'].append('Executable and writable (possible shellcode)')
                self.results['risk_factors'].append(f'Section "{name}" is executable and writable')
            
            # Check for known packer sections
            packers = {
                '.upx0': 'UPX Packed',
                '.upx1': 'UPX Packed',
                '.vmp': 'VMProtect',
                '.themida': 'Themida',
                '.enigma': 'Enigma Protector',
                '.ors': 'Obsidium',
                '.code': 'ASPack',
                '.mackt': 'Armadillo',
                '.mpress': 'Mpress'
            }
            
            for p_name, p_desc in packers.items():
                if p_name in name.lower():
                    self.results['packer_detected'] = p_desc
                    section_data['suspicious'] = True
                    section_data['risk_reasons'].append(f'Packer detected: {p_desc}')
                    self.results['risk_factors'].append(f'File packed with {p_desc}')
            
            self.results['sections'].append(section_data)
    
    def analyze_imports(self):
        if not self.pe:
            return
        
        suspicious_apis = {
            'Process Injection': ['VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread', 'NtCreateThreadEx', 'QueueUserAPC', 'SetThreadContext'],
            'Anti-Debug': ['IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'NtQueryInformationProcess', 'GetTickCount'],
            'Keylogging': ['GetAsyncKeyState', 'GetKeyState', 'SetWindowsHookExA', 'SetWindowsHookExW', 'RegisterHotKey'],
            'Registry Manipulation': ['RegSetValueExA', 'RegCreateKeyExA', 'RegOpenKeyExA', 'RegDeleteValueA', 'RegDeleteKeyA'],
            'Network': ['InternetOpenA', 'InternetConnectA', 'HttpSendRequestA', 'URLDownloadToFileA', 'WinExec', 'ShellExecuteA', 'WSAStartup', 'socket', 'connect'],
            'File Manipulation': ['CreateFileA', 'WriteFile', 'DeleteFileA', 'MoveFileA', 'CopyFileA', 'FindFirstFileA'],
            'Service Manipulation': ['CreateServiceA', 'OpenSCManagerA', 'StartServiceA', 'ControlService', 'DeleteService'],
            'Process Manipulation': ['OpenProcess', 'TerminateProcess', 'CreateProcessA', 'GetCurrentProcess'],
            'Encryption': ['CryptEncrypt', 'CryptDecrypt', 'CryptAcquireContextA'],
            'Memory Manipulation': ['VirtualAlloc', 'VirtualProtect', 'VirtualFree', 'VirtualQuery'],
            'Anti-Disassembly': ['ZwSetInformationThread', 'NtSetInformationThread', 'SetUnhandledExceptionFilter']
        }
        
        if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode() if entry.dll else "Unknown"
                self.results['imports'][dll_name] = []
                
                for imp in entry.imports:
                    if imp.name:
                        func_name = imp.name.decode()
                        self.results['imports'][dll_name].append(func_name)
                        
                        for category, apis in suspicious_apis.items():
                            if func_name in apis:
                                self.results['suspicious_apis'].append({
                                    'function': func_name,
                                    'dll': dll_name,
                                    'category': category
                                })
    
    def analyze_exports(self):
        if not self.pe:
            return
        
        if hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    self.results['exports'].append(exp.name.decode())
    
    def extract_strings(self):
        # Extract ASCII strings (minimum 4 characters)
        strings = []
        current = []
        for byte in self.file_content[:100000]:  # Limit for performance
            if 32 <= byte <= 126:
                current.append(chr(byte))
            else:
                if len(current) >= 4:
                    strings.append(''.join(current))
                current = []
        
        # Check for suspicious strings
        suspicious_patterns = {
            'URL': r'https?://[^\s]+',
            'IP Address': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            'Domain': r'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b',
            'Registry Key': r'HKEY_[A-Z_]+\\[^\s]+',
            'File Path': r'[A-Za-z]:\\(?:[^\\/]+\\)+[^\\/]+\.[a-zA-Z]+',
            'Email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        }
        
        indicators = {}
        for pattern_type, pattern in suspicious_patterns.items():
            matches = []
            for s in strings[:1000]:
                found = re.findall(pattern, s)
                if found:
                    matches.extend(found)
            if matches:
                indicators[pattern_type] = list(set(matches))[:5]
        
        self.results['strings'] = strings[:100]
        self.results['indicators'] = indicators
    
    def calculate_risk_score(self):
        risk_count = len(self.results['risk_factors'])
        suspicious_apis_count = len(self.results['suspicious_apis'])
        suspicious_sections = [s for s in self.results['sections'] if s.get('suspicious', False)]
        
        if risk_count > 5 or suspicious_apis_count > 5 or len(suspicious_sections) > 2:
            self.results['overall_risk'] = 'Critical'
        elif risk_count > 3 or suspicious_apis_count > 3 or len(suspicious_sections) > 1:
            self.results['overall_risk'] = 'High'
        elif risk_count > 1 or suspicious_apis_count > 1:
            self.results['overall_risk'] = 'Medium'
        else:
            self.results['overall_risk'] = 'Low'
    
    def analyze(self):
        if not self.load_pe():
            return None
        
        self.calculate_hashes()
        self.analyze_file_info()
        self.analyze_sections()
        self.analyze_imports()
        self.analyze_exports()
        self.extract_strings()
        self.calculate_risk_score()
        
        return self.results
