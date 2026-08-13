#!/usr/bin/env python3
from flask import Flask, request, jsonify, send_from_directory, session
from flask_cors import CORS
import requests
import hashlib
import time
import os
import json
import tempfile
import math
from datetime import datetime, timedelta
import sqlite3
from functools import wraps
import traceback

app = Flask(__name__, static_folder='../')
app.secret_key = 'your-secret-key-here-change-in-production'
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True for HTTPS
CORS(app, supports_credentials=True, origins=['*'])

# ===== DATABASE SETUP =====
DB_PATH = 'bougg_users.db'

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # Users table
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            is_admin INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Search logs table
    c.execute('''
        CREATE TABLE IF NOT EXISTS search_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            filename TEXT,
            scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            result TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Daily search limits
    c.execute('''
        CREATE TABLE IF NOT EXISTS daily_searches (
            user_id INTEGER,
            search_date DATE,
            count INTEGER DEFAULT 0,
            PRIMARY KEY (user_id, search_date),
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Create admin user if not exists
    admin_password = hashlib.sha256('admin123'.encode()).hexdigest()
    try:
        c.execute('INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)',
                  ('admin', admin_password, 1))
        print("✅ Admin user created")
    except sqlite3.IntegrityError:
        print("ℹ️ Admin user already exists")
    
    conn.commit()
    conn.close()
    print("✅ Database initialized")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# ===== AUTH DECORATORS =====
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Please login first'}), 401
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Please login first'}), 401
        conn = get_db()
        user = conn.execute('SELECT is_admin FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        conn.close()
        if not user or not user['is_admin']:
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated_function

# ===== AUTH ENDPOINTS =====
@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid request data'}), 400
            
        username = data.get('username', '').strip()
        password = data.get('password', '')
        email = data.get('email', '').strip()
        
        if not username or not password:
            return jsonify({'error': 'Username and password required'}), 400
        
        if len(password) < 6:
            return jsonify({'error': 'Password must be at least 6 characters'}), 400
        
        hashed = hashlib.sha256(password.encode()).hexdigest()
        
        conn = get_db()
        try:
            conn.execute('INSERT INTO users (username, password, email) VALUES (?, ?, ?)',
                         (username, hashed, email))
            conn.commit()
            conn.close()
            return jsonify({'success': True, 'message': 'Registration successful!'})
        except sqlite3.IntegrityError:
            conn.close()
            return jsonify({'error': 'Username already exists'}), 400
    except Exception as e:
        print(f"Registration error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid request data'}), 400
            
        username = data.get('username', '').strip()
        password = data.get('password', '')
        
        if not username or not password:
            return jsonify({'error': 'Username and password required'}), 400
        
        hashed = hashlib.sha256(password.encode()).hexdigest()
        conn = get_db()
        user = conn.execute('SELECT id, username, is_admin FROM users WHERE username = ? AND password = ?',
                            (username, hashed)).fetchone()
        conn.close()
        
        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['is_admin'] = bool(user['is_admin'])
            print(f"✅ User logged in: {username}")
            return jsonify({
                'success': True,
                'user': {
                    'id': user['id'],
                    'username': user['username'],
                    'is_admin': bool(user['is_admin'])
                }
            })
        
        return jsonify({'error': 'Invalid credentials'}), 401
    except Exception as e:
        print(f"Login error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'success': True})

@app.route('/api/user', methods=['GET'])
def get_user():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    conn = get_db()
    user = conn.execute('SELECT id, username, email, is_admin FROM users WHERE id = ?',
                        (session['user_id'],)).fetchone()
    conn.close()
    
    if user:
        return jsonify({
            'id': user['id'],
            'username': user['username'],
            'email': user['email'],
            'is_admin': bool(user['is_admin'])
        })
    return jsonify({'error': 'User not found'}), 404

@app.route('/api/remaining-searches', methods=['GET'])
@login_required
def get_remaining():
    try:
        user_id = session['user_id']
        conn = get_db()
        user = conn.execute('SELECT is_admin FROM users WHERE id = ?', (user_id,)).fetchone()
        conn.close()
        
        if user and user['is_admin']:
            return jsonify({'remaining': float('inf')})
        
        today = datetime.now().date().isoformat()
        conn = get_db()
        record = conn.execute('SELECT count FROM daily_searches WHERE user_id = ? AND search_date = ?',
                              (user_id, today)).fetchone()
        conn.close()
        
        used = record['count'] if record else 0
        limit = 10
        remaining = max(0, limit - used)
        return jsonify({'remaining': remaining})
    except Exception as e:
        print(f"Remaining searches error: {str(e)}")
        return jsonify({'error': str(e)}), 500

def increment_search_count(user_id):
    today = datetime.now().date().isoformat()
    conn = get_db()
    conn.execute('''
        INSERT INTO daily_searches (user_id, search_date, count) 
        VALUES (?, ?, 1)
        ON CONFLICT(user_id, search_date) 
        DO UPDATE SET count = count + 1
    ''', (user_id, today))
    conn.commit()
    conn.close()

# ===== FILE ANALYSIS =====
def analyze_file_general(file_content, filename):
    analysis = {
        'file_info': {},
        'hashes': {},
        'entropy': 0,
        'file_type': 'Unknown',
        'is_pe': False
    }
    
    md5 = hashlib.md5(file_content).hexdigest()
    sha1 = hashlib.sha1(file_content).hexdigest()
    sha256 = hashlib.sha256(file_content).hexdigest()
    
    analysis['hashes'] = {
        'md5': md5,
        'sha1': sha1,
        'sha256': sha256
    }
    
    file_size = len(file_content)
    analysis['file_info']['file_size'] = file_size
    analysis['file_info']['file_size_human'] = f"{file_size / 1024:.2f} KB" if file_size < 1048576 else f"{file_size / 1048576:.2f} MB"
    
    if file_content:
        entropy = 0
        for i in range(256):
            count = file_content.count(i)
            if count > 0:
                p = count / file_size
                entropy -= p * math.log2(p)
        analysis['entropy'] = round(entropy, 4)
    
    ext = filename.lower().split('.')[-1] if '.' in filename else ''
    analysis['file_type'] = ext.upper() if ext else 'Unknown'
    
    if file_content[:2] == b'MZ':
        analysis['is_pe'] = True
        analysis['file_type'] = 'PE (Windows Executable)'
    
    return analysis

# ===== SCAN ENDPOINT =====
@app.route('/api/scan', methods=['POST'])
@login_required
def scan_file():
    try:
        user_id = session['user_id']
        
        # Check remaining searches
        conn = get_db()
        user = conn.execute('SELECT is_admin FROM users WHERE id = ?', (user_id,)).fetchone()
        conn.close()
        
        if not user or not user['is_admin']:
            today = datetime.now().date().isoformat()
            conn = get_db()
            record = conn.execute('SELECT count FROM daily_searches WHERE user_id = ? AND search_date = ?',
                                  (user_id, today)).fetchone()
            conn.close()
            used = record['count'] if record else 0
            if used >= 10:
                return jsonify({'error': 'Daily search limit reached (10/day). Try again tomorrow.'}), 429
        
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        content = file.read()
        filename = file.filename
        sha256 = hashlib.sha256(content).hexdigest()
        
        # Run analysis
        file_analysis = analyze_file_general(content, filename)
        
        # Increment search count
        if not user or not user['is_admin']:
            increment_search_count(user_id)
        
        # Get remaining searches
        if user and user['is_admin']:
            remaining = float('inf')
        else:
            today = datetime.now().date().isoformat()
            conn = get_db()
            record = conn.execute('SELECT count FROM daily_searches WHERE user_id = ? AND search_date = ?',
                                  (user_id, today)).fetchone()
            conn.close()
            used = record['count'] if record else 0
            remaining = max(0, 10 - used)
        
        result_data = {
            'success': True,
            'filename': filename,
            'sha256': sha256,
            'file_analysis': file_analysis,
            'remaining_searches': remaining
        }
        
        return jsonify(result_data)
        
    except Exception as e:
        print(f"Scan error: {str(e)}")
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

# ===== FRONTEND ROUTES =====
@app.route('/')
def serve_index():
    try:
        return send_from_directory('..', 'index.html')
    except Exception as e:
        return f"Error: {str(e)}", 500

@app.route('/<path:path>')
def serve_static(path):
    try:
        return send_from_directory('..', path)
    except Exception as e:
        return f"Error: {str(e)}", 404

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok', 'message': 'BOUGG backend is running!'})

# ===== INIT DATABASE =====
init_db()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f"🛡️ BOUGG Auth Backend running on port {port}")
    app.run(host='0.0.0.0', port=port, debug=True)
