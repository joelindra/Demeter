from flask import Flask, request, render_template, jsonify, session, redirect, url_for, flash
from datetime import datetime
import json
import hashlib
import time
import threading
import sqlite3
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging
from logging.handlers import RotatingFileHandler
import os
import secrets

# Konfigurasi logging
if not os.path.exists('logs'):
    os.makedirs('logs')

logging.basicConfig(level=logging.INFO)
handler = RotatingFileHandler('logs/webhook.log', maxBytes=10000000, backupCount=5)
handler.setFormatter(logging.Formatter(
    '[%(asctime)s] %(levelname)s in %(module)s: %(message)s'
))

app = Flask(__name__)
app.logger.addHandler(handler)

# Secret key untuk session
app.secret_key = secrets.token_hex(16)

# Rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Database setup
def init_db():
    with sqlite3.connect('webhooks.db') as conn:
        # Tabel untuk webhook
        conn.execute('''
            CREATE TABLE IF NOT EXISTS webhooks
            (id TEXT PRIMARY KEY,
             timestamp TEXT,
             method TEXT,
             path TEXT,
             headers TEXT,
             data TEXT,
             ip_address TEXT,
             status TEXT)
        ''')
        
        # Tabel untuk user
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users
            (id INTEGER PRIMARY KEY AUTOINCREMENT,
             username TEXT UNIQUE,
             password TEXT,
             created_at TEXT)
        ''')
        
        # Cek apakah sudah ada user admin
        admin_exists = conn.execute('SELECT COUNT(*) FROM users WHERE username = ?', ('anonre',)).fetchone()[0]
        if admin_exists == 0:
            # Buat user admin default dengan password "admin123"
            password_hash = hashlib.sha256("hackerbiasa123".encode()).hexdigest()
            conn.execute('''
                INSERT INTO users (username, password, created_at)
                VALUES (?, ?, ?)
            ''', ('anonre', password_hash, datetime.now().strftime('%Y-%m-%d %H:%M:%S')))

init_db()

# In-memory cache untuk webhook terakhir
webhook_cache = []
MAX_CACHE_SIZE = 50

def cleanup_old_records():
    """Membersihkan record lama dari database secara periodik"""
    while True:
        try:
            with sqlite3.connect('webhooks.db') as conn:
                # Hapus record lebih dari 30 hari
                conn.execute('''
                    DELETE FROM webhooks 
                    WHERE datetime(timestamp) < datetime('now', '-30 days')
                ''')
            time.sleep(86400)  # Jalankan setiap 24 jam
        except Exception as e:
            app.logger.error(f"Error in cleanup: {str(e)}")

# Mulai thread cleanup
cleanup_thread = threading.Thread(target=cleanup_old_records, daemon=True)
cleanup_thread.start()

def generate_webhook_id(data):
    """Menghasilkan ID unik untuk setiap webhook"""
    timestamp = datetime.now().isoformat()
    content = f"{timestamp}{str(data)}"
    return hashlib.sha256(content.encode()).hexdigest()[:12]

# Login required decorator
def login_required(f):
    from functools import wraps
    
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session or not session['logged_in']:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            error = 'Username dan password diperlukan'
        else:
            with sqlite3.connect('webhooks.db') as conn:
                password_hash = hashlib.sha256(password.encode()).hexdigest()
                user = conn.execute(
                    'SELECT * FROM users WHERE username = ? AND password = ?', 
                    (username, password_hash)
                ).fetchone()
                
                if user:
                    session['logged_in'] = True
                    session['username'] = username
                    app.logger.info(f'User {username} logged in')
                    return redirect(url_for('home'))
                else:
                    error = 'Username atau password salah'
    
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/')
@login_required
def home():
    return render_template('index.html', webhooks=webhook_cache)

@app.route('/webhook', methods=['POST', 'GET', 'PUT', 'DELETE'])
@limiter.limit("100/minute")
def webhook():
    try:
        # Mendapatkan data dari request
        if request.is_json:
            data = request.get_json()
        else:
            data = {
                'raw_data': request.get_data(as_text=True),
                'form_data': request.form.to_dict(),
                'args': request.args.to_dict()
            }
        
        # Membuat entry webhook baru
        webhook_id = generate_webhook_id(data)
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        webhook_entry = {
            'id': webhook_id,
            'timestamp': timestamp,
            'headers': dict(request.headers),
            'data': data,
            'method': request.method,
            'path': request.path,
            'ip_address': request.remote_addr,
            'status': 'success'
        }
        
        # Simpan ke database
        with sqlite3.connect('webhooks.db') as conn:
            conn.execute('''
                INSERT INTO webhooks (id, timestamp, method, path, headers, data, ip_address, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                webhook_id,
                timestamp,
                request.method,
                request.path,
                json.dumps(dict(request.headers)),
                json.dumps(data),
                request.remote_addr,
                'success'
            ))

        # Update cache
        webhook_cache.insert(0, webhook_entry)
        if len(webhook_cache) > MAX_CACHE_SIZE:
            webhook_cache.pop()
        
        # Log webhook
        app.logger.info(f'Webhook received: {webhook_id} from {request.remote_addr}')
        
        return jsonify({
            'status': 'success',
            'message': 'Webhook received',
            'webhook_id': webhook_id
        })

    except Exception as e:
        error_id = hashlib.sha256(str(time.time()).encode()).hexdigest()[:8]
        app.logger.error(f'Error processing webhook {error_id}: {str(e)}')
        
        return jsonify({
            'status': 'error',
            'message': f'Error processing webhook: {str(e)}',
            'error_id': error_id
        }), 400

@app.route('/get-webhooks')
@login_required
def get_webhooks():
    try:
        search = request.args.get('search', '').lower()
        if search:
            filtered_webhooks = [
                webhook for webhook in webhook_cache
                if search in json.dumps(webhook).lower()
            ]
            return jsonify(filtered_webhooks)
        return jsonify(webhook_cache)
    except Exception as e:
        app.logger.error(f'Error getting webhooks: {str(e)}')
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/clear', methods=['POST'])
@login_required
def clear_history():
    try:
        webhook_cache.clear()
        with sqlite3.connect('webhooks.db') as conn:
            conn.execute('DELETE FROM webhooks')
        return jsonify({'status': 'success', 'message': 'History cleared'})
    except Exception as e:
        app.logger.error(f'Error clearing history: {str(e)}')
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/stats')
@login_required
def get_stats():
    try:
        with sqlite3.connect('webhooks.db') as conn:
            cursor = conn.cursor()
            
            # Total webhooks
            total = cursor.execute('SELECT COUNT(*) FROM webhooks').fetchone()[0]
            
            # Webhooks per method
            methods = cursor.execute('''
                SELECT method, COUNT(*) as count 
                FROM webhooks 
                GROUP BY method
            ''').fetchall()
            
            # Success rate
            success_rate = cursor.execute('''
                SELECT (
                    CAST(SUM(CASE WHEN status = 'success' THEN 1 ELSE 0 END) AS FLOAT) / 
                    COUNT(*) * 100
                ) as success_rate 
                FROM webhooks
            ''').fetchone()[0]
            
            return jsonify({
                'total_webhooks': total,
                'methods': dict(methods),
                'success_rate': round(success_rate, 2) if success_rate else 0
            })
    except Exception as e:
        app.logger.error(f'Error getting stats: {str(e)}')
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({
        'status': 'error',
        'message': 'Rate limit exceeded',
        'retry_after': int(e.retry_after)
    }), 429

if __name__ == '__main__':
    app.run(debug=True, port=5000, host='0.0.0.0')