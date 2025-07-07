from flask import Flask, request, render_template, jsonify, session, redirect, url_for, flash
from datetime import datetime
import json
import hashlib
import time
import threading
import sqlite3
# Removed Flask-Limiter imports as requested
# from flask_limiter import Limiter
# from flask_limiter.util import get_remote_address
import logging
from logging.handlers import RotatingFileHandler
import os
import secrets
from functools import wraps

# --- Konfigurasi Awal ---
# Membuat direktori logs jika belum ada
if not os.path.exists('logs'):
    os.makedirs('logs')

# Konfigurasi logging
logging.basicConfig(level=logging.INFO)
handler = RotatingFileHandler('logs/webhook.log', maxBytes=10000000, backupCount=5)
handler.setFormatter(logging.Formatter(
    '[%(asctime)s] %(levelname)s in %(module)s: %(message)s'
))

# Inisialisasi Aplikasi Flask
app = Flask(__name__)
app.logger.addHandler(handler)

# Kunci rahasia untuk session management yang aman
app.secret_key = secrets.token_hex(16)

# Removed Flask-Limiter initialization as requested
# limiter = Limiter(
#     app=app,
#     key_func=get_remote_address,
#     default_limits=["200 per day", "50 per hour"]
# )

# --- Database ---
def init_db():
    """Inisialisasi database SQLite dan tabel yang diperlukan."""
    with sqlite3.connect('webhooks.db') as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS webhooks
            (id TEXT PRIMARY KEY, timestamp TEXT, method TEXT, path TEXT,
             headers TEXT, data TEXT, ip_address TEXT, status TEXT)
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users
            (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
             password TEXT NOT NULL, created_at TEXT)
        ''')
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM users WHERE username = ?', ('anonre',))
        if cursor.fetchone()[0] == 0:
            password_hash = hashlib.sha256("hackerbiasa123".encode()).hexdigest()
            conn.execute(
                'INSERT INTO users (username, password, created_at) VALUES (?, ?, ?)',
                ('anonre', password_hash, datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            )
        conn.commit() # Ensure changes are saved

init_db()

# --- Cache & Cleanup ---
webhook_cache = []
MAX_CACHE_SIZE = 50

def load_initial_cache():
    """Memuat riwayat webhook terakhir dari database ke dalam cache saat aplikasi dimulai."""
    global webhook_cache
    try:
        with sqlite3.connect('webhooks.db') as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM webhooks ORDER BY timestamp DESC LIMIT ?", (MAX_CACHE_SIZE,))
            rows = cursor.fetchall()
            
            temp_cache = []
            for row in rows:
                entry = dict(row)
                try:
                    entry['headers'] = json.loads(entry['headers'])
                    entry['data'] = json.loads(entry['data'])
                except (json.JSONDecodeError, TypeError):
                    app.logger.warning(f"Could not parse JSON for webhook ID {entry.get('id')}. Data might be raw string.")
                    # Keep data as string if JSON parsing fails
                    if isinstance(entry['data'], str):
                        try:
                            # Attempt to parse as a simple string if not JSON
                            entry['data'] = entry['data'] 
                        except Exception:
                            entry['data'] = {'raw_content': entry['data']} # Fallback to dict
                    else:
                        entry['data'] = {'raw_content': str(entry['data'])} # Ensure it's storable
                    
                    if isinstance(entry['headers'], str):
                        try:
                            entry['headers'] = json.loads(entry['headers'])
                        except json.JSONDecodeError:
                            entry['headers'] = {'raw_headers': entry['headers']} # Fallback to dict
                    else:
                        entry['headers'] = {'raw_headers': str(entry['headers'])} # Ensure it's storable

                temp_cache.append(entry)
            
            # Reverse to maintain newest-first order for cache
            webhook_cache = temp_cache[::-1] 
            app.logger.info(f"Successfully loaded {len(webhook_cache)} recent webhooks into cache.")
    except Exception as e:
        app.logger.error(f"Failed to load initial cache from database: {e}")

load_initial_cache()

def cleanup_old_records():
    """Menghapus record webhook yang lebih tua dari 30 hari secara periodik."""
    while True:
        time.sleep(86400) # Check every 24 hours
        try:
            with sqlite3.connect('webhooks.db') as conn:
                conn.execute("DELETE FROM webhooks WHERE datetime(timestamp) < datetime('now', '-30 days')")
                conn.commit() # Commit changes to the database
                app.logger.info("Successfully cleaned up old webhook records.")
        except Exception as e:
            app.logger.error(f"Error during database cleanup: {e}")

cleanup_thread = threading.Thread(target=cleanup_old_records, daemon=True)
cleanup_thread.start()

# --- Decorator & Fungsi Helper ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            flash('Anda harus login untuk mengakses halaman ini.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def generate_webhook_id(data):
    # Use a combination of timestamp and a hash of the data for a unique ID
    content = f"{datetime.now().isoformat()}{str(data)}{secrets.token_hex(4)}"
    return hashlib.sha256(content.encode()).hexdigest()[:12]

def process_and_store_webhook():
    try:
        # Attempt to get JSON data, fallback to form data or raw data
        if request.is_json:
            data = request.get_json(silent=True) # silent=True returns None on parse error
            if data is None: # If JSON parsing failed, try other methods
                data = {
                    'raw_data': request.get_data(as_text=True),
                    'form_data': request.form.to_dict(),
                    'args': request.args.to_dict()
                }
        else:
            data = {
                'raw_data': request.get_data(as_text=True),
                'form_data': request.form.to_dict(),
                'args': request.args.to_dict()
            }
        
        webhook_id = generate_webhook_id(data)
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Ensure headers are a dict, not ImmutableMultiDict
        headers_dict = dict(request.headers)

        webhook_entry = {
            'id': webhook_id, 
            'timestamp': timestamp, 
            'method': request.method,
            'path': request.path, 
            'headers': headers_dict, 
            'data': data,
            'ip_address': request.remote_addr, 
            'status': 'success' # Default status
        }
        
        # Check for a status in headers or data (e.g., for analytics)
        if 'X-Status' in headers_dict:
            webhook_entry['status'] = headers_dict['X-Status']
        elif isinstance(data, dict) and 'status' in data:
            webhook_entry['status'] = data['status']

        with sqlite3.connect('webhooks.db') as conn:
            conn.execute(
                '''INSERT INTO webhooks (id, timestamp, method, path, headers, data, ip_address, status)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                (webhook_id, timestamp, request.method, request.path,
                 json.dumps(webhook_entry['headers']), json.dumps(webhook_entry['data']),
                 request.remote_addr, webhook_entry['status'])
            )
            conn.commit() # Commit changes to the database

        # Add to cache (newest first)
        webhook_cache.insert(0, webhook_entry)
        if len(webhook_cache) > MAX_CACHE_SIZE:
            webhook_cache.pop() # Remove oldest if cache exceeds size
        
        app.logger.info(f'Webhook received: {webhook_id} from {request.remote_addr} on path {request.path} (Method: {request.method})')
        return jsonify({'status': 'success', 'message': 'Webhook received', 'webhook_id': webhook_id})
    except Exception as e:
        error_id = hashlib.sha256(str(time.time()).encode()).hexdigest()[:8]
        app.logger.error(f'Error processing webhook {error_id}: {e}', exc_info=True) # Log full traceback
        return jsonify({'status': 'error', 'message': f'Internal Server Error: {e}', 'error_id': error_id}), 500

# --- Rute Aplikasi ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'logged_in' in session:
        return redirect(url_for('dashboard'))
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if not username or not password:
            error = 'Username dan password harus diisi.'
        else:
            with sqlite3.connect('webhooks.db') as conn:
                password_hash = hashlib.sha256(password.encode()).hexdigest()
                user = conn.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password_hash)).fetchone()
                if user:
                    session['logged_in'] = True
                    session['username'] = username
                    app.logger.info(f'User {username} logged in successfully.')
                    return redirect(url_for('dashboard'))
                else:
                    error = 'Username atau password salah.'
    return render_template('login.html', error=error)

@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash('Anda telah berhasil logout.', 'success')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Cukup render template. JavaScript akan menangani pengambilan data.
    return render_template('index.html')

# --- Rute Penampung Webhook ---
@app.route('/', defaults={'path': ''}, methods=['GET', 'POST']) # Hanya GET dan POST
@app.route('/<path:path>', methods=['GET', 'POST']) # Hanya GET dan POST
# Removed @limiter.limit as requested
def catch_all_webhooks(path):
    # Ignore automatic browser requests for favicon.ico
    if path == 'favicon.ico':
        return '', 204  # 204 No Content

    # All GET and POST requests will now be processed and stored as webhooks.
    # The previous condition to ignore GET requests for logging has been removed.
    return process_and_store_webhook()

# --- API Endpoints (disesuaikan dengan frontend baru) ---

@app.route('/get-webhooks')
@login_required
# Removed @limiter.limit as requested
def get_webhooks():
    """API untuk mendapatkan data webhook yang dipanggil oleh JavaScript."""
    return jsonify(webhook_cache)

@app.route('/clear', methods=['POST'])
@login_required
def clear_history():
    """API untuk membersihkan riwayat yang dipanggil oleh JavaScript."""
    try:
        webhook_cache.clear()
        with sqlite3.connect('webhooks.db') as conn:
            conn.execute('DELETE FROM webhooks')
            conn.commit() # Commit changes to the database
        app.logger.info(f"Webhook history cleared by user {session.get('username')}.")
        return jsonify({'status': 'success', 'message': 'History cleared'})
    except Exception as e:
        app.logger.error(f'Error clearing history: {e}', exc_info=True) # Log full traceback
        return jsonify({'status': 'error', 'message': str(e)}), 500

# Endpoint stats ini tidak lagi digunakan oleh frontend baru, tapi kita biarkan saja.
@app.route('/api/stats')
@login_required
def get_stats():
    """API untuk mendapatkan statistik webhook."""
    try:
        with sqlite3.connect('webhooks.db') as conn:
            conn.row_factory = sqlite3.Row # Ensure rows are dict-like
            cursor = conn.cursor()
            total = cursor.execute('SELECT COUNT(*) FROM webhooks').fetchone()[0]
            methods_raw = cursor.execute('SELECT method, COUNT(*) FROM webhooks GROUP BY method').fetchall()
            methods = {row['method']: row['COUNT(*)'] for row in methods_raw} # Convert to dict
            
            cursor.execute("SELECT COUNT(*), SUM(CASE WHEN status = 'success' THEN 1 ELSE 0 END) FROM webhooks")
            total_count, success_count = cursor.fetchone()
            
            success_rate = (success_count / total_count * 100) if total_count > 0 and success_count is not None else 0
            return jsonify({'total_webhooks': total, 'methods': methods, 'success_rate': round(success_rate, 2)})
    except Exception as e:
        app.logger.error(f'Error getting stats: {e}', exc_info=True) # Log full traceback
        return jsonify({'status': 'error', 'message': str(e)}), 500

# Removed @app.errorhandler(429) as rate limiting is removed
# @app.errorhandler(429)
# def ratelimit_handler(e):
#     return jsonify({'status': 'error', 'message': 'Rate limit exceeded', 'details': str(e.description)}), 429

@app.errorhandler(404)
def page_not_found(e):
    # Jika ada yang mencoba mengakses rute API yang salah, arahkan ke dashboard.
    if request.path.startswith('/api/'):
        app.logger.warning(f"API Endpoint not found: {request.path}")
        return jsonify({'status': 'error', 'message': 'Endpoint not found. Check your API routes.'}), 404
    app.logger.info(f"Redirecting 404 for path: {request.path} to dashboard.")
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    # Pastikan Anda menjalankan di port yang tidak terpakai, misal 5001 jika 5000 sibuk.
    app.run(debug=True, port=13370, host='0.0.0.0')
