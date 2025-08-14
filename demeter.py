from flask import Flask, request, render_template, jsonify, session, redirect, url_for, flash
from datetime import datetime
import json
import hashlib
import time
import threading
import sqlite3
import logging
from logging.handlers import RotatingFileHandler
import os
import secrets
from functools import wraps

# --- Initial Configuration ---
# Create logs directory if it doesn't exist
if not os.path.exists('logs'):
    os.makedirs('logs')

# Configure logging
logging.basicConfig(level=logging.INFO)
handler = RotatingFileHandler('logs/webhook.log', maxBytes=10000000, backupCount=5)
handler.setFormatter(logging.Formatter(
    '[%(asctime)s] %(levelname)s in %(module)s: %(message)s'
))

# Initialize Flask App
app = Flask(__name__)
app.logger.addHandler(handler)

# Secure secret key for session management
app.secret_key = secrets.token_hex(16)


# --- Database ---
def init_db():
    """Initializes the SQLite database and necessary tables."""
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
        conn.commit()

init_db()

# --- Cache & Cleanup ---
webhook_cache = []
MAX_CACHE_SIZE = 50

def load_initial_cache():
    """Loads the last webhooks from the database into the cache on startup."""
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
                except (json.JSONDecodeError, TypeError):
                    entry['headers'] = {'raw_content': str(entry['headers'])}

                try:
                    entry['data'] = json.loads(entry['data'])
                except (json.JSONDecodeError, TypeError):
                    entry['data'] = {'raw_content': str(entry['data'])}

                temp_cache.append(entry)
            
            # Reverse to maintain newest-first order for cache
            webhook_cache = temp_cache[::-1] 
            app.logger.info(f"Successfully loaded {len(webhook_cache)} recent webhooks into cache.")
    except Exception as e:
        app.logger.error(f"Failed to load initial cache from database: {e}")

load_initial_cache()

def cleanup_old_records():
    """Periodically deletes webhook records older than 30 days."""
    while True:
        time.sleep(86400) # Check every 24 hours
        try:
            with sqlite3.connect('webhooks.db') as conn:
                conn.execute("DELETE FROM webhooks WHERE datetime(timestamp) < datetime('now', '-30 days')")
                conn.commit()
                app.logger.info("Successfully cleaned up old webhook records.")
        except Exception as e:
            app.logger.error(f"Error during database cleanup: {e}")

cleanup_thread = threading.Thread(target=cleanup_old_records, daemon=True)
cleanup_thread.start()

# --- Decorators & Helper Functions ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            flash('You must be logged in to view this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def generate_webhook_id(data):
    content = f"{datetime.now().isoformat()}{str(data)}{secrets.token_hex(4)}"
    return hashlib.sha256(content.encode()).hexdigest()[:12]

def process_and_store_webhook():
    try:
        data = {}
        if request.is_json:
            data = request.get_json(silent=True)
            if data is None: 
                data = {'raw_body': request.get_data(as_text=True)}
        elif request.form:
            data = request.form.to_dict()
        elif request.get_data():
            data = {'raw_body': request.get_data(as_text=True)}
        
        if request.args:
            if data:
                data.setdefault('query_params', {}).update(request.args.to_dict())
            else:
                data = request.args.to_dict()

        webhook_id = generate_webhook_id(data)
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        headers_dict = dict(request.headers)

        webhook_entry = {
            'id': webhook_id, 
            'timestamp': timestamp, 
            'method': request.method,
            'path': request.path, 
            'headers': headers_dict, 
            'data': data,
            'ip_address': request.remote_addr, 
            'status': 'success'
        }
        
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
            conn.commit()

        webhook_cache.insert(0, webhook_entry)
        if len(webhook_cache) > MAX_CACHE_SIZE:
            webhook_cache.pop()
        
        app.logger.info(f'Webhook received: {webhook_id} from {request.remote_addr} on path {request.path}')
        return jsonify({'status': 'success', 'message': 'Webhook received', 'webhook_id': webhook_id})
    except Exception as e:
        error_id = secrets.token_hex(4)
        app.logger.error(f'Error processing webhook {error_id}: {e}', exc_info=True)
        return jsonify({'status': 'error', 'message': f'Internal Server Error', 'error_id': error_id}), 500

# --- Application Routes (Specific routes first) ---
@app.route('/')
def index_redirect():
    """Redirects the root URL ('/') to the login page."""
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'logged_in' in session:
        return redirect(url_for('dashboard'))
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if not username or not password:
            error = 'Username and password are required.'
        else:
            with sqlite3.connect('webhooks.db') as conn:
                password_hash = hashlib.sha256(password.encode()).hexdigest()
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password_hash))
                user = cursor.fetchone()
                if user:
                    session['logged_in'] = True
                    session['username'] = username
                    app.logger.info(f'User {username} logged in successfully.')
                    return redirect(url_for('dashboard'))
                else:
                    error = 'Invalid username or password.'
    return render_template('login.html', error=error)

@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash('You have been successfully logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('index.html')

# --- API Endpoints ---
@app.route('/get-webhooks')
@login_required
def get_webhooks():
    """API to get webhook data called by JavaScript."""
    return jsonify(webhook_cache)

@app.route('/clear', methods=['POST'])
@login_required
def clear_history():
    """API to clear history called by JavaScript."""
    try:
        webhook_cache.clear()
        with sqlite3.connect('webhooks.db') as conn:
            conn.execute('DELETE FROM webhooks')
            conn.commit()
        app.logger.info(f"Webhook history cleared by user {session.get('username')}.")
        return jsonify({'status': 'success', 'message': 'History cleared'})
    except Exception as e:
        app.logger.error(f'Error clearing history: {e}', exc_info=True)
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/stats')
@login_required
def get_stats():
    """API to get webhook statistics."""
    try:
        with sqlite3.connect('webhooks.db') as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            total = cursor.execute('SELECT COUNT(*) FROM webhooks').fetchone()[0]
            methods_raw = cursor.execute('SELECT method, COUNT(*) as count FROM webhooks GROUP BY method').fetchall()
            methods = {row['method']: row['count'] for row in methods_raw}
            
            status_counts_raw = cursor.execute("SELECT status, COUNT(*) as count FROM webhooks GROUP BY status").fetchall()
            status_counts = {row['status']: row['count'] for row in status_counts_raw}
            
            return jsonify({
                'total_webhooks': total, 
                'methods': methods, 
                'status_counts': status_counts
            })
    except Exception as e:
        app.logger.error(f'Error getting stats: {e}', exc_info=True)
        return jsonify({'status': 'error', 'message': str(e)}), 500

# --- Webhook Catcher Route (MUST BE LAST) ---
# This "catch-all" route handles any path not matched by the specific routes above.
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
def catch_all_webhooks(path):
    if path == 'favicon.ico':
        return '', 204
    return process_and_store_webhook()


# --- Error Handlers ---
@app.errorhandler(404)
def page_not_found(e):
    # For a non-existent page, render a proper 404 page.
    app.logger.warning(f"404 Not Found for path: {request.path}")
    # Note: You need to create a '404.html' file in your templates/ folder.
    return render_template('404.html'), 404

if __name__ == '__main__':
    app.run(debug=True, port=13370, host='0.0.0.0')
