import json
import os

from flask import Flask, render_template, request, redirect, url_for, send_file, jsonify
from flask_socketio import SocketIO
from core.database import db, ThreatRecord

from core.log_parser import parse_log_file, parse_log_text
from core.mapreduce import run_all_jobs
from report_generator import generate_report
from core.threat_intel import enrich_threats

UPLOAD_FOLDER = 'uploads'
RESULTS_FILE = 'results.json'
test_server = None

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///threats.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

with app.app_context():
    db.create_all()

socketio = SocketIO(app, cors_allowed_origins="*")

def load_results():
    if not os.path.exists(RESULTS_FILE):
        return None
    with open(RESULTS_FILE) as fh:
        return json.load(fh)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    logs = []
    logfile = request.files.get('logfile')
    if logfile and logfile.filename:
        path = os.path.join(UPLOAD_FOLDER, logfile.filename)
        logfile.save(path)
        logs = parse_log_file(path)

    if not logs:
        log_path = request.form.get('log_path', '').strip()
        if log_path and os.path.exists(log_path):
            logs = parse_log_file(log_path)

    if not logs:
        raw_logs = request.form.get('raw_logs', '').strip()
        if raw_logs:
            logs = parse_log_text(raw_logs)

    if not logs:
        return redirect(url_for('index'))

    results = run_all_jobs(logs)
    results = enrich_threats(results)

    for ip, count in results.get('brute_force', {}).get('flagged', {}).items():
        db.session.add(ThreatRecord(ip_address=ip, threat_type='Brute Force', severity='High', details=f'{count} attempts'))
    for ip, urls in results.get('sqli', {}).get('flagged', {}).items():
        db.session.add(ThreatRecord(ip_address=ip, threat_type='SQL Injection', severity='Critical', details=f'{len(urls)} payloads'))
    for ip, rpm in results.get('ddos', {}).get('flagged', {}).items():
        db.session.add(ThreatRecord(ip_address=ip, threat_type='DDoS', severity='High', details=f'Peak {rpm} req/min'))
    for ip, paths in results.get('scanner', {}).get('flagged', {}).items():
        db.session.add(ThreatRecord(ip_address=ip, threat_type='Scanner', severity='Medium', details=f'{len(paths)} paths scanned'))
    db.session.commit()

    with open(RESULTS_FILE, 'w') as fh:
        json.dump(results, fh, default=str)

    return redirect(url_for('dashboard'))

@app.route('/dashboard')
def dashboard():
    results = load_results()
    if not results:
        return redirect(url_for('index'))
    return render_template('dashboard.html', results=results)

@app.route('/history')
def history():
    records = ThreatRecord.query.order_by(ThreatRecord.timestamp.desc()).all()
    return render_template('history.html', records=records)

@app.route('/report')
def report():
    results = load_results()
    if not results:
        return redirect(url_for('index'))
    path = generate_report(results)
    return send_file(path, as_attachment=True, download_name='incident_report.pdf')

@app.route('/realtime')
def realtime():
    return render_template('realtime_dashboard.html')

@app.route('/api/stream', methods=['POST'])
def stream_log():
    data = request.json
    if data and 'log' in data:
        log_line = data['log']

        parsed = parse_log_text(log_line)
        enriched_data = {}
        if parsed:
            results = run_all_jobs(parsed)
            results = enrich_threats(results)
            enriched_data = results

            for ip, count in results.get('brute_force', {}).get('flagged', {}).items():
                db.session.add(ThreatRecord(ip_address=ip, threat_type='Brute Force', severity='High', details=f'{count} attempts'))
            for ip, urls in results.get('sqli', {}).get('flagged', {}).items():
                db.session.add(ThreatRecord(ip_address=ip, threat_type='SQL Injection', severity='Critical', details=f'{len(urls)} payloads'))
            for ip, rpm in results.get('ddos', {}).get('flagged', {}).items():
                db.session.add(ThreatRecord(ip_address=ip, threat_type='DDoS', severity='High', details=f'Peak {rpm} req/min'))
            for ip, paths in results.get('scanner', {}).get('flagged', {}).items():
                db.session.add(ThreatRecord(ip_address=ip, threat_type='Scanner', severity='Medium', details=f'{len(paths)} paths scanned'))
            db.session.commit()

        socketio.emit('new_log', {
            'log': log_line,
            'enriched': enriched_data
        })
        return jsonify({'status': 'streamed'}), 200
    return jsonify({'error': 'no log provided'}), 400

@app.route('/api/poll_logs')
def poll_logs():
    log_path = request.args.get('path', '')
    position = int(request.args.get('pos', 0))

    if not log_path:
        return jsonify({'error': 'No path provided'}), 400

    if not os.path.exists(log_path):
        return jsonify({'error': f'File not found: {log_path}'}), 400

    try:
        with open(log_path, 'r') as f:
            f.seek(position)
            new_lines = []
            for line in f:
                stripped = line.strip()
                if stripped:
                    new_lines.append(stripped)
            new_position = f.tell()

            results = {}
            if new_lines:
                parsed = parse_log_text('\n'.join(new_lines))
                if parsed:
                    results = run_all_jobs(parsed)
                    results = enrich_threats(results)

                    for ip, count in results.get('brute_force', {}).get('flagged', {}).items():
                        db.session.add(ThreatRecord(ip_address=ip, threat_type='Brute Force', severity='High', details=f'{count} attempts'))
                    for ip, urls in results.get('sqli', {}).get('flagged', {}).items():
                        db.session.add(ThreatRecord(ip_address=ip, threat_type='SQL Injection', severity='Critical', details=f'{len(urls)} payloads'))
                    for ip, rpm in results.get('ddos', {}).get('flagged', {}).items():
                        db.session.add(ThreatRecord(ip_address=ip, threat_type='DDoS', severity='High', details=f'Peak {rpm} req/min'))
                    for ip, paths in results.get('scanner', {}).get('flagged', {}).items():
                        db.session.add(ThreatRecord(ip_address=ip, threat_type='Scanner', severity='Medium', details=f'{len(paths)} paths scanned'))
                    db.session.commit()

                    for log_line in new_lines[-5:]:
                        socketio.emit('new_log', {
                            'log': log_line,
                            'enriched': results
                        })

            return json.loads(json.dumps({
                'logs': new_lines,
                'position': new_position,
                'results': results
            }, default=str))
    except PermissionError:
        return jsonify({'error': 'Permission denied. Try a different path or run with sudo'}), 403
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/generate_test_traffic', methods=['POST'])
def generate_test_traffic():
    import threading
    import http.server
    import socketserver
    from datetime import datetime
    import random
    import urllib.request
    import time

    log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'sample_logs')
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, 'access.log')

    open(log_file, 'w').close()

    class LoggingHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            status = 200
            if self.path in ['/admin', '/wp-admin', '/phpmyadmin', '/.env']:
                status = 404
            self.send_response(status)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b'OK')

        def log_message(self, format, *args):
            ips = ['192.168.1.100', '10.0.0.50', '172.16.0.25', '45.141.84.120', '89.248.167.131']
            paths = ['/', '/index.html', '/api/users', '/login', '/admin', '/about', '/products']
            attack_paths = ['/wp-admin', '/phpmyadmin', '/.env', '/etc/passwd', '/admin.php', '/config.php']
            user_agents = ['Mozilla/5.0 (Windows NT 10.0)', 'curl/7.88.1', 'python-requests/2.31.0', 'Nikto/2.1.6']

            ua = random.choice(user_agents)
            if 'Nikto' in ua:
                path = random.choice(attack_paths)
                status = random.choice([200, 403, 404])
            else:
                path = random.choice(paths)
                status = 200
            ip = random.choice(ips)

            log_entry = f'{ip} - - [{datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET {path} HTTP/1.1" {status} 1024 "-" "{ua}"\n'
            with open(log_file, 'a') as f:
                f.write(log_entry)

    global test_server
    if test_server is not None:
        try:
            test_server.server_close()
        except Exception:
            pass

    test_server = None
    test_port = 5555
    for port in range(5555, 5570):
        try:
            test_server = socketserver.TCPServer(("", port), LoggingHTTPRequestHandler)
            test_port = port
            break
        except Exception:
            continue

    if test_server is None:
        return jsonify({'error': 'Could not find available port'}), 500

    thread = threading.Thread(target=test_server.serve_forever, daemon=True)
    thread.start()

    test_urls = ['/', '/index.html', '/api/users', '/login', '/admin', '/about', '/products', '/wp-admin', '/phpmyadmin', '/.env']

    for url in test_urls:
        try:
            urllib.request.urlopen(f'http://localhost:{test_port}{url}', timeout=2)
        except Exception:
            pass
        time.sleep(0.05)

    def continuous_traffic():
        while True:
            for _ in range(random.randint(3, 8)):
                url = random.choice(test_urls)
                try:
                    urllib.request.urlopen(f'http://localhost:{test_port}{url}', timeout=2)
                except Exception:
                    pass
            time.sleep(random.uniform(0.5, 2.0))

    bg_thread = threading.Thread(target=continuous_traffic, daemon=True)
    bg_thread.start()

    return jsonify({
        'path': log_file,
        'port': test_port,
        'status': f'Server running on port {test_port}'
    })


if __name__ == '__main__':
    socketio.run(app, debug=False, allow_unsafe_werkzeug=True, port=5002, use_reloader=False)
