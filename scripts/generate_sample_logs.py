import os
import random
from datetime import datetime, timedelta, timezone

os.makedirs('sample_logs', exist_ok=True)
NORMAL_IPS = ['203.0.113.1', '203.0.113.2', '203.0.113.3', '203.0.113.4', '198.51.100.1', '198.51.100.2', '198.51.100.3', '198.51.100.4', '8.8.8.8', '1.1.1.1', '9.9.9.9', '208.67.222.222', '77.88.8.1', '208.67.220.220', '76.76.19.19', '94.140.14.14']
NORMAL_UAS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (Android 13; Mobile; rv:109.0) Gecko/113.0 Firefox/113.0',
    'Googlebot/2.1 (+http://www.google.com/bot.html)'
]
NORMAL_URLS = ['/index.html', '/about', '/contact', '/products', '/blog', '/blog/post-1', '/blog/post-2', '/pricing', '/faq', '/api/users', '/api/products', '/api/search?q=laptop', '/static/style.css', '/static/app.js', '/favicon.ico', '/sitemap.xml', '/login', '/register', '/profile', '/dashboard']
BRUTE_IP = '5.188.206.14'
SQLI_IP = '194.165.16.11'
DDOS_IPS = ['45.141.84.120', '185.220.101.47', '171.25.193.20']
SCAN_IP = '89.248.167.131'
SQLI_PAYLOADS = [
    "/login?user=admin%27%20OR%20%271%27=%271%27--&pass=x",
    "/search?q=1%20UNION%20SELECT%20username,password%20FROM%20users--",
    "/api/items?id=1;DROP%20TABLE%20products--",
    "/products?cat=1%20AND%20CAST((SELECT%20version())%20AS%20int)--",
    "/login?user=1%27%20AND%20SLEEP(5)--&pass=x",
    "/api/user?id=1%20OR%201=1",
    "/search?query=%27;%20INSERT%20INTO%20admins%20VALUES(%27hacked%27,%27pass%27)--"
]
SCANNER_PATHS_LIST = ['/.env', '/wp-admin', '/wp-admin/admin-ajax.php', '/phpmyadmin', '/phpmyadmin/index.php', '/admin', '/admin/login', '/config.php', '/.git/HEAD', '/backup.sql', '/database.sqlite', '/server.xml', '/etc/passwd', '/../../../etc/shadow', '/actuator/env', '/.htaccess', '/robots.txt', '/admin/dashboard', '/wp-login.php', '/xmlrpc.php', '/api/v1/admin/users', '/console', '/manager/html']
BASE_TIME = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=24)

def make_entry(ip, method, url, status, ua=None, size=None, offset_sec=None):
    offset = offset_sec if offset_sec is not None else random.randint(0, 86400)
    ts = BASE_TIME + timedelta(seconds=offset)
    return f"{ip} - - [{ts.strftime('%d/%b/%Y:%H:%M:%S +0000')}] \"{method} {url} HTTP/1.1\" {status} {size or random.randint(200,12000)} \"-\" \"{ua or random.choice(NORMAL_UAS)}\""

lines = []
for _ in range(2100):
    ip = random.choice(NORMAL_IPS)
    url = random.choice(NORMAL_URLS)
    st = random.choices([200, 304, 404, 500], weights=[78, 10, 10, 2])[0]
    method = 'POST' if '/login' in url else 'GET'
    if method == 'POST' and st == 200:
        st = 302
    lines.append(make_entry(ip, method, url, st))

bf_start = random.randint(3600, 72000)
for i in range(150):
    offset = bf_start + random.randint(0, 240)
    lines.append(make_entry(BRUTE_IP, 'POST', '/login', 401, ua='python-requests/2.31.0', size=512, offset_sec=offset))

for _ in range(80):
    payload = random.choice(SQLI_PAYLOADS)
    status = random.choices([200, 500, 403], weights=[40, 40, 20])[0]
    lines.append(make_entry(SQLI_IP, 'GET', payload, status, ua='sqlmap/1.7.12#stable (https://sqlmap.org)'))

for ddos_ip in DDOS_IPS:
    burst_start = random.randint(3600, 72000)
    for j in range(220):
        offset = burst_start + (j // 30)
        lines.append(make_entry(ddos_ip, 'GET', '/api/data', 200, ua='curl/7.88.1', size=128, offset_sec=offset))

for path in SCANNER_PATHS_LIST * 4:
    st = random.choices([200, 403, 404], weights=[20, 30, 50])[0]
    lines.append(make_entry(SCAN_IP, 'GET', path, st, ua='Nikto/2.1.6 (Evasions:None) (Test:All)'))

random.shuffle(lines)
output_path = os.path.join('sample_logs', 'access.log')
with open(output_path, 'w') as f:
    f.write('\n'.join(lines))
print(f'Generated {len(lines):,} log entries -> {output_path}')
