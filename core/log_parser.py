import re
from datetime import datetime

LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<url>\S+) (?P<protocol>[^\"]+)" '
    r'(?P<status>\d{3}) (?P<bytes>\S+)(?: "(?P<referer>[^\"]*)" "(?P<ua>[^\"]*)")?'
)


def parse_line(line):
    m = LOG_PATTERN.match(line.strip())
    if not m:
        return None
    d = m.groupdict()
    try:
        d['timestamp'] = datetime.strptime(d['time'], '%d/%b/%Y:%H:%M:%S %z')
        d['status'] = int(d['status'])
        d['bytes'] = int(d['bytes']) if d['bytes'] and d['bytes'] != '-' else 0
        d['hour'] = d['timestamp'].hour
        d['minute_key'] = d['timestamp'].strftime('%Y-%m-%d %H:%M')
        d['url_path'] = d['url'].split('?')[0]
    except (ValueError, TypeError):
        return None
    return d


def parse_log_file(path):
    with open(path, 'r', errors='ignore') as f:
        return [p for p in (parse_line(line) for line in f) if p]


def parse_log_text(text):
    return [p for p in (parse_line(line) for line in text.splitlines()) if p]
