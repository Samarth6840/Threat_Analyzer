import re
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

SQLI_PATTERN = re.compile(
    r"union[\s%20+]+select|select[\s%20+]+.*from|drop[\s%20+]+table|insert[\s%20+]+into|"
    r"'[\s]*or[\s]*'1'[\s]*=[\s]*'1|--[\s]*$|;[\s]*--|\bexec\b|\bcast\b|0x[0-9a-f]{4,}|sleep\(\d+\)",
    re.IGNORECASE
)
SCANNER_PATHS = re.compile(
    r'\.(php|asp|aspx|env|git|bak|config|xml|sql|old|htaccess|DS_Store)$|wp-admin|phpmyadmin|admin|\./\.|etc/passwd|proc/self|actuator|\.git/HEAD|xmlrpc\.php|wp-login',
    re.IGNORECASE
)


def _split_into_chunks(data, n_workers):
    if not data:
        return [[] for _ in range(n_workers)]
    k, rem = divmod(len(data), n_workers)
    chunks = []
    start = 0
    for i in range(n_workers):
        end = start + k + (1 if i < rem else 0)
        chunks.append(data[start:end])
        start = end
    return chunks


def _shuffle(mapped_pairs):
    grouped = defaultdict(list)
    for key, value in mapped_pairs:
        grouped[key].append(value)
    return dict(grouped)


def mapreduce(data, mapper_fn, reducer_fn, n_workers=4):
    chunks = _split_into_chunks(data, n_workers)
    all_mapped = []
    with ThreadPoolExecutor(max_workers=n_workers) as executor:
        futures = {executor.submit(mapper_fn, chunk): i for i, chunk in enumerate(chunks)}
        for future in as_completed(futures):
            all_mapped.extend(future.result())
    grouped = _shuffle(all_mapped)
    return {key: reducer_fn(values) for key, values in grouped.items()}


def _sum_reducer(values):
    return sum(values)


def _collect_unique_reducer(values):
    return list(set(values))


def _brute_force_mapper(chunk):
    return [(log['ip'], 1) for log in chunk if log['status'] in (401, 403)]


def brute_force_job(logs):
    counts = mapreduce(logs, _brute_force_mapper, _sum_reducer)
    flagged = {ip: c for ip, c in counts.items() if c >= 5}
    return {'counts': counts, 'flagged': flagged, 'total_events': sum(counts.values())}


def _sqli_mapper(chunk):
    pairs = []
    for log in chunk:
        probe = (log.get('url') or '') + ' ' + (log.get('ua') or '')
        if SQLI_PATTERN.search(probe):
            pairs.append((log['ip'], log.get('url', '')))
    return pairs


def sqli_job(logs):
    hits = mapreduce(logs, _sqli_mapper, _collect_unique_reducer)
    return {'hits': hits, 'flagged': {ip: urls for ip, urls in hits.items()}, 'total_events': sum(len(v) for v in hits.values())}


def _ddos_mapper(chunk):
    return [((log['ip'], log.get('minute_key', 'unknown')), 1) for log in chunk]


def ddos_job(logs):
    per_minute = mapreduce(logs, _ddos_mapper, _sum_reducer)
    ip_max_rpm = defaultdict(int)
    for (ip, _), count in per_minute.items():
        ip_max_rpm[ip] = max(ip_max_rpm[ip], count)
    flagged = {ip: rpm for ip, rpm in ip_max_rpm.items() if rpm >= 20}
    return {'ip_max_rpm': dict(ip_max_rpm), 'flagged': flagged, 'total_events': len(per_minute)}


def _scanner_mapper(chunk):
    return [(log['ip'], log.get('url_path', '')) for log in chunk if SCANNER_PATHS.search(log.get('url', '') or '')]


def scanner_job(logs):
    hits = mapreduce(logs, _scanner_mapper, _collect_unique_reducer)
    flagged = {ip: paths for ip, paths in hits.items() if len(paths) >= 3}
    return {'hits': hits, 'flagged': flagged, 'total_events': sum(len(v) for v in hits.values())}


def _status_mapper(chunk):
    return [(log['status'], 1) for log in chunk]


def _ip_mapper(chunk):
    return [(log['ip'], 1) for log in chunk]


def _hour_mapper(chunk):
    return [(log.get('hour', 0), 1) for log in chunk]


def _url_mapper(chunk):
    return [(log.get('url_path', '/'), 1) for log in chunk]


def run_all_jobs(logs):
    with ThreadPoolExecutor(max_workers=4) as executor:
        bf_f = executor.submit(brute_force_job, logs)
        sqli_f = executor.submit(sqli_job, logs)
        ddos_f = executor.submit(ddos_job, logs)
        scan_f = executor.submit(scanner_job, logs)
        bf = bf_f.result()
        sqli = sqli_f.result()
        ddos = ddos_f.result()
        scan = scan_f.result()
    status_dist = mapreduce(logs, _status_mapper, _sum_reducer)
    hourly = mapreduce(logs, _hour_mapper, _sum_reducer)
    top_ips = mapreduce(logs, _ip_mapper, _sum_reducer)
    top_urls = mapreduce(logs, _url_mapper, _sum_reducer)
    all_threats = set(bf['flagged']) | set(sqli['flagged']) | set(ddos['flagged']) | set(scan['flagged'])
    return {
        'total_requests': len(logs),
        'total_threats': len(all_threats),
        'brute_force': bf,
        'sqli': sqli,
        'ddos': ddos,
        'scanner': scan,
        'status_distribution': {str(k): v for k, v in status_dist.items()},
        'hourly_traffic': {str(k): v for k, v in sorted(hourly.items())},
        'top_ips': dict(sorted(top_ips.items(), key=lambda x: -x[1])[:12]),
        'top_urls': dict(sorted(top_urls.items(), key=lambda x: -x[1])[:10]),
        'all_threat_ips': list(all_threats),
        'geo_threats': []
    }
