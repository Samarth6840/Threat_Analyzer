import os
import time
import requests

ABUSEIPDB_KEY = os.getenv('ABUSEIPDB_KEY', '')
GEO_API = 'http://ip-api.com/json/{ip}?fields=status,lat,lon,city,country,isp'
ABUSE_API = 'https://api.abuseipdb.com/api/v2/check'


def geolocate_ip(ip):
    try:
        r = requests.get(GEO_API.format(ip=ip), timeout=5)
        d = r.json()
        if d.get('status') == 'success':
            return {
                'lat': d['lat'],
                'lon': d['lon'],
                'city': d.get('city', 'Unknown'),
                'country': d.get('country', 'Unknown'),
                'isp': d.get('isp', 'Unknown')
            }
    except Exception:
        pass
    return None


def check_abuseipdb(ip):
    if not ABUSEIPDB_KEY:
        return {'abuseScore': 0, 'country': 'N/A', 'isp': 'Set ABUSEIPDB_KEY env variable for live scores', 'totalReports': 0}
    try:
        r = requests.get(
            ABUSE_API,
            headers={'Key': ABUSEIPDB_KEY, 'Accept': 'application/json'},
            params={'ipAddress': ip, 'maxAgeInDays': 90},
            timeout=5
        )
        d = r.json()['data']
        return {
            'abuseScore': d.get('abuseConfidenceScore', 0),
            'country': d.get('countryCode', 'N/A'),
            'isp': d.get('isp', 'Unknown'),
            'totalReports': d.get('totalReports', 0)
        }
    except Exception:
        return {'abuseScore': 0, 'country': 'N/A', 'isp': 'API error', 'totalReports': 0}


def enrich_threats(results):
    threat_ips = results.get('all_threat_ips', [])[:25]
    bf = results['brute_force']['flagged']
    sqli = results['sqli']['flagged']
    ddos = results['ddos']['flagged']
    scan = results['scanner']['flagged']
    geo_threats = []
    for ip in threat_ips:
        geo = geolocate_ip(ip)
        abuse = check_abuseipdb(ip)
        if not geo:
            continue
        threat_types = []
        if ip in bf: threat_types.append('Brute Force')
        if ip in sqli: threat_types.append('SQL Injection')
        if ip in ddos: threat_types.append('DDoS')
        if ip in scan: threat_types.append('Scanner')
        geo_threats.append({
            'ip': ip, 'lat': geo['lat'], 'lon': geo['lon'], 'city': geo['city'],
            'country': geo['country'], 'isp': geo['isp'], 'abuseScore': abuse['abuseScore'],
            'totalReports': abuse['totalReports'], 'threatTypes': threat_types
        })
        time.sleep(0.3)
    results['geo_threats'] = geo_threats
    return results
