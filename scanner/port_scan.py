import socket
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor
import time

def scan_port(host, port, timeout):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            if sock.connect_ex((host, port)) == 0:
                return port
    except:
        return None
    return None

def scan_ports(url, ports=None, timeout=1.0, max_threads=20):
    if ports is None:
        ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 8080]

    # اطمینان از وجود پروتکل برای urlparse
    if "://" not in url:
        url = "http://" + url

    try:
        parsed_url = urlparse(url)
        host = parsed_url.hostname
        if not host:
            return {'status': 'error', 'message': 'آدرس نامعتبر'}

        start_time = time.time()
        open_ports = []

        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            results = executor.map(lambda p: scan_port(host, p, timeout), ports)
            open_ports = [p for p in results if p is not None]

        end_time = time.time()

        return {
            'status': 'success',
            'host': host,
            'open_ports': open_ports,
            'scanned_ports': ports,
            'scan_time_sec': round(end_time - start_time, 2)
        }

    except socket.gaierror:
        return {'status': 'error', 'message': 'خطا در تبدیل دامنه به IP'}
    except Exception as e:
        return {'status': 'error', 'message': str(e)}
