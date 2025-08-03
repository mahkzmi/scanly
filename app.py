from flask import Flask, request, render_template, jsonify
from scanner.ssl_check import check_ssl
from scanner.cms_detector import detect_cms
from scanner.headers_check import check_headers
from scanner.robots_check import check_robots
from scanner.port_scan import scan_ports
from urllib.parse import urlparse
import re

app = Flask(__name__)

tool_map = {
    'ssl': check_ssl,
    'cms': detect_cms,
    'headers': check_headers,
    'robots': check_robots,
    'ports': scan_ports
}

def normalize_url(url):
    parsed = urlparse(url)
    if not parsed.scheme:
        return 'https://' + url
    return url

def is_valid_url(url):
    # بررسی ساده صحت URL (می‌توان پیشرفته‌تر کرد)
    regex = re.compile(
        r'^(?:http|https)://'  # پروتکل حتما باید باشد
        r'([a-zA-Z0-9\-\.]+)'  # دامنه یا IP
        r'(:[0-9]+)?'          # پورت اختیاری
        r'(\/.*)?$'            # مسیر اختیاری
    )
    return re.match(regex, url) is not None

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    raw_url = request.form.get('url', '').strip()
    selected_tools = request.form.getlist('tools')

    if not raw_url:
        return render_template('index.html', error="لطفاً یک آدرس وارد کنید.")

    if not selected_tools:
        return render_template('index.html', error="هیچ ابزاری برای بررسی انتخاب نشده است.")

    url = normalize_url(raw_url)

    if not is_valid_url(url):
        return render_template('index.html', error="آدرس وارد شده معتبر نیست.")

    results = {}
    for tool in selected_tools:
        func = tool_map.get(tool)
        if func:
            try:
                results[tool] = func(url)
            except Exception as e:
                results[tool] = {'error': f'خطا در اجرای ابزار {tool}: {str(e)}'}

    score = evaluate_score(results)

    return render_template('report_template.html', url=url, results=results, score=score)

@app.route('/api/scan', methods=['POST'])
def api_scan():
    data = request.get_json(force=True)
    raw_url = data.get('url', '').strip()
    selected_tools = data.get('tools', [])

    if not raw_url:
        return jsonify({'error': 'لطفاً یک آدرس وارد کنید.'}), 400

    if not selected_tools:
        return jsonify({'error': 'هیچ ابزاری برای بررسی انتخاب نشده است.'}), 400

    url = normalize_url(raw_url)

    if not is_valid_url(url):
        return jsonify({'error': 'آدرس وارد شده معتبر نیست.'}), 400

    results = {}
    for tool in selected_tools:
        func = tool_map.get(tool)
        if func:
            try:
                results[tool] = func(url)
            except Exception as e:
                results[tool] = {'error': f'خطا در اجرای ابزار {tool}: {str(e)}'}

    score = evaluate_score(results)
    return jsonify({'url': url, 'results': results, 'score': score})

def evaluate_score(results):
    score = 0

    ssl = results.get('ssl', {})
    if ssl.get('status') == 'secure':
        if ssl.get('issuer') and 'self' not in ssl.get('issuer').lower():
            score += 20
        else:
            score += 10

    headers = results.get('headers', {})
    if isinstance(headers, dict):
        h_score = 0
        if headers.get('X-Frame-Options'): h_score += 5
        if headers.get('Content-Security-Policy'): h_score += 5
        if headers.get('Strict-Transport-Security'): h_score += 5
        if headers.get('Referrer-Policy'): h_score += 5
        score += h_score

    if results.get('cms') and results['cms'] != 'Unknown':
        score += 10

    robots = results.get('robots', {})
    if robots.get('status') == 'found' and not robots.get('risky', False):
        score += 10

    ports = results.get('ports', {}).get('open_ports', [])
    risky_ports = [21, 22, 23, 3306]
    if all(p not in ports for p in risky_ports):
        score += 20

    return min(score, 100)

if __name__ == '__main__':
    app.run(debug=True)
