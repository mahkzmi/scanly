import logging
from flask import Flask, request, render_template, jsonify
from urllib.parse import urlparse
import validators

from scanner.ssl_check import check_ssl
from scanner.cms_detector import detect_cms
from scanner.headers_check import check_headers
from scanner.robots_check import check_robots
from scanner.port_scan import scan_ports

app = Flask(__name__)

# تنظیمات لاگ (اختیاری)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# نگاشت ابزارهای قابل استفاده
tool_map = {
    'ssl': check_ssl,
    'cms': detect_cms,
    'headers': check_headers,
    'robots': check_robots,
    'ports': scan_ports
}

def normalize_url(url: str) -> str:
    """اضافه کردن https:// اگر scheme وجود نداشته باشد"""
    parsed = urlparse(url)
    if not parsed.scheme:
        return 'https://' + url
    return url

def is_valid_url(url: str) -> bool:
    """اعتبارسنجی استاندارد URL با استفاده از کتابخانه validators"""
    return validators.url(url)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    try:
        raw_url = request.form.get('url', '').strip()
        selected_tools = request.form.getlist('tools')

        if not raw_url:
            return render_template('index.html', error="لطفاً یک آدرس وارد کنید.")

        if not selected_tools:
            return render_template('index.html', error="هیچ ابزاری برای بررسی انتخاب نشده است.")

        url = normalize_url(raw_url)

        if not is_valid_url(url):
            return render_template('index.html', error="آدرس وارد شده معتبر نیست.")

        # محدود کردن ابزارها فقط به ابزارهای مجاز (امنیت)
        selected_tools = [tool for tool in selected_tools if tool in tool_map]

        results = {}
        for tool in selected_tools:
            func = tool_map[tool]
            try:
                results[tool] = func(url)
            except Exception as e:
                logger.error(f"Error running tool {tool} on {url}: {e}")
                results[tool] = {'error': f'خطا در اجرای ابزار {tool}: {str(e)}'}

        score = evaluate_score(results)

        return render_template('report_template.html', url=url, results=results, score=score)

    except Exception as e:
        logger.exception("Unexpected error in /scan endpoint")
        return render_template('index.html', error="خطای داخلی رخ داده است. لطفاً دوباره تلاش کنید.")

@app.route('/api/scan', methods=['POST'])
def api_scan():
    try:
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

        selected_tools = [tool for tool in selected_tools if tool in tool_map]

        results = {}
        for tool in selected_tools:
            func = tool_map[tool]
            try:
                results[tool] = func(url)
            except Exception as e:
                logger.error(f"Error running tool {tool} on {url}: {e}")
                results[tool] = {'error': f'خطا در اجرای ابزار {tool}: {str(e)}'}

        score = evaluate_score(results)

        return jsonify({'url': url, 'results': results, 'score': score})

    except Exception as e:
        logger.exception("Unexpected error in /api/scan endpoint")
        return jsonify({'error': 'خطای داخلی رخ داده است.'}), 500

def evaluate_score(results: dict) -> int:
    """
    محاسبه امتیاز کلی امنیت بر اساس نتایج ابزارها
    """
    score = 0

    ssl = results.get('ssl', {})
    if ssl.get('status') == 'secure':
        issuer = ssl.get('issuer', '').lower()
        if issuer and 'self' not in issuer:
            score += 20
        else:
            score += 10

    headers = results.get('headers', {})
    if isinstance(headers, dict):
        header_points = 0
        if headers.get('X-Frame-Options'): header_points += 5
        if headers.get('Content-Security-Policy'): header_points += 5
        if headers.get('Strict-Transport-Security'): header_points += 5
        if headers.get('Referrer-Policy'): header_points += 5
        score += header_points

    cms = results.get('cms')
    if cms and cms != 'Unknown':
        score += 10

    robots = results.get('robots', {})
    if robots.get('status') == 'found' and not robots.get('risky_paths'):
        score += 10

    ports = results.get('ports', {}).get('open_ports', [])
    risky_ports = [21, 22, 23, 3306]
    if all(p not in ports for p in risky_ports):
        score += 20

    return min(score, 100)

if __name__ == '__main__':
    app.run(debug=True)
