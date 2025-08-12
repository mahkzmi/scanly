import requests
from urllib.parse import urlparse

def check_robots(url):
    try:
        parsed = urlparse(url)
        scheme = parsed.scheme or "http"
        hostname = parsed.hostname or parsed.path  # اگر hostname نبود، path رو بذار

        if not hostname:
            return {'status': 'invalid url', 'message': 'آدرس وارد شده نامعتبر است.'}

        def fetch_robots(scheme, hostname):
            url_robots = f"{scheme}://{hostname}/robots.txt"
            headers = {'User-Agent': 'ScanlyBot/1.0 (+https://scanly.example.com)'}
            return requests.get(url_robots, timeout=5, headers=headers)

        # تلاش اول با scheme اصلی
        response = fetch_robots(scheme, hostname)

        # اگر کد خطا یا timeout و scheme https بود، fallback به http کن
        if response.status_code != 200 and scheme == "https":
            try:
                response = fetch_robots("http", hostname)
            except:
                pass

        if response.status_code == 200:
            content = response.text.lower()
            sensitive_paths = ["/admin", "/login", "/config", "/.env", "/backup", "/private", "/database"]
            risky_paths = [p for p in sensitive_paths if p in content]

            return {
                'status': 'found',
                'risky_paths': risky_paths,
                'message': 'فایل robots.txt یافت شد.',
                'content_snippet': content[:500] + ("..." if len(content) > 500 else "")
            }
        elif response.status_code == 404:
            return {'status': 'not found', 'message': 'فایل robots.txt پیدا نشد.'}
        else:
            return {'status': 'error', 'message': f'پاسخ غیرمنتظره: کد وضعیت {response.status_code}'}

    except requests.exceptions.Timeout:
        return {'status': 'error', 'message': 'درخواست به فایل robots.txt تایم‌اوت شد.'}
    except requests.exceptions.RequestException as e:
        return {'status': 'error', 'message': f'خطا در ارسال درخواست: {str(e)}'}
    except Exception as e:
        return {'status': 'error', 'message': f'خطای ناشناخته: {str(e)}'}
