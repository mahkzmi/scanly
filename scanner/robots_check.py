import requests
from urllib.parse import urlparse

def check_robots(url):
    """
    بررسی وجود فایل robots.txt و ارزیابی امنیتی محتوا

    پارامترها:
        url (str): آدرس سایت برای بررسی فایل robots.txt

    خروجی:
        dict: شامل وضعیت یافتن فایل robots.txt، وجود مسیرهای حساس در آن و یا پیام خطا
    """

    try:
        # افزودن scheme اگر وجود نداشته باشد
        parsed = urlparse(url)
        if not parsed.scheme:
            url = "http://" + url
            parsed = urlparse(url)

        hostname = parsed.hostname
        scheme = parsed.scheme

        if not hostname:
            return {'status': 'invalid url', 'message': 'آدرس وارد شده نامعتبر است.'}

        # ساخت URL کامل robots.txt
        domain = f"{scheme}://{hostname}"
        robots_url = domain + "/robots.txt"

        # درخواست HTTP به robots.txt با timeout مشخص
        response = requests.get(robots_url, timeout=5)

        # بررسی وضعیت پاسخ
        if response.status_code == 200:
            content = response.text.lower()

            # لیست مسیرهای حساس و پرریسک که نباید در robots.txt مشخص شوند
            sensitive_paths = ["/admin", "/login", "/config", "/.env", "/backup", "/private", "/database"]

            # بررسی وجود مسیرهای پرریسک در محتوا
            risky = any(path in content for path in sensitive_paths)

            return {
                'status': 'found',
                'risky': risky,
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
