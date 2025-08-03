import requests
from requests.exceptions import RequestException, Timeout, HTTPError, ConnectionError

def check_headers(url):
    """
    بررسی وجود هدرهای امنیتی حیاتی در پاسخ HTTP

    پارامتر:
        url (str): آدرس سایت برای بررسی

    خروجی:
        dict: شامل مقادیر هدرهای امنیتی زیر یا پیام خطا
            - X-Frame-Options
            - Content-Security-Policy
            - Strict-Transport-Security
            - Referrer-Policy
    """

    # تعریف هدرهای امنیتی که می‌خواهیم بررسی کنیم
    security_headers = [
        'X-Frame-Options',
        'Content-Security-Policy',
        'Strict-Transport-Security',
        'Referrer-Policy'
    ]

    headers = {
        'User-Agent': 'Mozilla/5.0 (compatible; SecurityHeadersChecker/1.0; +https://yourdomain.com/bot)'
    }

    try:
        # ارسال درخواست GET با تایم‌اوت 7 ثانیه و هدر User-Agent
        response = requests.get(url, headers=headers, timeout=7)
        response.raise_for_status()  # اگر کد وضعیت 4xx یا 5xx بود، خطا می‌دهد

        # استخراج هدرها از پاسخ
        result = {}
        for header in security_headers:
            value = response.headers.get(header)
            if value:
                result[header] = value
            else:
                result[header] = None  # اگر هدر وجود نداشت، مقدار None می‌ذاریم

        return result

    except Timeout:
        return {'error': 'درخواست به سرور تایم‌اوت شد.'}
    except HTTPError as http_err:
        return {'error': f'خطای HTTP: {str(http_err)}'}
    except ConnectionError:
        return {'error': 'اتصال به سرور برقرار نشد.'}
    except RequestException as e:
        return {'error': f'خطا در ارسال درخواست: {str(e)}'}
    except Exception as e:
        # اگر خطای غیرمنتظره‌ای رخ داد، آن را هم مدیریت می‌کنیم
        return {'error': f'خطای ناشناخته: {str(e)}'}
