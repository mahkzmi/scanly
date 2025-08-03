import ssl
import socket
from urllib.parse import urlparse
from datetime import datetime

def check_ssl(url):
    """
    بررسی وضعیت گواهی SSL سایت و بازگرداندن اطلاعات کلیدی آن

    پارامترها:
        url (str): آدرس سایت برای بررسی گواهی SSL

    خروجی:
        dict: شامل وضعیت امنیتی، صادرکننده گواهی، تاریخ انقضا و یا خطا
    """
    try:
        # افزودن scheme در صورت نبودن
        parsed = urlparse(url)
        if not parsed.scheme:
            url = "https://" + url
            parsed = urlparse(url)

        hostname = parsed.hostname
        if not hostname:
            return {'status': 'error', 'message': 'آدرس نامعتبر است.'}

        # ایجاد کانتکست SSL با تنظیمات پیش‌فرض (رعایت استانداردها)
        context = ssl.create_default_context()

        # اتصال TCP به پورت 443
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

                # استخراج تاریخ انقضای گواهی
                expire_date_str = cert.get('notAfter')
                expire_date = datetime.strptime(expire_date_str, "%b %d %H:%M:%S %Y %Z")

                # استخراج نام صادرکننده گواهی
                issuer = cert.get('issuer')
                issuer_common_name = None
                if issuer:
                    for tup in issuer:
                        for key, value in tup:
                            if key == 'commonName':
                                issuer_common_name = value
                                break
                        if issuer_common_name:
                            break

                return {
                    'status': 'secure',
                    'issuer': issuer_common_name or 'ناشناس',
                    'expires': expire_date.strftime('%Y-%m-%d'),
                    'days_to_expire': (expire_date - datetime.utcnow()).days
                }

    except ssl.SSLError as e:
        return {'status': 'insecure', 'error': f'خطای SSL: {str(e)}'}
    except socket.timeout:
        return {'status': 'error', 'message': 'اتصال به سرور تایم‌اوت شد.'}
    except socket.gaierror:
        return {'status': 'error', 'message': 'نام دامنه نامعتبر است یا قابل دسترسی نیست.'}
    except Exception as e:
        return {'status': 'error', 'message': f'خطای ناشناخته: {str(e)}'}
