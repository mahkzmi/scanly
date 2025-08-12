import ssl
import socket
from urllib.parse import urlparse
from datetime import datetime

def check_ssl(url, port=443):
    try:
        parsed = urlparse(url)
        scheme = parsed.scheme.lower() if parsed.scheme else ''
        hostname = parsed.hostname or parsed.path  # fallback

        if not hostname:
            return {'status': 'error', 'message': 'آدرس نامعتبر است.'}

        # اگر scheme نبود یا http بود، تبدیل به https می‌کنیم
        if scheme != 'https':
            scheme = 'https'

        context = ssl.create_default_context()

        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

                expire_date_str = cert.get('notAfter')
                try:
                    expire_date = datetime.strptime(expire_date_str, "%b %d %H:%M:%S %Y %Z")
                except Exception:
                    expire_date = None

                issuer = cert.get('issuer', ())
                issuer_common_name = 'ناشناس'
                for rdn in issuer:
                    for key, value in rdn:
                        if key == 'commonName':
                            issuer_common_name = value
                            break

                days_to_expire = (expire_date - datetime.utcnow()).days if expire_date else None

                status = 'secure'
                message = 'گواهی SSL معتبر است.'

                if days_to_expire is not None and days_to_expire <= 30:
                    status = 'warning'
                    message = f'گواهی SSL کمتر از ۳۰ روز دیگر منقضی می‌شود! ({days_to_expire} روز مانده)'

                return {
                    'status': status,
                    'issuer': issuer_common_name,
                    'expires': expire_date.strftime('%Y-%m-%d') if expire_date else 'نامشخص',
                    'days_to_expire': days_to_expire,
                    'message': message
                }

    except ssl.SSLError as e:
        return {'status': 'insecure', 'error': f'خطای SSL: {str(e)}'}
    except socket.timeout:
        return {'status': 'error', 'message': 'اتصال به سرور تایم‌اوت شد.'}
    except socket.gaierror:
        return {'status': 'error', 'message': 'نام دامنه نامعتبر است یا قابل دسترسی نیست.'}
    except Exception as e:
        return {'status': 'error', 'message': f'خطای ناشناخته: {str(e)}'}
