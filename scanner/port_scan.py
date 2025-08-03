import socket
from urllib.parse import urlparse

def scan_ports(url, ports=None, timeout=1.0):
    """
    اسکن پورت‌های رایج برای یک دامنه یا IP مشخص شده

    پارامترها:
        url (str): آدرس وب‌سایت یا IP برای اسکن پورت‌ها
        ports (list[int], optional): لیست پورت‌هایی که باید بررسی شوند (اگر None باشد، پورت‌های پیش‌فرض استفاده می‌شوند)
        timeout (float, optional): مدت زمان تایم‌اوت اتصال به هر پورت (ثانیه)

    خروجی:
        dict: شامل کلید 'open_ports' با لیست پورت‌های باز یا کلید 'error' در صورت بروز خطا
    """

    # پورت‌های پیش‌فرض اگر ورودی داده نشود
    if ports is None:
        ports = [21, 22, 23, 80, 443, 3306, 8080]

    # تحلیل URL و استخراج hostname یا IP
    try:
        parsed_url = urlparse(url)
        host = parsed_url.hostname

        if not host:
            return {'error': 'آدرس URL نامعتبر است و نمی‌توان hostname را استخراج کرد.'}

    except Exception as e:
        return {'error': f'خطا در پردازش URL: {str(e)}'}

    open_ports = []

    try:
        for port in ports:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((host, port))
                if result == 0:
                    open_ports.append(port)

        return {'open_ports': open_ports}

    except socket.timeout:
        return {'error': 'اتصال به یکی از پورت‌ها تایم‌اوت شد.'}
    except socket.gaierror:
        return {'error': 'خطا در تبدیل نام دامنه به IP.'}
    except socket.error as err:
        return {'error': f'خطای شبکه: {str(err)}'}
    except Exception as e:
        return {'error': f'خطای ناشناخته: {str(e)}'}
