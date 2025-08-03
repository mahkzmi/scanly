import requests
from urllib.parse import urljoin
from requests.exceptions import RequestException

def detect_cms(url):
    """
    تشخیص CMS سایت بر اساس نشانه‌ها در کد HTML و هدرها و بررسی مسیرهای معمول CMSها

    پارامتر:
        url (str): آدرس سایت برای بررسی

    خروجی:
        str: نام CMS (مثلاً WordPress, Joomla, Drupal) یا 'Unknown' اگر تشخیص داده نشود
    """
    headers = {
        'User-Agent': 'Mozilla/5.0 (compatible; CMSDetector/1.0; +https://yourdomain.com/bot)'
    }

    try:
        response = requests.get(url, headers=headers, timeout=7)
        response.raise_for_status()  # بررسی موفقیت درخواست
        html = response.text.lower()

        # بررسی نشانه‌های رایج در HTML
        if 'wp-content' in html or 'wp-includes' in html:
            return 'WordPress'
        if 'content="joomla!' in html or 'joomla' in html:
            return 'Joomla'
        if 'drupal' in html or 'sites/default' in html:
            return 'Drupal'

        # بررسی هدرهای HTTP
        server_header = response.headers.get('Server', '').lower()
        x_powered_by = response.headers.get('X-Powered-By', '').lower()
        if 'wordpress' in x_powered_by:
            return 'WordPress'
        if 'joomla' in x_powered_by:
            return 'Joomla'
        if 'drupal' in x_powered_by:
            return 'Drupal'

        # بررسی مسیرهای کلیدی CMSها (مثلاً ورود ادمین)
        def check_path(path):
            try:
                r = requests.get(urljoin(url, path), headers=headers, timeout=5)
                return r.status_code == 200
            except RequestException:
                return False

        if check_path('/wp-login.php') or check_path('/wp-admin/'):
            return 'WordPress'
        if check_path('/administrator/') or check_path('/index.php?option=com_'):
            return 'Joomla'
        if check_path('/user/login') or check_path('/node/'):
            return 'Drupal'

        return 'Unknown'

    except RequestException:
        return 'Unknown'
