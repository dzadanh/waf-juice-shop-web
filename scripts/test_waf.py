import json
import sys
import time
from urllib import error, request


DIRECT = "http://127.0.0.1:3000"
WAF = "http://127.0.0.1:8080"
LOGIN = "/rest/user/login"
ADMIN = "admin@juice-sh.op"
SQLI = {"email": "' OR 1=1--", "password": "anything"}
VALID = {"email": ADMIN, "password": "admin123"}


def send(url, data=None):
    body = json.dumps(data).encode() if data is not None else None
    headers = {"Content-Type": "application/json"} if body else {}
    req = request.Request(url, data=body, headers=headers)
    try:
        with request.urlopen(req, timeout=5) as res:
            return res.status, res.read(), None
    except error.HTTPError as exc:
        return exc.code, exc.read(), None
    except (error.URLError, TimeoutError, OSError) as exc:
        return None, b"", str(exc)


def website_ready(url):
    for _ in range(30):
        status, body, problem = send(url)
        if status == 200 and b"OWASP Juice Shop" in body:
            return True, "HTTP 200"
        time.sleep(2)
    return False, problem or f"HTTP {status}, không thấy trang Juice Shop"


def login(url, data):
    status, body, problem = send(url + LOGIN, data)
    if problem:
        return False, f"Lỗi kết nối: {problem}"
    if status != 200:
        return False, f"HTTP {status}"
    try:
        auth = json.loads(body).get("authentication", {})
    except (ValueError, AttributeError):
        return False, "Phản hồi không phải JSON đăng nhập"
    if not isinstance(auth, dict):
        return False, "Phản hồi thiếu dữ liệu đăng nhập"
    if auth.get("umail") == ADMIN and auth.get("token"):
        return True, "HTTP 200, đăng nhập admin thành công"
    return False, "Không thấy email admin hoặc token trong phản hồi"


def blocked_by_waf():
    status, body, problem = send(WAF + LOGIN, SQLI)
    if problem:
        return False, f"Lỗi kết nối: {problem}"
    if status == 403 and b'"authentication"' not in body:
        return True, "HTTP 403"
    return False, f"HTTP {status}, cần 403; xem docker compose logs waf"


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    results = []

    def show(name, result):
        passed, detail = result
        results.append(passed)
        print(f"TEST {len(results)}: {name} - {'PASS' if passed else 'FAIL'} ({detail})")

    direct_ok = website_ready(DIRECT)
    waf_ok = website_ready(WAF)
    show("Trang trực tiếp port 3000", direct_ok)
    show("Trang qua WAF port 8080", waf_ok)
    show("SQL Injection không qua WAF",
         login(DIRECT, SQLI) if direct_ok[0] else (False, "Port 3000 chưa sẵn sàng"))
    show("SQL Injection qua WAF",
         blocked_by_waf() if waf_ok[0] else (False, "Port 8080 chưa sẵn sàng"))
    show("Đăng nhập hợp lệ qua WAF",
         login(WAF, VALID) if waf_ok[0] else (False, "Port 8080 chưa sẵn sàng"))

    print(f"TỔNG KẾT: {sum(results)}/5 test PASS")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
