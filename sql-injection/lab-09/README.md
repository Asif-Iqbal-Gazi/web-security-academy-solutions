## Lab: Blind SQL injection with conditional responses

### 📋 Summary

This lab contains a blind SQL injection vulnerability. The application uses a tracking cookie for analytics and performs a SQL query containing the value of that submitted cookie.
The results of the SQL query are not returned directly and no error messages are displayed. However, the application includes a "**Welcome back!**" message in the page if the query returns any rows. The database contains a different table called `users`, with columns named `username` and `password`. The goal is to exfiltrate `administrator` credential and log in to the application.

- **Vulnerability Type**: Blind SQL Injection (`Boolean-based`)
- **Impact**: Full administrative account take over.

---

### 🎯 Objectives

- Identify the cookie vulnerable to `Blind-SQLi`.
- Fingerprint the database engine.
- Exfiltrate the `administrator` password.
- Authenticate as administrator to solve the lab.

---

### 🔬 Discovery & Methodology

1. **Probing Cookies for Blind-SQLi**

To anchor the exploit to a correct injection point, the script iterates through the cookies in the session's `CookieJar`. It appends boolean payloads for both a _True Case_ (`' AND '1'='1`) and _False Case_ (`' AND '1'='2`). If the "**Welcome back!**" message is present for the _True_ case but disappears for the _False_ case, the cookie is confirmed as the injection vector.
In this instance the vulnerable cookie was `TrackingId`.

2. **Fingerprinting Database Engine**

Since syntax varies between database engines, the script fingerprints the back-end by appending database specific clauses:

- **ORACLE**:

```sql
' AND (SELECT 'a' FROM DUAL)='a'--

```

- **PostgreSQL**:

```sql
' AND (SELECT version()) LIKE '%PostgreSQL%'--
```

- **MSSQL/MySQL**:
  Default if the specific probe above fails.

3. **Exfiltrating Credential**

The script targets `users` table to recover `administrator` password. This is done in two stages:

- **Identifying Password Length**:

  To identify the length, the script injects a boolean condition into the vulnerable cookie:

  ```sql
  ' AND (SELECT LENGTH(password) FROM users WHERE username='administrator') > X--
  ```

  For a range of $length \in [1, 50]$, this query generates a monotonic pattern of True/False responses (e.g., `TTTTTTTTTFFFFFF`). By identifying the specific points where "Welcome back!" message disappears, we can leverage a **binary search** algorithm to find the exact length in significantly fewere requests than a linear search.

- **Determining the Password string**:

  Assuming the password consists of printable ASCII characters ($x \in [32, 126]$), the script performs a binary search for each character position using the following condition:

  ```sql
  ' AND (SELECT ASCII(SUBSTRING(password, position, 1)) FROM users WHERE username='administrator') > X--
  ```

4. **Authenticate and Verify**:

The script fetches the _CSRF Token_ from the `/login` endpoint using `BeautifulSoup`. It then submits a `POST` request with the exfiltrated credentials. Finally it checks the home page for "Congratulation" string to verify the lab is solved.

_Note_:

- To ensure subquery only returns a single (preventing database errors), we append `LIMIT 1` for non-Oracle database and `AND ROWNUM=1` for Oracle.
- For Oracle `SUBSTR()` is used instead of `SUBSTRING()`
- Using `ASCII()` allows for numeric comparisons (for $x$), avoiding the need to escape characters in payload ($char \in [` `, `~]$).

### 🛠️ Exploit Implementation

The automation script (`lab-09.py`) utilizes a modular Object-Oriented design and performs the entire operation in 6 phases:

- **Phase 1: Connectivity**:
  Checks if the lab is active.
- **Phase 2: Probing Cookies**:
  Identifies the injection anchor by temporarily modifying `cookie.value` directly in the `session` to prevent _double cookie_ pollution (since, `session.request()` is used to make requests).
- **Phase 3: DB Fingerprinting**:
  Detects back-end SQL dialect to ensure syntax compatibility.
- **Phase 4: Identifying Length**:
  Uses binary search to efficiently find the password length.
- **Phase 5: Exfiltrate Password**:
  Recovers the passwrod string one character at a time using an optimized binary search accross the printable ASCII range.
- **Phase 7: Post-Exploitation:**
  Extracts the CSRF token, perfomrs login, and verfiies the solved state.

---

### 🛡️ Remediation

**Primary Fix: Parameterized Queries (Prepared Statements)**
The application should use prepared statements to ensure that user input (the cookie value) is treated as data rather than executable code.
This prevents database from interpreting injected SQL tructures like `AND` or `UNION` clauses.
