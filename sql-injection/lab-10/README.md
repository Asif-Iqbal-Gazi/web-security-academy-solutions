## Lab: Blind SQL injection with conditional responses

### 📋 Summary

This lab contains a blind SQL injection vulnerability. The application uses a tracking cookie for analytics, and performs a SQL query containing the value of the submitted cookie.
**The application does not respond to differently based on whether query returns rows, and the results are not reflected in the UI**.
However, the application returns custom error message (HTTP 500) if the SQL query causes a database error.
By intentionally triggering a "division by zero" error, we can infer the truth of our queries.

The database contains a different table called `users`, with columns named `username` and `password`. The goal is to exfiltrate `administrator` credential and log in to the application.

- **Vulnerability Type**: Blind SQL Injection (`Error-Based`)
- **Impact**: Full administrative account take over.

---

### 🎯 Objectives

- Identify the cookie vulnerable to `Blind-SQLi`.
- Exfiltrate the `administrator` password from the `users` table.
- Authenticate as administrator to solve the lab.

---

### 🔬 Discovery & Methodology

1. **Probing Cookies for Error-Based SQLi**

To anchor the exploit, the script iterates through the cookies in session's `CookieJar`. Instead of simple boolean math, it appends an Oracle "Error Bomb" payload:

- **Logic**: If condition `1=1` is true, force a division by zero (`1/0`)
- **True Case**: `' || (SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE 'a' END FROM dual) || '` --> **HTTP 500**
- **False Case**: `' || (SELECT CASE WHEN (1=0) THEN TO_CHAR(1/0) ELSE 'a' END FROM dual) || '` --> **HTTP 200**

If the server returns a 500 only when the condition _True_, the cookie is confirmed as the injection vector.
In this instance the vulnerable cookie was `TrackingId`.

2. **Exfiltrating Credential**

Since the lab identifies the back-end as **Oracle**, we use the `dual` table and `SUBSTR()` syntax to recover the `administrator` password.
The script targets `users` table to recover `administrator` password. This is done in two stages:

- **Identifying Password Length**:

  To identify the length, the script injects a conditional error:

  ```sql
  ' || (SELECT CASE WHEN (LENGTH(PASSWORD) > X) THEN TO_CHAR(1/0) ELSE 'a' END FROM users WHERE username='administrator') || '
  ```

  For a range of $length \in [1, 50]$, this query generates a monotonic pattern of True/False responses (e.g., `TTTTTTTTTFFFFFF`). By identifying the specific points where "Welcome back!" message disappears, we can leverage a **binary search** algorithm to find the exact length in significantly fewer requests than a linear search.

- **Determining the Password string**:

  Assuming the password consists of printable ASCII characters ($x \in [32, 126]$), the script performs a binary search for each character position using the following condition:

  ```sql
  ' || (SELECT CASE WEHEN (ASCII(SUBSTRING(password, position, 1)) > X) THEN TO_CHAR(1/0) ELSE 'a' END FROM users WHERE username='administrator' AND ROWNUM=1) || '
  ```

3. **Authenticate and Verify**:

The script fetches the _CSRF Token_ from the `/login` endpoint using `BeautifulSoup`. It then submits a `POST` request with the exfiltrated credentials. Finally it checks the home page for "Congratulation" string to verify the lab is solved.

_Note_:

- To ensure subquery only returns a single (preventing database errors), we append `LIMIT 1` for non-Oracle database and `AND ROWNUM=1` for Oracle.
- For Oracle `SUBSTR()` is used instead of `SUBSTRING()`
- Using `ASCII()` allows for numeric comparisons (for $x$), avoiding the need to escape characters in payload ($char \in [` `, `~`).

_Payload Note_:
In this payload:

```sql
' || (SELECT CASE WHEN (SELECT ASCII(SUBSTRING(password, position, 1)) > X FROM users WHERE username='administrator') THEN TO_CHAR(1/0) ELSE 'a' END FROM dual|| '
```

- `TO_CHAR` is not required in this context.
- Equivalent statement:

```sql
' || (SELECT CASE WHEN (ASCII(SUBSTRING(password, position, 1)) > X) THEN 1/0 ELSE 'a' FROM users WHERE username='administrator') || '
```

- This is equivalent to:

```sql
' || (SELECT 1/0 FROM users WHERE username='administrator' AND (ASCII(SUBSTRING(password, position, 1))) > X) || '
```

This is because if the `WHERE` clause matches only then `SELECT` expression is evaluated.

### 🛠️ Exploit Implementation

The automation script (`lab-10.py`) utilizes a modular Object-Oriented design across 6 phases:

- **Phase 1: Connectivity**:
  Checks if the lab is active.
- **Phase 2: Probing Cookies**:
  Identifies the anchor by triggering forced HTTP 500 errors.
- **Phase 3: Exfiltration Setup**:
  Configures the Oracle specific sub queries (adding `ROWNUM=1`).
- **Phase 4: Identifying Length**:
  Uses binary search to efficiently find the password length via conditional error.
- **Phase 5: Exfiltrate Password**:
  Recovers the password string one character at a time using an optimized binary search across the printable ASCII range.
- **Phase 6: Post-Exploitation:**
  Extracts the CSRF token, performs login, and verifies the solved state.

---

### 🛡️ Remediation

**Primary Fix: Parameterized Queries (Prepared Statements)**
The application should use prepared statements to ensure that user input (the cookie value) is treated as data rather than executable code.
This prevents database from interpreting injected SQL structures like `CASE` or `SELECT` statements injected into the cookie.
