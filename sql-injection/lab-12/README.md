## Lab: Blind SQL injection with time delays and information retrieval

### 📋 Summary

This lab contains a **Time-Based SQLi** vulnerability.

The application includes the value of a tracking cookie (`TrackingId`) directly inside a SQL query. The results of the query are not reflected in the UI, and no database errors are shown.

However, the back-end database is **PostgreSQL**, which supports the `pg_sleep()` function. By injecting conditional logic that triggers a delay when a condition evaluates to true, we can infer database value based on response time.

The goals is the extract the `administrator` password from the `users` table and log in to the application.

- **Vulnerability Type**: Blind SQL Injection (`Time-Based`)
- **Impact**: Full administrative account take over.
- **Database Engine**: PostgreSQL (identified via `pg_sleep()`)

---

### 🎯 Objectives

- Identify the cookie vulnerable to `Blind-SQLi`.
- Exfiltrate the `administrator` password from the `users` table.
- Authenticate as administrator to solve the lab.

---

### 🔬 Discovery & Methodology

1. **Probing Cookies for Time-Based SQLi**

The script iterates through the session cookies and injects a conditional sleep payload to detect the injection point.

**Payload**:

```sql
' || (SELECT CASE WHEN (condition) THEN  pg_sleep(2) ELSE pg_sleep(0) END) || '
```

- If the condition is True, the response is delayed.
- If the condition is False, the response time remains normal.

If a consistent delay is observed only when the condition evaluates to true, the cookie is confirmed as injectable.
In this instance, the vulnerable cookie was `TrackingId`.

2. **Time Calibration**

Since network latency vary, the script first measures normal response times.

- Computes average response time.
- Calculates standard deviation.
- Sets a dynamic threshold for detecting delays.
- Adjusts sleep time accordingly.

This improves reliability and reduces false positive.

3. **Exfiltrating Credential**

Data extraction is performed in two stages:

**Step 1: Identifying Password Length**

To determine password length, the script injects:

```sql
' || (SELECT CASE WHEN (LENGTH(password) > X) THEN pg_sleep(2) ELSE pg_sleep(0) END FROM users WHERE username='administrator' LIMIT 1) || '
```

As `X` increases, the response pattern becomes monotonic:

```
TRUE TRUE TRUE TRUE FALSE FALSE
```

Binary search is used to efficiently determine the exact length.

**Step 2: Extracting the Password String**

Assuming printable ASCII character (`32-126`) the script extracts each character using:

```sql
' || (SELECT CASE WHEN (ASCII(SUBSTRING(password, position, 1)) > X) THEN pg_sleep(2) ELSE pg_sleep(0) END FROM users WHERE username='administrator' LIMIT 1) || '
```

Binary search is applied to determine the ASCII value of each character in significantly fewer requests than a linear approach.

4. **Authenticate and Verify**:

The script:

- Fetches CSRF token from `/login` using `BeautifulSoup`
- Submits a POST request with extracted credentials.
- Verifies success by checking the `"Congratulation"` message on homepage.

### 🛠️ Exploit Implementation

The automation script (`lab-12.py`) follows a structured approach:

- **Phase 1: Connectivity**:
  - Verifies lab is available.
- **Phase 2: Timing Calibration**:
  - Measures baseline latency.
  - Computes threshold for delay detection.
  - Sets adaptive sleep time.
- **Phase 3: Cookie Identification**
  - Iterates through cookies.
  - Confirms injection using conditional sleep payload.
- **Phase 4: Length Extraction**:
  - Uses binary search to determine password length.
- **Phase 5: Password Extraction**
  - Recovers the password one character at a time using ASCII comparison and binary search.
- **Phase 6: Post-Exploitation:**
  - Retrieves CSRF token.
  - Logs in as administrator
  - Confirms lab completion

The script is designed to:

- Restore cookie state after each injection.
- Minimize request count using binary search.
- Reduce timing noise using statistical calibration.

---

### 🛡️ Remediation

**Primary Fix: Parameterized Queries (Prepared Statements)**
The application should use prepared statements to ensure that user input (the cookie value) is treated as data rather than executable code.
