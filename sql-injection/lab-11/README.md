## Lab: Visible error-based SQL injection

### 📋 Summary

This lab contains a SQL injection vulnerability in the tracking cookie. Unlike previous lab where the injection was "blind", this application is configured to display descriptive database error in the UI. By intentionally providing malformed queries to database, specifically type mismatch error, we can force it to reflect sensitive data (like password, username) directly in the error response.
The database contains a different table called `users`, with columns named `username` and `password`. The goal is to exfiltrate `administrator` credential and log in to the application.

- **Vulnerability Type**: Visible Error-Based SQL Injection
- **Impact**: Full administrative account take over.

---

### 🎯 Objectives

- Identify the cookie vulnerable to `Error-Based` SQLi.
- Exfiltrate the `administrator` password from the `users` table leveraging `CAST()` error.
- Authenticate as administrator to solve the lab.

---

### 🔬 Discovery & Methodology

1. **Identifying the Vulnerability**

By appending a single quote (') to the cookies, the application returns an HTTP 500 error. Unlike Lab 10, the response body contains a detailed "`is-warning`" paragraph describing the SQL syntax error. This confirms the vulnerability is `Visible Error-Based`.

2. **The Type-Mismatch Trick (`CAST`)**

The most efficient way to exfiltrate data here is to force a `CAST()` error. We ask the database to convert a string (the password) into an integer.
When the database attempts this, it fails and generates an error message that looks like this:

```
invalid input syntax for type integer: "<reflected-password>"
```

**Payload Structure**:

```sql
' AND 1=CAST((SELECT password FROM users LIMIT 1)AS int)--'
```

3. **Handling Length Constraints**

The application has a character limit on the `TrackingId` cookie. To prevent the query from being truncated, the script:

- Replaces the existing cookie value entirely instead of appending to it.
- Remove unnecessary whitespace.
- Remove the where clause, as `administrator` is the first row.

### 🛠️ Exploit Implementation

The automation script (`lab-11.py`) is significantly faster than previous ones, because it does not require a loop to guess character.
It operates in 4 phases:

- **Phase 1: Connectivity**:
  Checks if the lab is active.
- **Phase 2: Probing Cookies**:
  Identifies the anchor by triggering HTTP 500 errors.
- **Phase 3: Direct Exfiltration**:
  - Injects the `CAST()` subquery.
  - Captures the HTTP 500 response.
  - Uses regex to parse the password directly from the "is-warning" element in the HTML.
- **Phase 4: Authentication**
  Extracts the CSRF token, performs login, and verifies the solved state.

---

### 🛡️ Remediation

**Primary Fix: Disable Verbose Error Message**
In a production environment, database errors should never be sent to the client.
The application should catch exceptions and return a generic error page.

**Secondary Fix: Parameterized Queries (Prepared Statements)**
Even with hidden errors, the vulnerability remains. Using prepared statements ensures that the `TrackingId` is never executed as part of the SQL command.
