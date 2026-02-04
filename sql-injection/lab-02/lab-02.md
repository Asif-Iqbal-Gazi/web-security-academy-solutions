## Lab: SQL injection vulnerability allowing login bypass

### 📋 Summary

The application's login function is vulnerable to SQL injection. By manipulating the `username` field, we can alter the logic of the authentication query to bypass password verification and login as any user.

- **Vulnerability Type**: SQL Injection (Authentication Bypass)
- **Impact**: Full account takeover of the `administrator` account without a valid password.

---

### 🎯 Objectives

- Login to the application as the `administrator` user.

---

### 🔬 Discovery & Methodology

The application likely processes login credentials using a query structured like this:

```sql
SELECT * FROM users WHERE username = '[USERNAME]' AND password = '[PASSWORD]'
```

**Discovery Steps**:

1. **Breaking the Syntax**: Entering `administrator'` in the username field caused a `500 Internal Server Error`. This indicates that the single quote escaped the string literal, breaking the SQL syntax and confirming the injection point.
2. **Logic Bypass**: By entering `administrator'--`, the query is transformed:
   ```sql
   SELECT * FROM users WHERE username = 'administrator'-- AND 1=1--' AND password = "password"
   ```
   The `--` sequence comments out the rest of the query, effectively removing the `AND password = '...'` requirement. The database only evaluates the username, granting access to the `administrator` account.

---

### 🛠️ Exploit Implementation

The automation script (`lab-02.py`) handles the stateful nature of the login process:

- **Session Management**: Uses `requests.Session()` to handle cookies and maintain the session state between the initial GET (to fetch the `CSRF token`) and the subsequent POST.
- **CSRF Extraction**: Uses a regular expression to find and extract the hidden CSRF token from the login form.

---

### 🛡️ Remediation

**Primary Fix: Parameterized Queries (Prepared Statements)**
Authentication queries should never use string concatenation. Using prepared statements ensures that the database treats the injection payload as a literal string rather than executable SQL code.

**Example (Java/JDBC)**:

```java
String sql = "SELECT * FROM users WHERE username = ? AND password = ?";
PreparedStatement statement = connection.prepareStatement(sql);
statement.setString(1, username);
statement.setString(2, password);
ResultSet result = statement.executeQuery();
```
