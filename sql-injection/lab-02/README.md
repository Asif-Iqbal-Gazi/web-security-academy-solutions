## Lab: SQL injection vulnerability allowing login bypass

### 📋 Summary

The application's login function is vulnerable to SQL injection. By manipulating the `username` field, the back-end query can be altered to ignore password verification. This allows for an unauthorized login as the `administrator` user.

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

1. **Syntax Break**:
   Entering `administrator'` in the username field triggered a `500 Internal Server Error`.
   This confirmed that the single quote escaped the string literal and broke the SQL syntax.
2. **Logic Bypass**:
   Entering `administrator'-- ` in the username field transformed the query:

   ```sql
   SELECT * FROM users WHERE username = 'administrator'-- AND 1=1--' AND password = [PASSWORD]
   ```

   The `--` sequence commented out the remainder of the query. This removed the password requirement, forcing the database to evaluate only the username.

---

### 🛠️ Exploit Implementation

The automation script (`lab-02.py`) manages the stateful login process through the following steps:

- **Session Persistence**:
  Uses `requests.Session()` to handle cookies and maintain the session state between the initial GET (to fetch the `CSRF token`) and the subsequent POST.
- **CSRF Token Extraction**:
  Performs a `GET` request to login page and uses `BeautifulSoup` to extract the hidden CSRF token required for the form submission.
- **Verification**:
  Re-polls the landing page to check for the "Congratulation" success banner.

---

### 🛡️ Remediation

**Primary Fix: Parameterized Queries (Prepared Statements)**
Authentication queries should never use string concatenation. Prepared statements ensure that the database treats the injection payload as a literal string for the username rather than an executable SQL code.

**Example (Java/JDBC)**:

```java
String sql = "SELECT * FROM users WHERE username = ? AND password = ?";
PreparedStatement statement = connection.prepareStatement(sql);
statement.setString(1, username);
statement.setString(2, password);
ResultSet result = statement.executeQuery();
```
