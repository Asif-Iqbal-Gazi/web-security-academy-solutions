## Lab: SQL injection UNION attack, retrieving multiple values in a single column

### 📋 Summary

The product category filter is vulnerable to `UNION-based` SQL injection. This lab presents a challenge: the `users` table contains two sensitive columns(`username` and `password`), but original query's result set only contains **one** column compatible with string data. By using **string concatenation**, we can merge multiple fields into a single result set to bypass this limitation.

- **Vulnerability Type**: SQL Injection (`UNION-based`)
- **Impact**: Full account takeover via credential exfiltration through a single reflected column.

---

### 🎯 Objectives

- Determine the column count and identify the string-compatible column.
- Use string concatenation to merge `username` and `password` into a single field.
- Parse the concatenated string to retrieve the `administrator` credentials.
- Log in as the `administrator` user.

---

### 🔬 Discovery & Methodology

1. **Column Count**:

   ```sql
   'ORDER BY 2 --
   ```

   The above payload resulted in `200 OK` while,

   ```sql
   'ORDER BY 3 --
   ```

   resulted in `500 Error`, this confirms the table width: 2.

2. **Type Mapping**:
   Each column index was tested with a string literal (`marker`) one at a time to find string compatible one.
   G

   ```
   'UNION SELECT NULL,'asif-probe' --
   ```

   This confirmed the 2nd column can hold string data.

3. **Data Exfiltration**:
   Concatenation operator (`||`) was used to reflect both `username` and `password`.

   ```sql
   'UNION SELECT NULL, username || ':' || password FROM users --
   ```

   _Note: The `||` operator is standard for PostgreSQL. For MySQL, `CONCAT(username, '~', password)` would be used._

   The database appends the content of the `users` table to the product list. We then parse the HTML response to extract the credentials.

---

### 🛠️ Exploit Implementation

The automation script (`lab-06.py`) is comprehensive exploit chain divided into six phases:

- **Reconnaissance**:
  Confirms the lab URL is active and dynamically harvest valid categories to anchor the injection.
- **Column Count & Type Mapping**:
  Identifies table width and maps string-compatible column.
- **Data Exfiltration**:
  Executes `UNION SELECT` payload and uses `BeautifulSoup` to parse the HTML response, extracting all credentials pairs into a dictionary.
- **Authentication & Verification**:
  Harvest CSRF token from login page and attempts to login as "`administrator`" user.
  Confirms the "Solved" state by checking success banner on the home page.

---

### 🛡️ Remediation

**Primary Fix: Parameterized Queries (Prepared Statements)**
The application should use prepared statements to prevent user input from breaking the SQL structure.
