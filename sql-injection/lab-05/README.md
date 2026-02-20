## Lab: SQL injection UNION attack, retrieving data from other tables

### 📋 Summary

The product category is vulnerable to `UNION-based` SQL injection. Because query results are reflected in the response, we can use a `UNION SELECT` statement to exfiltrate sensitive data from other tables.
In this lab, the target is `users` table, specifically the credentials for the `administrator` account.

- **Vulnerability Type**: SQL Injection (`UNION-based`)
- **Impact**: Full takeover of administrator account and complete database exfiltration.

---

### 🎯 Objectives

- Determine the number of columns returned by the original query.
- Identify which columns are compatible with string data.
- Perform a `UNION-based` attack to dump the `users` table.
- Login as `administrator` user using the dumped credentials.

---

### 🔬 Discovery & Methodology

1. **Column Count & Type Discovery**:
   The table width was identified using `ORDER BY`. Incremental probing confirmed the number of columns.
   Each column index was tested with a string literal (`'marker`) one at time to find compatible ones. This lab requires at least two string-compatible columns to retrieve both username and password in a single request.
2. **Data Exfiltration**
   A `UNION SELECT` payload was used to map `username` and `password` columns from `users` table onto the reflected columns of the product table.

**Discovery Steps**:

- `'ORDER BY 2 -- ` (Resulted in `200 OK`) vs `'ORDER BY 3 -- ` (Resulted in `500 Error`) confirmed a 2 column table.
- `'UNION SELECT 'asif-probe', 'asif-probe' --` confirmed both the column to be string-compatible.
- `'UNION SELECT username, password FROM users --` was used to dump all user credentials.

---

### 🛠️ Exploit Implementation

The automation script (`lab-05.py`) is comprehensive exploit chain divided into five phases:

- **Reconnaissance**:
  Confirms the lab URL is active and harvest valid categories dynamically to anchor the injection.
- **Column Count & Type Mapping**:
  Identifies column count and find all indices compatible with string data.
- **Credentials Dumping**:
  Executes `UNION` payload and uses `BeautifulSoup` to parse the HTML response, extracting all credentials pairs into dictionary.
- **Login**:
  Loads the login page to extract `CSRF` token, then submits a `POST` request with exfiltrated `administrator` credential.
- **Verification**:
  Confirms the "Solved" state by checking for the success banner on the home page.

---

### 🛡️ Remediation

**Primary Fix: Parameterized Queries (Prepared Statements)**
The application should use prepared statements to prevent user input from breaking the SQL structure.
