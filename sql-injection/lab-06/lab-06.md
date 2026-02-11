## Lab: SQL injection UNION attack, retrieving multiple values in a single column

### 📋 Summary

This lab presents a structural challenge: the `users` table contains two critical columns (`username` and `password`), but the original query's result set only contains **one** column compatible with string data. To solve this, we must concatenate multiple fields into a single string to exfiltrate them through that one available column.

- **Vulnerability Type**: SQL Injection (`UNION-based`)
- **Impact**: Full takeover of administrator account and complete database exfiltration.

---

### 🎯 Objectives

- Determine the column count and identify the string-compatible column.
- Use string concatenation to merge `username` and `password` into a single field.
- Parse the concatenated string to retrieve the `administrator` credentials and authentication.

---

### 🔬 Discovery & Methodology

1. **Column Count & Type Discovery (Review)** We utilize the techniques established in previous labs to identify the table structure.
   - **Discovery Step**: `ORDER BY X--` determines the number of columns..
   - **Probing Step**: `UNION SELECT NULL, 'marker'--` identifies that columns must be string compatible to support extraction of username and password pairs.
   - **Structural Constraint**: Discovery reveals that only one specific column index (e.g., Column 2) accepts string data.
2. **Data Exfiltration (Dumping via Concatenation)** Since we cannot exfiltrate the username and password into separate columns, we join them using a separator (e.g., `~`). This allows us to retrieve both values through a single string-compatible column.

**Logic Transformation**:

```sql
' UNION SELECT NULL, username || '~' || password FROM users--
```

_Note: The `||` operator is standard for PostgreSQL. For MySQL, `CONCAT(username, '~', password)` would be used._

The database appends the content of the `users` table to the product list. We then parse the HTML response to extract the credentials.

---

### 🛠️ Exploit Implementation

The automation script (`lab-06.py`) is comprehensive exploit chain divided into five phases:

- **Reconnaissance**: Verifies the target URL is alive.
- **Structural Analysis**: Uses `ORDER BY` to find the column count.
- **Type Mapping**: Iteratively probes columns with a marker string to identify those capable of holding user credentials.
- **Exfiltration**: Executes the `UNION SELECT` payload and utilizes `BeautifulSoup` to scrape the `administrator` password from the resulting HTML table.
- **Authentication**: Performs a stateful login. It first harvests a CSRF token from the `/login` page and then submits the stolen credentials within the same session.

---

### 🛡️ Remediation

**Primary Fix: Parameterized Queries (Prepared Statements)**
The application should use prepared statements to prevent user input from breaking the SQL structure.
