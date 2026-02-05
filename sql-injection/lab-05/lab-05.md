## Lab: SQL injection UNION attack, retrieving data from other tables

### 📋 Summary

This lab features a SQL injection vulnerability in the product category filter. Since the application reflects query results in the response, we can leverage a `UNION-based` attack to retrieve data from other tables. In this scenario, we target a secondary table named `users` to retrieve the `username` and `password` for the `administrator` account.
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
1. **Column Count & Type Discovery (Review)** We utilize the techniques established in previous labs to identify the table structure.
	   - **Discovery Step**: `ORDER BY X--` determines the number of columns..
	   - **Probing Step**: `UNION SELECT 'marker', NULL, NULL--` identifies that columns must be string compatible to support extraction of username and password pairs.
2. **Data Exfiltration (Dumping)** Once the structure is known (e.g., 3 columns and two of them string-compatible), we can craft a payload to join the `users` table to the `products` result set:
```sql
' UNION SELECT NULL, username, password FROM users--
```
The database appends the content of the `users` table to the product list. We then parse the HTML response to extract the credentials.

---
### 🛠️ Exploit Implementation

The automation script (`lab-05.py`) is a comprehensive exploit chain divided into five phases:
1. **Reconnaissance**: Verifies the target URL is alive.
    
2. **Structural Analysis**: Uses `ORDER BY` to find the column count.
    
3. **Type Mapping**: Iteratively probes columns with a marker string to identify those capable of holding user credentials.
    
4. **Exfiltration**: Executes the `UNION SELECT` payload and utilizes **BeautifulSoup** to scrape the `administrator` password from the resulting HTML table.
    
5. **Authentication**: Performs a stateful login. It first harvests a **CSRF token** from the `/login` endpoint and then submits the stolen credentials within the same session.

The automation script (`lab-05.py`) is comprehensive exploit chain divided into five phases:
- **Reconnaissance**: Verifies the target URL is alive.
- **Structural Analysis**: Uses `ORDER BY` to find the column count.
- **Type Mapping**: Iteratively probes columns with a marker string to identify those capable of holding user credentials.
- **Exfiltration**: Executes the `UNION SELECT` payload and utilizes `BeautifulSoup` to scrape the `administrator` password from the resulting HTML table.
- **Authentication**: Performs a stateful login. It first harvests a CSRF token from the `/login` page and then submits the stolen credentials within the same session.

---
### 🛡️ Remediation

**Primary Fix: Parameterized Queries (Prepared Statements)**
The application should use prepared statements to prevent user input from breaking the SQL structure.
