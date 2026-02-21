## Lab: SQL injection attack, listing the database contents on non-Oracle databases

### 📋 Summary

This product category is vulnerable to `UNION-based` SQL injection. This lab demonstrates a complete attack chain: from structural discovery and database fingerprinting to schema mapping and administrative account takeover.

- **Vulnerability Type**: SQL Injection (`UNION-based`)
- **Impact**: Full account takeover and complete database compromise.

---

### 🎯 Objectives

- Determine the column count and identify the string-compatible column.
- Fingerprint the database engine.
- Map the database schema to locate the dynamic user table and its columns.
- Exfiltrate and login with the `administrator` credential.

---

### 🔬 Discovery & Methodology

1. **Dynamic Parameter Discovery**
   To **anchor** the exploit to a valid category, the script harvests legitimate category names from the homepage.

2. **Column Count & Type Discovery (Review)** We utilize the techniques established in previous labs to identify the table structure.
   - **Discovery Step**: `ORDER BY X--` determines the number of columns..
   - **Probing Step**: `UNION SELECT NULL, 'marker'--` identifies string-compatible columns to support extraction of database version.

3. **Database Specific Constants**
   Cycled through engine-specific constants until a `200 OK` is received, identifying the SQL dialect:
   - **PostgreSQL**: `version()` (**Target Case**)
   - **MSSQL/MySQL**: `@@version`
   - **Oracle**: `v$version` (requires `FROM DUAL`)

4. **Schema Mapping & Extraction**
   Since table names are randomized per lab instance, the exploit dynamically queries the metadata:
   - Queries `information_schema.tables` for any table name containing "`users`".
   - Queries `information_schema.columns` for the Specific user table to find `username` and `password` fields.
   - Uses `||` operator to concatenate `username` and `password` with a colon delimiter for single column extraction.

5. **Final Payload**:

```sql
' UNION SELECT username || ':' || password, NULL from users_pprfam--+
```

(Note: Since the exfiltrated data is reflected in a single column, the application renders the result within `<th>` without corresponding `<td>` elements. The automation script leverages this specific HTML structure to precisely extract credentials.)

### 🛠️ Exploit Implementation

The automation script (`lab-08.py`) utilizes a modular Object-Oriented design and performs the entire operation in 6 phases:

- **Phase 1 - 4:** Connectivity, Reconnaissance, Column Count, and String Mapping.
- **Phase 5: Fingerprinting:** Confirms the backend engine to ensure the correct metadata registry is queried.
- **Phase 6: Schema & Credential Dump:** Programmatically navigates the `information_schema` to retrieve the `administrator` password.
- **Phase 7: Post-Exploitation:** Extracts CSRF token form the `/loign` page and performs a POST request using the exfiltrated credentials to solve the lab.

---

### 🛡️ Remediation

**Primary Fix: Parameterized Queries (Prepared Statements)**
The application should use prepared statements to prevent user input from breaking the SQL structure.
