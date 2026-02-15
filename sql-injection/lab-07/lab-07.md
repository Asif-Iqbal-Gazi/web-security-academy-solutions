## Lab: SQL injection attack, querying the database type and version on MySQL and Microsoft

### 📋 Summary

This product category is vulnerable to `UNION-based` SQL injection. The goal is to exfiltrate the database version string to fingerprint the backend engine.

- **Vulnerability Type**: SQL Injection (`UNION-based`)
- **Impact**: Database fingerprinting and information disclosure

---

### 🎯 Objectives

- Determine the column count and identify the string-compatible column.
- Query the database version and verify the lab status.

---

### 🔬 Discovery & Methodology

1. **Dynamic Parameter Discovery**
   To **anchor** the exploit to a valid category, the script harvests legitimate category names from the homepage.

2. **Column Count & Type Discovery (Review)** We utilize the techniques established in previous labs to identify the table structure.
   - **Discovery Step**: `ORDER BY X--` determines the number of columns..
   - **Probing Step**: `UNION SELECT NULL, 'marker'--` identifies string-compatible columns to support extraction of database version.

3. **Database Specific Constants**
   Different database engines uses unique global variables for versioning.
   - **MSSQL/MySQL**: `@@version` (our case)
   - **PostgreSQL**: `version()`
   - **Oracle**: `v$version`

4. **Final Payload**:

```sql
' UNION SELECT @@version, NULL --+
```

---

### 🛠️ Exploit Implementation

The automation script (`lab-07.py`) utilizes a modular Object-Oriented design and performs the entire operation in 6 phases:

- **Phase 1: Connectivity**: Verifies the target is reachable and identifies the PortSwigger lab environment.
- **Phase 2: Reconnaissance**: Harvests valid categories to serve as the injection anchor.
- **Phase 3: Column Count**: Determines columns count using `ORDER BY` technique.
- **Phase 4: Compatibility Mapping**: Identifies string-compatible column indices.
- **Phase 5: Final Payload Injection**: Injects the `@@version` constant into the mapped column.
- **Phase 6: Verification**: Verifies the "Solved" state by polling the home page leveraging `requests.Session()`.

---

### 🛡️ Remediation

**Primary Fix: Parameterized Queries (Prepared Statements)**
The application should use prepared statements to prevent user input from breaking the SQL structure.
