## Lab: SQL injection UNION attack, finding a column containing text

### 📋 Summary

The product category is vulnerable to `UNION-based` SQL injection.
This lab demonstrate how to identify which column in a result set are compatible with string data.
Identifying a string-compatible column is requirement for exfiltrating text-based information like credentials or database version string.

- **Vulnerability Type**: SQL Injection (`UNION-based`)
- **Impact**: Information disclosure via database exfiltration.

---

### 🎯 Objectives

- Determine the number of columns returned by the original query.
- Identify the specific column that supports string data.
- Retrieve and display a randomly generated "marker" string provided by the lab.

---

### 🔬 Discovery & Methodology

1. **Column Count**:
   Using `ORDER BY X` technique, the tale width was determined. A `200 OK` response for index `X` and a `500 Error` for `X + 1` confirmed the column count.

2. **Type Identification**:
   A `UNION` query requires compatible data type between the original and injected result sets.
   Probing was performed by placing a string literal (the "marker") into one column at a time while keeping the remaining columns as `NULL`.

**Discovery Steps**:

- `UNION SELECT 'marker', NULL, NULL--` (Resulted in a `500 Error`: Column 1 is likely an `Int/Date`)
- `UNION SELECT NULL, 'marker', NULL--` (Resulted in a `200 OK`: Column 2 confirmed as String compatible)

---

### 🛠️ Exploit Implementation

The automation script (`lab-04.py`) is designed as a multi-stage discovery tool:

- **Reconnaissance**:
  Uses `BeautifulSoup` to dynamically harvest valid category to anchor the injection.
- **Marker Extraction**:
  Uses `BeautifulSoup`and `re` to dynamically retrieve the required target string from the lab's "hint" banner.
- **Column Discovery**:
  Uses Binary search to efficiently determine the number of columns in the original query.
- **Iterative Type Probing**:
  Loops through each discovered column index, injecting the marker string until the application returns a `200 OK`.
- **Final Verification**:
  Confirms the "Solved" state by checking for the success banner on the landing page.

---

### 🛡️ Remediation

**Primary Fix: Parameterized Queries (Prepared Statements)**
The application should use prepared statements to prevent user input from breaking the SQL structure.
