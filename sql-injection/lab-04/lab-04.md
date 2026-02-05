## Lab: SQL injection UNION attack, finding a column containing text

### 📋 Summary

This lab extends the `UNION-based` SQL injection technique. After determining the number of columns in a result set, the next critical step is identifying which of those columns can hold string data. This is necessary for exfiltrating text-based information like usernames, passwords, or database versions. 
- **Vulnerability Type**: SQL Injection (`UNION-based`)
- **Impact**: Information disclosure via database exfiltration.

---
### 🎯 Objectives

- Determine the number of columns returned by the original query.
- Identify specific column compatible with string data.
- Retrieve and display a randomly generated "marker" string provided by the lab.

---
### 🔬 Discovery & Methodology
1. **Column Count (Review)** Using the `Exponential + Binary Search` method with `ORDER BY X`. we determine the column of original query.
	   - **Pattern**: `ORDER BY 3` (Success 200) --> `ORDER BY 4` (Error 500) indicates 3 columns.
2. **Type Identification**: A `UNION` query requires compatible data type between the original and injected queries. We probe each columns by placing a literal (the "marker") into one column while keeping the others as `NULL`.

**Discovery Steps**:
- `UNION SELECT 'marker', NULL, NULL--` (Error: Column 1 is likely an `Int/Date`)
- `UNION SELECT NULL, 'marker', NULL--` (Success 200: Column 2 is String compatible)

---
### 🛠️ Exploit Implementation

The automation script (`lab-04.py`) is designed as a multi-stage discovery tool:
- **Marker Extraction**: Uses `BeautifulSoup`and `re` to dynamically pull the target string from the lab's "hint" banner.
- **Column Discovery**: Uses Binary search to efficiently determine the number of columns in the original query.
- **Iterative Type Probing**: Loops through each discovered column index, injecting the marker string until a `200 OK` response is received.

---
### 🛡️ Remediation

**Primary Fix: Parameterized Queries (Prepared Statements)**
The application should use prepared statements to prevent user input from breaking the SQL structure.
