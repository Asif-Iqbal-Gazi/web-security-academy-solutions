## Lab: SQL injection UNION attack, determining the number of columns returned by the query

### 📋 Summary

The application's product category filter is vulnerable to **UNION-based SQL injection**. Because query results are reflected in the response, the database can be forced to return data from other tables.
The first step in a `UNION` attack is determining the exact number of columns returned by the original query to satisfy the "_equal column count_" requirement of SQL `UNION` operator.

- **Vulnerability Type**: SQL Injection (`UNION-based`)
- **Impact**: Information disclosure via database exfiltration.

---

### 🎯 Objectives

- Determine the number of columns returned by the queries.

---

### 🔬 Discovery & Methodology

The application likely processes the filter using a query structured like this:

```sql
SELECT * FROM products WHERE category = 'Gifts' AND released = 1
```

**Discovery Steps**:

1. **Syntax Break**:
   Injecting a single quote `'` triggered a `500 Internal Server Error`.
   This confirmed the input is directly concatenated directly into the query.

2. **Technique A (`ORDER BY`)**:
   Appending `ORDER BY X` instructs the database to sort results by the column index `X`. If `X` exceeds the actual column count, the database returns an error.

> [!NOTE]
> **Binary Search Logic**: For a 5-column table, `ORDER BY i`, returns a `200 OK` for $i \in [1,5]$ and `500` error for $i > 5$.
> This creates a boolean array pattern: `TTTTTFFFFF...` which can leveraged to find the column count efficiently using the **Binary Search** algorithm.

3. **Technique B** (`UNION SELECT NULL`):
   Appending `UNION SELECT NULL`, attempts to join a second result set. Because `NULL` is compatible with most data types, the number of `NULL` values is incremented until the query succeeds.

   ```sql
   SELECT * FROM products WHERE category = 'Gifts' UNION SELECT NULL, NULL, NULL--' AND released = 1
   ```

   Column count is exactly 3 if the server returns `200 OK` for the above query.

---

### 🛠️ Exploit Implementation

The automation script (`lab-03.py`) features a high-performance discovery engine:

- **Reconnaissance**:
  Uses `BeautifulSoup` library to harvest valid categories to anchor the injection.

- **Search Optimization**:
  Instead of slow linear search, the script uses **Binary Search** to pinpoint column count.
  This is significantly faster for database tables with a high column count.

---

### 🛡️ Remediation

**Primary Fix: Parameterized Queries (Prepared Statements)**
The application must use prepared statements. This ensures the database engine treats `UNION SELECT ...` payload as a literal string value rather than a structural change to the SQL command.
