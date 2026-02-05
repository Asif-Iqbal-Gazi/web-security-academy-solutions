## Lab: SQL injection UNION attack, determining the number of columns returned by the query

### 📋 Summary

The application's product category filter is vulnerable to a **SQL injection**. Because they query results are reflected in the response, we can use a `UNION SELECT` attack. The first step in any `UNION` attack is determining the exact number of columns returned by the original query to satisfy the "_equal column count_" requirement of SQL `UNION` operator.

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

1. **Breaking the Syntax**: Entering `'` results in a `500 Internal Server Error`, indicating the input is concatenated directly into query.
2. **Technique A (`ORDER BY`)**: By appending `ORDER BY X`, we instruct the database to sort the results by the specific index `X`. If we sort by a column that exceeds the actual count, the database throws an error ( resulting `500` response).

  > [!NOTE] 
   > **Binary Search Logic**: For a 5-column table, `ORDER BY i`, will return a `200 OK` for $i \in [1,5]$ and `500` error for $i > 5$. This creates a boolean array pattern: `TTTTTFFFFF...` We can leverage this pattern to implement a **Binary Search** algorithm to find the column count efficiently.

3. **Technique B** (`UNION SELECT NULL`): By appending `UNION SELECT NULL`, we attempt to join a second query. Since `NULL` is compatible with most data types, we increment the number of `NULL` values until the query succeeds.

   ```sql
   SELECT * FROM products WHERE category = 'Gifts' UNION SELECT NULL, NULL, NULL--' AND released = 1
   ```

   If the server returns `200 OK` for the above, we know the column count is exactly 3.

---
### 🛠️ Exploit Implementation

The automation script (`lab-03.py`) features a high-performance discovery engine:

- **Optimization**: Instead of linear search (1,2,3...), it uses _Exponential Search_ to find an upper bound, followed by **Binary Search** to pinpoint the exact column count. This is significantly faster for database tables with a high column count.

---
### 🛡️ Remediation

**Primary Fix: Parameterized Queries (Prepared Statements)**
The application must use prepared statements. This ensures the database engine treats `UNION SELECT ...` as a literal string rather than a structural change to the SQL command.
