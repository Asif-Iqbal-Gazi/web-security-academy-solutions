## Lab: SQL injection vulnerability in WHERE clause allowing retrieval of hidden data

### 📋 Summary

The application's product category filter is vulnerable to a classic **Boolean-based SQL injection**. The back-end query only shows "`released`" products. Manipulating the `WHERE` clause forces the database to ignore the release status and return every item in the inventory.

- **Vulnerability Type**: SQL Injection
- **Impact**: Disclosure of unreleased products and full inventory.

---

### 🎯 Objectives

- Display unreleased products by injecting a logic-based payload into the category filter.

---

### 🔬 Discovery & Methodology

The application executes a query similar to:

```sql
SELECT * FROM products WHERE category = 'Gifts' AND released = 1
```

**Discovery Steps**:

1. **Syntax Break**:
   Injecting a single quote `'` after category filter (`Gifts'`) caused a `500 Internal Server Error`.
   This confirmed the input is not sanitized and breaks the SQL syntax.
2. **Commenting**:
   Injecting a comment (`--`) after the single quote (`Gifts'--`) returned a `200 OK` and more items than standard category view.
   This confirmed that the `--` successfully ignored the `AND released = 1` portion of the query.
3. **Tautology Payload**:
   The payload `'OR 1=1--` created the following logic:
   ```sql
   SELECT * FROM products WHERE category = 'Gifts' OR 1=1--' AND released = 1
   ```
   Since `1=1` is always true, the database returns every record in the `products` table.
   This bypassed both the category filter and the release restriction.

---

### 🛠️ Exploit Implementation

The automation script (`lab-01.py`) performs the following steps:

- Accepts the target URL and uses `BeautifulSoup` to harvest valid product categories.
- Constructs a tautology payload (`' OR 1=1 -- `) and attaches it to identified category.
- Sends the request with payload via `requests.Session` and re-polls the homepage to check for the "Congratulation" success banner.

**Technical Considerations**

- Uses a `Session` object to maintain consistency across requests.
- Proxies all requests through `http://127.0.0.1:8080` for traffic analysis in Burp Suite.
- Uses `warnings.filterwarnings` to suppress insecure HTTPS warnings during local testing.

---

### 🛡️ Remediation

**Primary Fix: Parameterized Queries (Prepared Statements)**
The application must use a database driver that supports parameterized queries.
This ensures the database treats the input `' OR 1=1--` as a literal string value for the category name rather than part of the SQL command.

_Example (Python/psycopg2)_:

```python
# SECURE: Input is passed as a separate parameter
cursor.execute("SELECT * FROM products WHERE category = %s AND released = 1", (user_input,))
```

**Secondary Fix: Input Validation**
Use an allow-list for the category parameter. The request should be rejected if the input doesn't match a pre-defined category (e.g., "Gifts", "Pets").
