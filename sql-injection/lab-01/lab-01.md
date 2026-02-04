## Lab: SQL injection vulnerability in WHERE clause allowing retrieval of hidden data

### 📋 Summary

The application's product category filter is vulnerable to a classic **Boolean-based SQL injection**.
The backend query is designed to show only "released" products, but by manipulating the `WHERE` clause, we can force the query to ignore the release status and return every item in the database.

- **Vulnerability Type**: SQL Injection
- **Impact**: Disclosure of unreleased products and full inventory.

This lab contains a SQL injection vulnerability in the product category filter. When the user selects a category, the application carries out a SQL query like the following:

```sql
SELECT * FROM products WHERE category = 'Gifts' AND released = 1
```

---

### 🎯 Objectives

- Perform a SQL injection attack that causes the application to display one or more unreleased products

---

### 🔬 Discovery & Methodology

The application executes a query similar to:

```sql
SELECT * FROM products WHERE category = 'Gifts' AND released = 1
```

**Discovery Steps**:

1. **Breaking the Syntax**: `Gifts'` caused a `500 Internal Server Error`, confirming the input is not being sanitized and is breaking the SQL string literal.
2. **Commenting**: `Gifts'--` returned more items than standard "**Gifts**" category.
   This confirms that `--` successfully commented out the `AND released = 1` portion of the query.
3. **Tautology Payload**: `'OR 1=1--` creates the follwing logic:
   ```sql
   SELECT * FROM products WHERE category = 'Gifts' OR 1=1--' AND released = 1
   ```
   Since `1=1` is always true, the database returns every record in the `products` table, effectively ignoring the category filter and the release restriction.

- `filter?category=Gifts` shows three gifts
- `filter?category=Gifts'` (Single quote) results in 500 error response code.
- `filter?category=Gifts'--` shows four items
- `filter?category=Gifts' OR 1=1--` shows all products

---

### 🛠️ Exploit Implementation

The automation script (`lab-01.py`) performs the following logic:

- Accepts lab URL and dynamic payload for injection as input from user.
- Uses `request.get()` to make a `GET` request with user supplied payload for the `category` URL parameter. It then inspects the response body for `"Congratulation"` string, providing feedback on whether the injection was successful.

---

### 🛡️ Remediation

**Primary Fix: Parameterized Queries (Prepared Statements)**
The application must use a database driver that supports parameterized queries.
This ensures the database treats the input `' OR 1=1--` as a literal string value for the category name rather than part of the SQL command.

**Example (Python/psycopg2)**:

```python
# SECURE: Input is passed as a separate parameter
cursor.execute("SELECT * FROM products WHERE category = %s AND released = 1", (user_input,))
```

**Secondary Fix: Input Validation**
Implement an allow-list for the category parameter. If the input doesn't match a pre-defined category (e.g., "Gifts", "Pets"), the request shoudl be rejected before it ever reaches database layer.
