# PortSwigger Web Security Academy Solutions 🛡️

This repository contains my automated solutions and technical write-ups for the [PortSwigger Web Security Academy](https://portswigger.net/web-security/)

---

## ⚙️ How to Use

1. **Clone the Repository**:

   ```bash
   git clone https://github.com/Asif-Iqbal-Gazi/web-security-academy-solutions.git
   cd web-security-academy-solutions
   ```

2. **Install Dependencies**:

   ```bash
   pip install -r requirements.txt
   ```

3. **Run an Exploit**:

   ```bash
   python3 sql-injection/lab-05/lab-05.py <lab-url>
   ```

> [!NOTE]
> The scripts are currently configured to use `verify=False`.
> Ensure your local proxy (e.g., Burp Suite) is listening on `127.0.0.1:8080`.

---

## ✅ Progress Dashboard

| #   | Category          | Lab Name                                                                            | Difficulty     | Solution                                      | Writeup                                      |
| :-- | :---------------- | :---------------------------------------------------------------------------------- | :------------- | --------------------------------------------- | -------------------------------------------- |
| 1   | **SQL Injection** | SQL injection vulnerability in `WHERE` clause allowing retrieval of hidden data     | _APPRENTICE_   | [🐍 Python](./sql-injection/lab-01/lab-01.py) | [📝 Notes](./sql-injection/lab-01/README.md) |
| 2   | **SQL Injection** | SQL injection vulnerability allowing login bypass                                   | _APPRENTICE_   | [🐍 Python](./sql-injection/lab-02/lab-02.py) | [📝 Notes](./sql-injection/lab-02/README.md) |
| 3   | **SQL Injection** | SQL injection UNION attack, determining the number of columns returned by the query | _PRACTITIONER_ | [🐍 Python](./sql-injection/lab-03/lab-03.py) | [📝 Notes](./sql-injection/lab-03/lREADMEmd) |
| 4   | **SQL Injection** | SQL injection UNION attack, finding a column containing text                        | _PRACTITIONER_ | [🐍 Python](./sql-injection/lab-04/lab-04.py) | [📝 Notes](./sql-injection/lab-04/lab-04.md) |
| 5   | **SQL Injection** | SQL injection UNION attack, retrieving data from other tables                       | _PRACTITIONER_ | [🐍 Python](./sql-injection/lab-05/lab-05.py) | [📝 Notes](./sql-injection/lab-05/README.md) |
| 6   | **SQL Injection** | SQL injection UNION attack, retrieving multiple values in a single column           | _PRACTITIONER_ | [🐍 Python](./sql-injection/lab-06/lab-06.py) | [📝 Notes](./sql-injection/lab-06/README.md) |
| 7   | **SQL Injection** | SQL injection attack, querying the database type and version on MySQL and Microsoft | _PRACTITIONER_ | [🐍 Python](./sql-injection/lab-07/lab-07.py) | [📝 Notes](./sql-injection/lab-07/README.md) |
| 8   | **SQL Injection** | SQL injection attack, listing the database contents on non-Oracle databases         | _PRACTITIONER_ | [🐍 Python](./sql-injection/lab-08/lab-08.py) | [📝 Notes](./sql-injection/lab-08/README.md) |
| 9   | **SQL Injection** | Blind SQL injection with conditional responses                                      | _PRACTITIONER_ | [🐍 Python](./sql-injection/lab-09/lab-09.py) | [📝 Notes](./sql-injection/lab-09/README.md) |
| 10  | **SQL Injection** | Blind SQL injection with conditional errors                                         | _PRACTITIONER_ | [🐍 Python](./sql-injection/lab-10/lab-10.py) | [📝 Notes](./sql-injection/lab-10/README.md) |
| 11  | **SQL Injection** | Visible error-based SQL injection                                                   | _PRACTITIONER_ | [🐍 Python](./sql-injection/lab-11/lab-11.py) | [📝 Notes](./sql-injection/lab-11/README.md) |
| 12  | **SQL Injection** | Blind SQL injection with time delays and information retrieval                      | _PRACTITIONER_ | [🐍 Python](./sql-injection/lab-12/lab-12.py) | [📝 Notes](./sql-injection/lab-12/README.md) |

---

## 🗂️ Repository Structure

```text
.
├── sql-injection/          # Category-specific folders
│   ├── lab-XX/
│   │   ├── lab-XX.py       # Automated exploit script
│   │   └── README.md       # Technical write-ups
│   └─── README.md          # Category-specific cheatsheet
├── requirements.txt        # Project dependencies
└── README.md               # Portfolio dashboard
```
