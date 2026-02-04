# PortSwigger Web Security Academy Solutions 🛡️

This repository contains my automated solutions and technical write-ups for the [PortSwigger Web Security Academy](https://portswigger.net/web-security/)

---

## ⚙️ How to Use

1. **Clone the Repository**:

   ```bash
   git clone [https://github.com/Asif-Iqbal-Gazi/web-security-academy-solutions.git](https://github.com/Asif-Iqbal-Gazi/web-security-academy-solutions.git)
   cd web-security-academy-solutions
   ```

2. **Install Dependencies**:

   ```bash
   pip install -r requirements.txt
   ```

3. **Run an Exploit**:

   ```bash
   python3 sql-injection/lab-05/lab-05.py <LAB_URL>
   ```

   [!Note] The scirpts are currently configured to use `verify=False`. Ensure your local proxy (e.g., Burp Suite) is listening on `127.0.0.1:8080`.

---

## ✅ Progress Dashboard

---

## 🗂️ Repository Structure

```text
.
├── sql-injection/          # Category-specific folders
│   └── lab-XX/
│       ├── lab-XX.py       # Automated exploit script
│       └── lab-XX.md       # Technical write-ups
├── requirements.txt        # Project dependencies
└── README.md               # Portfolio dashboard
```
