# Password Security Auditor & Entropy Analyzer

A defensive security auditing utility built in Python for evaluating credential resilience, detecting dictionary mutation patterns, and maintaining tamper-evident security audit logs.

## Core Security Features
* **Shannon Entropy Calculation:** Evaluates true randomness and bit-strength of user credentials.
* **Levenshtein Distance Analysis:** Detects similarity between candidate passwords and known compromised datasets or previous credentials.
* **Heuristic Pattern Matching (`zxcvbn`):** Identifies spatial keyboard patterns, date formats, L33T substitutions, and common dictionary concatenations.
* **SQLite Audit Logging:** Records anonymized security assessment metrics for compliance and vulnerability remediation tracking.

---

## Published Security Advisory (Self-Audit & Remediation)

### Advisory ID: GHSA-PSA-2026-001
* **Title:** SQL Injection & Unbounded Algorithmic Complexity (DoS) in Audit Logger and Levenshtein Engine
* **Severity:** High (CVSS 7.5)
* **Component:** `auditor.py`
* **Status:** Patched / Remediated (v1.0.1)

### Vulnerability Description
During static security auditing of the initial implementation, two vulnerabilities were identified:
1. **Unparameterized SQL Queries in Audit Logger (CWE-89):** Raw metadata strings were concatenated directly into `INSERT` statements within the SQLite logging module, allowing malformed input strings to manipulate database queries.
2. **Algorithmic Complexity Exhaustion in Levenshtein Distance (CWE-407):** Computing the dynamic programming matrix $O(N \times M)$ on arbitrarily long input strings without pre-validation allowed resource exhaustion (Denial of Service) via oversized payloads.

### Remediation & Patch
* Replaced all string formatting in SQLite queries with strict parameterized statements (`cursor.execute("INSERT INTO audit_logs VALUES (?, ?, ?)", params)`).
* Enforced a strict maximum input length cap (`MAX_INPUT_BYTES = 256`) prior to Levenshtein matrix allocation to guarantee bounded memory and CPU execution time.
