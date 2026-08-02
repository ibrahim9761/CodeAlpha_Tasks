# 🔐 Secure Coding Review — Vulnerable Flask App, Audited & Remediated

![Python](https://img.shields.io/badge/Python-3.12-blue?logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.0-black?logo=flask&logoColor=white)
![Bandit](https://img.shields.io/badge/Static%20Analysis-Bandit-orange)
![Tests](https://img.shields.io/badge/Tests-18%2F18%20passing-brightgreen)
![License](https://img.shields.io/badge/License-MIT-lightgrey)

A complete, end-to-end secure code review of a small Python/Flask web
application — built for **CodeAlpha's Cyber Security Internship (Task 3)**,
and structured the way a real application security review is done in
practice: **static analysis + manual review + automated verification**,
with every finding tied to a CWE reference, a concrete fix, and a passing
regression test.

---

## Table of Contents

- [What this project demonstrates](#what-this-project-demonstrates)
- [Project structure](#project-structure)
- [Findings summary](#findings-summary)
- [Methodology](#methodology)
- [Getting started](#getting-started)
- [Running the tests](#running-the-tests)
- [Continuous Integration](#continuous-integration)
- [Full report](#full-report)
- [Skills demonstrated](#skills-demonstrated)
- [About](#about)

---

## What this project demonstrates

Most "secure coding review" demos stop at running a linter once and
listing its output. This project goes further:

- ✅ A **realistic vulnerable application** with 8 distinct, intentionally
  planted vulnerabilities spanning injection, auth, deserialization, and
  configuration issues
- ✅ A **fully remediated version** of the same application, fix-for-fix
- ✅ **Real tool output** — not paraphrased — from Bandit, before and after
- ✅ An **18-case automated test suite** that actively fires the original
  exploit payloads (SQL injection strings, XSS payloads, pickle opcodes,
  path-traversal filenames) at the fixed app to *prove* each fix holds
- ✅ A CI workflow that fails the build if a Medium/High-severity issue is
  ever reintroduced
- ✅ Two genuine functional bugs found and fixed while verifying the
  security fixes — documented transparently in the report, because a
  security review that only checks "did the scanner go quiet" and never
  runs the app can miss regressions

> ⚠️ **`app/vulnerable_app.py` is intentionally insecure.** It exists
> solely as the audit target for this exercise. Do not deploy it.
> See [`app/secure_app_fixed.py`](app/secure_app_fixed.py) for the
> production-appropriate version.

---

## Project structure

```
secure-coding-review/
├── app/
│   ├── vulnerable_app.py        # Audit target — intentionally vulnerable
│   └── secure_app_fixed.py      # Remediated version — every finding fixed
├── tests/
│   └── test_security.py         # 18 automated tests verifying every fix
├── reports/
│   ├── SECURITY_REVIEW_REPORT.md   # Full write-up: findings, CWEs, fixes
│   ├── bandit_raw_output.txt       # Real Bandit scan — BEFORE remediation
│   ├── bandit_fixed_output.txt     # Real Bandit scan — AFTER remediation
│   └── pytest_output.txt           # Real test run — 18/18 passing
├── .github/workflows/
│   └── security-checks.yml      # CI: Bandit + pytest on every push
├── requirements.txt
├── LICENSE
└── README.md
```

---

## Findings summary

| # | Vulnerability | Severity | CWE |
|---|---|---|---|
| 1 | SQL Injection (string-built query) | **Critical** | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) |
| 2 | OS Command Injection (`shell=True`) | **Critical** | [CWE-78](https://cwe.mitre.org/data/definitions/78.html) |
| 3 | Insecure Deserialization (`pickle.loads`) | **Critical** | [CWE-502](https://cwe.mitre.org/data/definitions/502.html) |
| 4 | Weak, unsalted password hashing (MD5) | High | [CWE-327](https://cwe.mitre.org/data/definitions/327.html) |
| 5 | Reflected Cross-Site Scripting (XSS) | High | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) |
| 6 | Unrestricted file upload / path traversal | High | [CWE-434](https://cwe.mitre.org/data/definitions/434.html) |
| 7 | Debug mode enabled, bound to all interfaces | Medium | [CWE-94](https://cwe.mitre.org/data/definitions/94.html) / [CWE-605](https://cwe.mitre.org/data/definitions/605.html) |
| 8 | Hardcoded secret key in source | Low | [CWE-259](https://cwe.mitre.org/data/definitions/259.html) |

**Result:**
- Bandit findings: **9 issues (3 High, 3 Medium, 3 Low) → 2 informational Low-severity notes**
- Automated exploit-payload tests: **18/18 passing** against the remediated app

Full root-cause analysis, exploit scenario, and code-level fix for every
row above: [`reports/SECURITY_REVIEW_REPORT.md`](reports/SECURITY_REVIEW_REPORT.md)

---

## Methodology

1. **Static analysis** — [Bandit](https://bandit.readthedocs.io/) v1.9.4 (Python-specific SAST) scanned for known-insecure patterns.
2. **Manual code review** — line-by-line inspection of request handling, auth, storage, and I/O, which caught an issue (unrestricted file upload) that the automated scan missed entirely.
3. **Remediation** — every finding fixed in a parallel, clean file (`secure_app_fixed.py`) so the before/after is directly diffable.
4. **Automated verification** — a pytest suite that doesn't just check the code *looks* fixed, it fires the actual exploit payloads (`' OR '1'='1'`, `<script>...`, shell metacharacters, raw pickle bytes, `../../etc/passwd` filenames) at the running app and asserts they're rejected.
5. **Regression testing** — re-running Bandit and the full test suite after fixes surfaced two functional bugs introduced during remediation (a broken redirect, a hardcoded binary path) — both fixed and now covered by dedicated tests.

---

## Getting started

```bash
git clone <your-repo-url>
cd secure-coding-review
pip install -r requirements.txt

# Run the static analyzer against both versions
bandit -r app/vulnerable_app.py -f txt      # findings expected
bandit -r app/secure_app_fixed.py -f txt    # clean (informational only)
```

To run the fixed app locally:

```bash
export FLASK_SECRET_KEY="replace-with-a-random-value"
python3 app/secure_app_fixed.py
```

---

## Running the tests

```bash
export FLASK_SECRET_KEY="test-secret"
pytest tests/ -v
```

Expected result: **18 passed**. Each test is named after the exploit it
attempts, e.g. `test_classic_sqli_payload_does_not_bypass_login`,
`test_disallowed_extension_rejected`, `test_dashboard_route_resolves`.

---

## Continuous Integration

[`.github/workflows/security-checks.yml`](.github/workflows/security-checks.yml)
runs on every push and pull request:

- Bandit against the vulnerable app (findings expected, informational)
- Bandit against the fixed app, **failing the build on any Medium/High finding**
- The full pytest security regression suite

This means the "before → after" story in this repo isn't just a
one-time snapshot — it's continuously enforced.

---

## Full report

📄 **[reports/SECURITY_REVIEW_REPORT.md](reports/SECURITY_REVIEW_REPORT.md)**
— methodology, all 8 findings with impact and fix, the functional bugs
found during verification, and general secure-coding recommendations.

📄 Raw evidence: [`bandit_raw_output.txt`](reports/bandit_raw_output.txt) ·
[`bandit_fixed_output.txt`](reports/bandit_fixed_output.txt) ·
[`pytest_output.txt`](reports/pytest_output.txt)

---

## Skills demonstrated

`Application Security` · `Secure Code Review` · `Static Analysis (SAST)` ·
`OWASP Top 10 vulnerability classes` · `Python / Flask` ·
`Automated Security Testing (pytest)` · `CI/CD (GitHub Actions)` ·
`Technical Documentation`

---

## About

Completed as part of the **CodeAlpha Cyber Security Internship**
— Task 3: Secure Coding Review.

**[Your Name]** · [LinkedIn](#) · [GitHub](#)
