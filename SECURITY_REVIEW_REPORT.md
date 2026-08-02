# Secure Coding Review Report
**Project:** VulnShop – Sample Flask E-Commerce Backend
**Prepared for:** CodeAlpha Cyber Security Internship — Task 3
**Reviewer:** [Your Name]
**Date:** August 2, 2026
**Language / Framework:** Python 3.12 / Flask

---

## 1. Objective

This report documents a secure code review of a small Flask-based web
backend (`app/vulnerable_app.py`). The goal was to identify security
vulnerabilities using a combination of **automated static analysis** and
**manual inspection**, assess their severity, and provide concrete
remediation. A fully remediated version of the application is provided at
`app/secure_app_fixed.py` for direct comparison.

## 2. Methodology

| Step | Tool / Method |
|---|---|
| Static analysis | [Bandit](https://bandit.readthedocs.io/) v1.9.4 — Python-specific SAST tool |
| Manual review | Line-by-line inspection of request handling, authentication, data storage, and I/O |
| Functional / regression testing | 18 automated `pytest` cases exercising the running application, including attempted exploit payloads |
| Verification | Re-ran Bandit and the full test suite against the remediated code to confirm every finding was actually resolved, not just visually patched |

Commands used:
```bash
bandit -r app/vulnerable_app.py -f txt
bandit -r app/secure_app_fixed.py -f txt
pytest tests/ -v
```

Full raw tool output is included at `reports/bandit_raw_output.txt` (before fixes),
`reports/bandit_fixed_output.txt` (after fixes), and `reports/pytest_output.txt`
(18/18 automated tests passing against the remediated app).

> **Why three methods, not one:** static analysis alone misses
> business-logic issues (it did not catch the unrestricted file upload, and
> it under-rated the SQL injection as "Low confidence"); manual review alone
> doesn't scale and doesn't *prove* a fix works; running the actual app
> caught two functional regressions — described in §5 — that neither
> static analysis nor a casual read-through surfaced.

## 3. Summary of Findings

| # | Vulnerability | Severity | CWE | Location |
|---|---|---|---|---|
| 1 | Hardcoded secret key | Low | [CWE-259](https://cwe.mitre.org/data/definitions/259.html) | `vulnerable_app.py:23` |
| 2 | SQL Injection (string concatenation) | **Critical** | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) | `vulnerable_app.py:49` |
| 3 | Weak password hashing (unsalted MD5) | High | [CWE-327](https://cwe.mitre.org/data/definitions/327.html) | `vulnerable_app.py:73` |
| 4 | Reflected Cross-Site Scripting (XSS) | High | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) | `vulnerable_app.py:89` |
| 5 | OS Command Injection (`shell=True`) | **Critical** | [CWE-78](https://cwe.mitre.org/data/definitions/78.html) | `vulnerable_app.py:99` |
| 6 | Insecure Deserialization (`pickle.loads`) | **Critical** | [CWE-502](https://cwe.mitre.org/data/definitions/502.html) | `vulnerable_app.py:109` |
| 7 | Unrestricted file upload / path traversal | High | [CWE-434](https://cwe.mitre.org/data/definitions/434.html) | `vulnerable_app.py:118` |
| 8 | Debug mode enabled, bound to all interfaces | Medium | [CWE-94](https://cwe.mitre.org/data/definitions/94.html) / [CWE-605](https://cwe.mitre.org/data/definitions/605.html) | `vulnerable_app.py:126` |

Bandit's automated scan flagged 6 of these 8 issues directly (with correct
CWE mapping); the SQL injection confidence was flagged "Low" by the tool
itself due to string-formatting heuristics, but manual review confirmed it
as a genuine, directly exploitable **Critical** issue. The unrestricted
file upload was not flagged by Bandit at all — it required manual
review, illustrating why automated tools should never be the only line
of defense.

---

## 4. Detailed Findings & Remediation

### 4.1 SQL Injection — Critical
**Issue:** User-supplied `username` and `password` are inserted directly
into a SQL query string via `%s` formatting, allowing an attacker to
inject arbitrary SQL (e.g. `' OR '1'='1' --`) and bypass authentication
entirely or exfiltrate the users table.

**Fix:** Use parameterized queries so the database driver handles
escaping, never the application:
```python
cursor = conn.execute(
    "SELECT password_hash FROM users WHERE username = ?", (username,)
)
```

### 4.2 Weak Password Hashing — High
**Issue:** Passwords are hashed with unsalted MD5, which is
cryptographically broken and crackable via rainbow tables in seconds.

**Fix:** Use `werkzeug.security.generate_password_hash`, which applies
PBKDF2-SHA256 with a random salt, and `check_password_hash` for
constant-time verification.

### 4.3 Reflected XSS — High
**Issue:** The `/search` endpoint injects the raw `q` parameter into an
HTML response, letting an attacker craft a URL that executes arbitrary
JavaScript in a victim's browser (session hijacking, credential theft).

**Fix:** Escape all user-controlled output before rendering:
```python
from markupsafe import escape
safe_term = escape(term)
```

### 4.4 OS Command Injection — Critical
**Issue:** `/ping` builds a shell command by string concatenation and
runs it with `shell=True`, so input like `127.0.0.1; rm -rf /` executes
arbitrary shell commands with the privileges of the web process.

**Fix:** Never use `shell=True` with user input. Use an argument list,
validate the host against a strict allow-list, and resolve the binary
path at runtime rather than hardcoding it (see §5 for why a hardcoded
path is itself a bug):
```python
if host not in ALLOWED_PING_HOSTS:
    return "Host not permitted", 400
ping_bin = shutil.which("ping")
if not ping_bin:
    return "ping utility not available on this host", 503
subprocess.run([ping_bin, "-c", "1", host], shell=False, ...)
```

### 4.5 Insecure Deserialization — Critical
**Issue:** `/load_cart` deserializes attacker-controlled bytes using
`pickle.loads`, which can execute arbitrary code during unpickling —
a well-known remote code execution vector.

**Fix:** Replace `pickle` with `json`, which cannot execute code:
```python
cart = json.loads(request.data)
```

### 4.6 Unrestricted File Upload — High
**Issue:** `/upload` saves files using the client-supplied filename with
no extension check and no sanitization, enabling path traversal
(`../../etc/passwd`) or the upload of executable web shells.

**Fix:** Enforce an extension allow-list and sanitize the filename with
`werkzeug.utils.secure_filename`.

### 4.7 Hardcoded Secret Key — Low
**Issue:** The Flask `secret_key` (used to sign session cookies) is a
plaintext literal in source code, so anyone with repo access can forge
session cookies.

**Fix:** Load from environment configuration and fail closed if unset:
```python
app.secret_key = os.environ.get("FLASK_SECRET_KEY")
if not app.secret_key:
    raise RuntimeError("FLASK_SECRET_KEY environment variable is not set")
```

### 4.8 Debug Mode / Bind-All-Interfaces — Medium
**Issue:** `debug=True` in a runnable entrypoint exposes the interactive
Werkzeug debugger, which allows arbitrary code execution if reached by an
attacker; binding to `0.0.0.0` exposes the dev server beyond localhost.

**Fix:** Gate debug mode behind an environment variable, default to
`False`, and bind to `127.0.0.1` unless a reverse proxy config says
otherwise.

---

## 5. Functional Bugs Found While Verifying the Fixes

Static analysis and a source-level read-through are not enough on their
own — they cannot tell you whether a "fixed" endpoint still actually
works. Running the remediated app end-to-end (via the `pytest` suite in
`tests/test_security.py`) surfaced two functional defects that were
invisible to Bandit and easy to miss by eye:

| # | Bug | Impact | Fix |
|---|---|---|---|
| 1 | `/login` redirected to `/dashboard`, but no `/dashboard` route existed | Every successful login resulted in a 404 for the user | Added a minimal `/dashboard` route |
| 2 | The command-injection fix hardcoded the path `/bin/ping` to satisfy a Bandit warning about "partial executable paths" | On systems where `ping` lives elsewhere (or isn't installed), the endpoint crashed with an unhandled 500 instead of failing safely | Resolve the binary at runtime with `shutil.which("ping")` and return a clean `503` if it isn't found — keeps the security property (no `shell=True`, no string-built command) without trading correctness for a quieter scanner |

This is called out explicitly because it's a common trap: chasing a
static analyzer's warning to zero can introduce new bugs if the "fix"
isn't also exercised functionally. Both defects are now covered by
regression tests (`test_dashboard_route_resolves`,
`test_allowed_host_does_not_500`) so they can't silently reappear.

## 6. Verification

After applying all fixes in `app/secure_app_fixed.py`, Bandit and the
full test suite were re-run:

**Static analysis (Bandit):**
- **Before:** 9 issues (3 Low, 3 Medium, 3 High)
- **After:** 2 issues (both Low, informational only — general awareness
  notes about using `subprocess` at all, already mitigated by the
  host allow-list and `shell=False`)

**Automated tests (pytest):**
- **18/18 tests passing**, including direct exploit-payload attempts for
  every finding in §4 (SQL injection strings, XSS payloads, shell
  metacharacters, raw pickle opcodes, disallowed file extensions, and
  path-traversal filenames). See `reports/pytest_output.txt` for the full
  run.

## 7. General Secure Coding Recommendations

1. **Never build queries via string formatting** — always use
   parameterized queries or an ORM.
2. **Never trust client input** for shell commands, deserialization, or
   file paths — validate against allow-lists, not blocklists.
3. **Hash secrets with purpose-built KDFs** (PBKDF2, bcrypt, Argon2),
   never general-purpose hashes like MD5/SHA1.
4. **Escape all output** rendered into HTML, even from "internal" data.
5. **Keep configuration out of source control** — secrets belong in
   environment variables or a secrets manager.
6. **Run static analysis in CI** (e.g. Bandit, Semgrep) so these classes
   of bugs are caught before merge, not after deployment.
7. **Disable debug/verbose modes** in anything resembling a production
   entrypoint, and default new configuration to the secure option.

## 8. Conclusion

The initial review identified 8 distinct vulnerabilities, including three
Critical-severity issues (SQL injection, command injection, insecure
deserialization) that would each independently allow full compromise of
the application or host. All findings were remediated and verified with
a second static analysis pass and an 18-case automated test suite that
actively attempts the original exploits against the fixed application.
The process also surfaced two functional regressions introduced along
the way, both since fixed and covered by regression tests. The combined
methodology — static analysis, manual review, and functional testing —
is recommended for any production codebase: each method caught issues
the other two missed.
