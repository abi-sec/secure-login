# Secure Login Page

A security-focused web application.

**Stack:** Node.js · Express · EJS · PostgreSQL · GitHub Actions

---

## Quick Start

### Prerequisites
- Node.js 20+
- PostgreSQL 14+
- Git

### 1. Clone and install

**Windows (PowerShell):**
```powershell
git clone <your-repo-url>
cd <repo-folder>
npm install
```

**Linux/macOS (bash):**
```bash
git clone <your-repo-url>
cd <repo-folder>
npm install
```

### 2. Configure environment

**Windows (PowerShell):**
```powershell
Copy-Item .env.example .env
```

**Linux/macOS (bash):**
```bash
cp .env.example .env
```

Open `.env` and fill in your values. Generate secrets (same command on both platforms):

```bash
# SESSION_SECRET (64 random bytes)
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"

# ENCRYPTION_KEY (exactly 32 bytes = 64 hex chars)
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

### 3. Set up PostgreSQL

**Windows (PowerShell):**
```powershell
# Create database (requires PostgreSQL bin tools in PATH)
createdb secureapp

# Run migrations
npm run migrate
```

**Linux/macOS (bash):**
```bash
# Create database
createdb secureapp

# Run migrations
npm run migrate
```

**Restricted DB user (recommended):**
Connect to PostgreSQL as superuser and run:

```sql
CREATE USER appuser WITH PASSWORD 'choose_a_strong_password';
GRANT CONNECT ON DATABASE secureapp TO appuser;
GRANT USAGE ON SCHEMA public TO appuser;
GRANT SELECT, INSERT, UPDATE, DELETE ON users, feedback, audit_log TO appuser;
GRANT USAGE, SELECT ON SEQUENCE audit_log_id_seq TO appuser;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
```

Then set `DB_USER=appuser` and `DB_PASSWORD=...` in your `.env`.

### 4. Serve zxcvbn as a static file

zxcvbn is loaded client-side. Copy it to the public folder so Express can serve it:

**Windows (PowerShell):**
```powershell
Copy-Item node_modules/zxcvbn/dist/zxcvbn.js public/zxcvbn.js
```

**Linux/macOS (bash):**
```bash
cp node_modules/zxcvbn/dist/zxcvbn.js public/zxcvbn.js
```

### 5. Start the app

Both platforms:
```bash
# Development (auto-restart on file changes)
npm run dev

# Production
npm start
```

App runs at: **http://localhost:3000**

---

## Project Structure

```
secure-app/
├── .github/
│   └── workflows/
│       └── security.yml        ← CI/CD: 3-gate security pipeline
├── src/
│   ├── app.js                  ← Express entry point, all middleware wired up
│   ├── config/
│   │   ├── database.js         ← Sequelize + PostgreSQL
│   │   └── passport.js         ← passport-local strategy + account lockout
│   ├── models/
│   │   ├── User.js             ← Argon2id hashing + AES-256-GCM email encryption
│   │   └── Feedback.js         ← Feedback + UUID file metadata
│   ├── routes/
│   │   ├── auth.js             ← Login, logout, register, change password
│   │   └── feedback.js         ← Feedback form + file upload
│   ├── middleware/
│   │   ├── rateLimiter.js      ← Rate limiting: login, register, upload
│   │   ├── fileValidator.js    ← multer + hex signature (file-type) inspection
│   │   └── rbac.js             ← requireAuth + requireRole middleware
│   ├── views/                  ← EJS templates (SSR — no React)
│   │   ├── login.ejs
│   │   ├── register.ejs
│   │   ├── feedback.ejs
│   │   └── error.ejs
│   └── utils/
│       └── logger.js           ← Winston structured JSON audit logger
├── migrations/
│   ├── 001_create_tables.sql   ← Schema: users, feedback, audit_log
│   └── run.js                  ← Migration runner
├── public/
│   └── zxcvbn.js               ← (copy from node_modules after install)
├── uploads/                    ← Uploaded files (UUID filenames only)
├── logs/                       ← Winston log output
├── .env.example
├── .eslintrc.json
└── package.json
```

---

## Security Architecture

### Authentication
| Control | Implementation |
|---|---|
| Password hashing | Argon2id (memory-hard, 64MB cost) |
| Session | express-session, httpOnly + sameSite:strict cookie |
| Brute force protection | Account lock after 5 failures (15 min), rate limiter (5 req/15 min/IP) |
| Enumeration prevention | Same error message for "user not found" and "wrong password" |
| Password strength | zxcvbn (client UX) + structural rules (server enforcement) |

### Input Handling
| Control | Implementation |
|---|---|
| Feedback field | express-validator whitelist — only expected characters pass |
| SQL Injection | Sequelize ORM — parameterized queries by default |
| XSS | EJS output encoding + `.escape()` on message field + helmet CSP |
| File type | multer (declared MIME) + file-type (hex signature) |
| File size | multer 5MB limit (client-side UX check + server enforcement) |
| IDOR/traversal | UUID filename — user input never touches the filesystem path |

### Infrastructure
| Control | Implementation |
|---|---|
| Security headers | helmet (CSP, X-Frame-Options, X-Content-Type-Options, HSTS) |
| PII encryption | AES-256-GCM on email field at rest |
| Audit logging | winston structured JSON + PostgreSQL audit_log table |
| RBAC | role column (user/admin) enforced per route via middleware |
| DB access | Restricted appuser with only DML privileges (no DDL) |

### CI/CD Security Gates
| Gate | Tool | Fails on |
|---|---|---|
| 1 — Dependencies | npm audit | HIGH or CRITICAL CVE |
| 2 — SAST | eslint-plugin-security | eval(), child_process, unsafe regex, timing attacks |
| 3 — DAST | OWASP ZAP baseline | Medium+ severity findings |

---

## Running Security Tools Locally

### Gate 1 and Gate 2

Both platforms:
```bash
# Gate 1 — Dependency audit
npm run audit-check

# Gate 2 — SAST
npm run lint
```

### Gate 3 — DAST (requires app running on port 3000)

**Windows (PowerShell):**
```powershell
docker run -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py `
  -t http://host.docker.internal:3000 `
  -r zap-report.html
```

**Linux/macOS (bash):**
```bash
docker run -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py \
  -t http://host.docker.internal:3000 \
  -r zap-report.html
```

---

## Report Checklist

For the CS 6417 final report, your group needs to produce:

- [ ] **SDLC justification** — DevSecOps chosen over Agile; security gates embedded in CI/CD at specific stages (pre-merge SAST, pre-release DAST)
- [ ] **Attack surface** — list all entry points (login form, register form, feedback form, file upload endpoint, session cookie)
- [ ] **Attack tree** (login page, depth ≥ 3) — include session fixation, session hijacking, MFA bypass, brute-force/rate-limit evasion
- [ ] **Threat model** — STRIDE mapping for each component
- [ ] **CWE mappings** — e.g. CWE-89 (SQLi), CWE-307 (brute force), CWE-434 (file upload), CWE-521 (weak password), CWE-613 (session expiry)
- [ ] **ZAP DAST report** — run the pipeline, capture findings, document remediations
- [ ] **Individual contributions** — commits, screenshots, test reports per member

---

## CWE Reference

| Threat | CWE | Mitigation in this app |
|---|---|---|
| SQL Injection | CWE-89 | Sequelize parameterized queries |
| XSS | CWE-79 | EJS encoding, express-validator .escape(), helmet CSP |
| Brute Force | CWE-307 | Rate limiter + account lockout |
| Weak Password | CWE-521 | Argon2id + zxcvbn + structural rules |
| Insecure File Upload | CWE-434 | multer + file-type hex inspection + UUID rename |
| IDOR | CWE-639 | UUID filenames — user input never used in paths |
| Session Fixation | CWE-384 | Session regenerated on login (passport behavior) |
| Sensitive Data Exposure | CWE-312 | AES-256-GCM on PII at rest |
| Missing Auth | CWE-306 | requireAuth middleware on all protected routes |
| Privilege Escalation | CWE-269 | requireRole middleware + logged escalation attempts |
| Path Traversal | CWE-22 | UUID filenames + restricted upload directory |
| Clickjacking | CWE-1021 | helmet X-Frame-Options + CSP frame-ancestors: none |

---

## Instructor Notes

- **DevSecOps over Agile**: Security is enforced at every PR via CI/CD gates, not manually remembered
- **Express over Django**: Manual security middleware implementation demonstrates understanding of each layer
- **EJS over React**: Forces manual output encoding; avoids React's automatic sanitization "magic"
- **PostgreSQL over MongoDB**: Schema enforcement + parameterized queries + pgcrypto support
- **Argon2id over bcrypt**: Memory-hard, resistant to GPU-based cracking attacks
- **AES-256-GCM over AES-256-CBC**: Authenticated encryption — detects ciphertext tampering
- **ZAP over Burp Suite**: Free + fully automatable in GitHub Actions without paid license
