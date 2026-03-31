# Secure Login Page (v3)

A security-focused web application.

**Stack:** Node.js · Express · EJS · PostgreSQL · GitHub Actions

### v3 Enhancements
- **Restricted Database Access:** Service connections use least privilege `app_user`.
- **Encrypted Audit Logging:** Security events are persisted directly into an encrypted `audit_log` PostgreSQL table.

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

Open `.env` and fill in your `DB_PASSWORD` (your root Postgres password). Leave `APP_DB_USER` and `APP_DB_PASSWORD` exactly as they are—the automated migrations will create this restricted user for you later!

Then, generate and fill in the encryption secrets (same command on both platforms):

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
