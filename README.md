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

