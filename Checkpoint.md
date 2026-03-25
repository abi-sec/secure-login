Software Security (CS 6417) Project Workflow
SDLC Framework
DevSecOps. We selected DevSecOps to guarantee automated, repeatable security validation across development and operations. DevSecOps embeds security into CI/CD (pre-merge SAST and dependency checks, pre-release DAST and fuzzing, and runtime audit logging and RBAC enforcement), producing reproducible artifacts and measurable metrics (e.g., build failures on high-severity CVEs, fuzz crash reports) required for our graduate-level deliverables. This approach ensures continuous security feedback, enforces security acceptance criteria on every PR, and enables incremental hardening of sensitive features (RBAC, encrypted storage, audit trails) with operational monitoring and auditability.
Why not Agile: We decided not to use Agile by itself. Agile supports iterative development but often depends on manual security work that can be deprioritized or missed. For our grad project we need automated, repeatable evidence (SAST/DAST/fuzzing/audit logs), so DevSecOps, which enforces security gates in CI/CD is a better fit.

•	Framework: GitHub Actions, Docker
•	Gate 1 (Dependencies): npm audit (Blocks vulnerable libraries).
•	Gate 2 (Code Quality): eslint-plugin-security (Blocks insecure coding patterns).
•	Gate 3 (Testing): OWASP ZAP (Automated attack scan) or Burp suite

Software Requirement Analysis
Technology Stack: Node.js, Express, EJS (Vanilla), PostgreSQL
For this project, we haven’t chosen fully automated frameworks in favour of a stack that requires manual security configuration
1. Why Node.js (Express) over Python (Django/Flask)?
•	Unlike Django, which has built-in security "magic," Express requires us to manually implement the security middleware.
•	Node’s event-loop model allows us to address specific Denial of Service (DoS) threats, such as Event Loop Blocking.
•	The npm registry is the largest software library in existence. Tools like npm audit and snyk allow for software analysis. In our project, we can demonstrate automatically blocking a build if a library has a known vulnerability.

2. Why Vanilla JS (EJS) over React?
While React is the industry standard, we have opted for Server-Side Rendering (SSR) via EJS for the following security-centric reasons:
•	React automatically sanitizes data. By using EJS, we must manually handle Output Encoding
•	React adds thousands of dependencies to the frontend. A Vanilla approach minimizes that risk as our web application only has 2 pages.
•	Standard SSR allows for simpler, more secure Stateful Sessions via HttpOnly cookies, avoiding the common security pitfalls of storing JWTs in React's localStorage (where they are vulnerable to XSS).
3. Why PostgreSQL?
•	Unlike MongoDB (which is schema-less), PostgreSQL enforces a strict schema. This prevents Data Injection or malformed data from being stored, which is a common source of application logic vulnerabilities.
•	PostgreSQL’s use of Parameterized SQL is a more mature and well-understood defence mechanism.
•	PostgreSQL supports pgcrypto, allowing for hashing and encryption to happen inside the database if needed, providing a secondary layer of defence.
•	PostgreSQL has sophisticated internal logging that can track every single query made to the database. This satisfies our project requirement of Restricted Database Access and Audit Logging much better than a simple file-based system like SQLite.

Technical Library/Tool Mapping based on Functional requirements

1. Authentication & User Management
•	passport.js (with passport-local) [Backend layer]
o	Handles the logic for checking credentials and maintaining the user session.
•	argon2 [Backend layer]
o	Cryptographic hashing of user passwords.
o	Unlike older algorithms like SHA-256 or Bcrypt, Argon2 is/ works better. It is memory-hard, making it significantly more resistant to GPU-based cracking (modern).
•	express-session [Backend layer]
o	Manages server-side session state.
o	Configured to use httpOnly: true (prevents XSS from stealing cookies) and sameSite: 'strict' (mitigates CSRF).
•	zxcvbn [Frontend layer]
o	Password strength estimation.
o	Instead of weak rules, this calculates the randomness of a password to ensure users pick passwords that are actually hard to crack.
2. Input Handling & File Security
•	express-validator [Backend layer]
o	Middleware for sanitizing and validating string inputs (Feedback field).
o	Good for implementing a whitelist which is only allowing expected characters and stripping out potential script tags to prevent Cross-Site Scripting (XSS).
•	multer [Backend layer]
o	Middleware for handling multipart/form-data (File Uploads).
o	Allows for strict limits configuration. We will set a MB limit(preferably between 2 to 10 MB) to prevent Disk Exhaustion Denial of Service (DoS).
•	file-type [Backend layer]
o	Binary inspection of uploaded files.
o	Attackers can rename a .exe to .jpg. This library checks the hex signatures in the file header to verify the actual content type.
•	uuid [Backend layer]
o	Unique ID generation for filenames.
o	By renaming every uploaded file to a random UUID, we prevent Directory Traversal attacks and Insecure direct object reference (IDOR) where users guess other filenames.
3. Infrastructure & Database Security
•	helmet [Backend layer]
o	Automatically configures secure HTTP headers.
o	Sets headers like Content-Security-Policy (CSP) and X-Frame-Options to protect the browser from clickjacking and unauthorized script execution.
•	Vanilla JS/EJS [Frontend/Template]
o	Basic client-side validation and UI logic.
o	Used for immediate feedback (e.g., checking file size before the upload starts) to improve UX and reduce unnecessary server load.
•	sequelize (PostgreSQL ORM) [Database layer]
o	Database abstraction layer.
o	Uses Parameterized Queries by default. This separates the "code" of the query from the "data" of the user input, making SQL Injection impossible.
•	crypto (Built-in Node module) [Database Layer]
o	Symmetric encryption for personal info (identifiers).
o	Used to encrypt sensitive fields like email addresses at rest using AES-256, ensuring that even if the database is leaked, the data remains unreadable.
•	express-rate-limit [Backend layer]
o	Rate limiting for API endpoints.
o	Prevents Brute-Force attacks on the login page and protects the File Upload endpoint from being flooded by an attacker.
4. Logging & Auditing (SDLC Integration)
•	winston [Backend layer]
o	Structured audit logging.
o	Logs critical security events (failed logins, privilege escalations). Unlike console.log, these can be formatted as JSON for easy analysis in security monitoring tools.
•	eslint-plugin-security [Backend layer]
o	Static Application Security Testing (SAST).
o	Automatically identifies dangerous/bad code patterns in Node.js (like eval() or child_process) before the code is ever deployed.
5. Security Testing
o	DAST-OWASP ZAP
o	DAST-Burpsuite

 

