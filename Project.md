Objective
The goal of this project is to design and implement a small web-based application while
applying software security principles throughout the Software Development Life Cycle (SDLC).
Students will focus on secure design, threat modeling, attack analysis, and validation, rather
than exploitation.
•
UG students: Focus on identifying and mitigating common software security flaws,
implementing secure login and input handling, and basic testing.
•
Grad students: Extend the project with advanced threat modeling, role-based access
control, logging, automated security testing, fuzzing, and quantitative risk analysis.
Functional Requirements
1. Login & User Management
o Must allow log in and log out, change password, and add new users/customers
with least privilege.
o Graduate enhancement: Logging of authentication attempts and enforce strong
password policies.
2. Input Field (e.g., Feedback / Contact Page)
o Must implement proper input validation to prevent injection attacks.
o Grad enhancement: Students need to include a single, restricted file upload (e.g.,
PDF, image, or text file) associated with the input page. The purpose of the upload
is to demonstrate secure handling of untrusted file input through type and size
validation, safe storage practices, and robust error handling. The upload is not
intended to provide business functionality
3. Database
o Store data securely using hashed passwords and parameterized queries.
o Grad enhancement: Implement audit logging, encrypted storage, and restricted
database access.
Project Workflow
1. SDLC Selection
o Choose Agile or DevOps approach.
o Justify your choice with respect to software security considerations.
Software Security (CS 4417/6417)
Instructor – Saqib Hakak
o Grad students should discuss how the SDLC integrates security in CI/CD or sprint
planning (Graduate students must clearly identify where security activities occur in
their chosen SDLC. General statements such as “security was considered
throughout development” are insufficient. The report must reference specific SDLC
stages (e.g., sprint planning, CI pipeline) and specific security-related actions
performed at those stages).
2. Attack Surface & Attack Tree
o Identify all entry points for your application (attack surface).
o Design a login page attack tree:
▪
UG: Depth ≥ 3, including credential attacks, input attacks, and authorization
bypass.
▪
Grad: Extend the attack tree to include session-related attacks (e.g., session
fixation/hijacking), multi-factor authentication bypass, and brute-force or
rate-limiting evasion.
3. Threat Modeling & Security Analysis
o Map vulnerabilities to CWE.
o Suggest mitigations for each threat.
4. Testing & Validation
o Verify authentication strength and input validation.
o Optional: use automated tools or fuzzing.
o Grad students: perform advanced security testing and document remediation
workflow.
Group Work & Individual Contributions
•
Groups: 3–4 students
•
Roles: Developer, Security Analyst, Tester (roles may rotate).
•
Collaboration: Groups must document individual contributions in a dedicated report
section. Each member should specify tasks completed and provide evidence (code
commits, screenshots, diagrams, test reports).
Deliverables
1. Project Report: Includes SDLC choice, attack surface & attack tree, threat analysis,
testing results, and individual contributions.
2. Working Application: Implements secure login, input handling, and database storage
(with enhancements for Grad students).
3. Optional Supplementary Material: Fuzzer outputs, automated tool reports, or extended
security testing documentation.
Grading Emphasis
•
Functional correctness (login, input handling, database) – 10 points
•
Security testing – 10 points
•
Individual contributions and Final report – 5 points