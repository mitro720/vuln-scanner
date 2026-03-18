# 🛡️ Vulnerability Scanner: Project Capabilities

This project is a comprehensive web security orchestration platform that combines a powerful Python scanning engine with a modern, real-time web interface.

---

## 🔍 1. Multi-Phase Reconnaissance
The scanner follows a structured approach to mapping the attack surface:

- **Subdomain Enumeration**: Discovers hidden subdomains using multiple sources (DNS, crt.sh, etc.).
- **Technology Fingerprinting**: Detects web servers, frameworks, and CMS (WordPress, Joomla, etc.).
- **WAF Detection**: Automatically identifies Web Application Firewalls protecting the target.
- **Sensitive File Probing**: Searches for exposed configuration files (.env, .git, etc.).
- **Crawler & API Discovery**: Maps the endpoint structure and identifies potential API routes.

## 🔌 2. Port & Service Discovery
- **Parallel Port Scanning**: Quickly identifies open ports using Nmap-inspired logic.
- **Service & Version Detection**: Grabs banners to identify the exact versions of running services.
- **Visual Survey**: Captures **automated screenshots** of all discovered web services for quick visual triage.

## 🛡️ 3. Vulnerability Analysis & Coverage
The scanner includes a library of over **26 specialized security modules** targeting the OWASP Top 10 and common web vulnerabilities:

### 💉 Injection Vulnerabilities
- **SQL Injection (SQLi)**: Automated detection of classic, error-based, and blind SQLi (Intensive mode available).
- **NoSQL Injection**: Probes for vulnerabilities in NoSQL databases like MongoDB.
- **Command Injection**: Detects OS command execution vulnerabilities (Intensive mode available).
- **SSTI (Server-Side Template Injection)**: Identifies template engine misconfigurations.
- **LDAP Injection**: Tests for malicious injection into directory services.
- **XXE (XML External Entity)**: Probes for unsafe XML processing.
- **CRLF Injection**: Checks for HTTP response splitting and header injection.

### 🔐 Authentication & Access Control
- **Broken Access Control (A01)**: Comprehensive checks for permission bypasses.
- **Identification & Authentication Failures (A07)**: Tests for session management and login flaws.
- **IDOR (Insecure Direct Object Reference)**: Identifies unauthorized access to resources.
- **JWT Vulnerabilities**: Checks for common JSON Web Token flaws (None algorithm, weak secrets).
- **Mass Assignment**: Probes for unauthorized field updates in API models.

### ⚙️ Configuration & Cryptography
- **Cryptographic Failures (A02)**: Identifies weak encryption or insecure transmission.
- **Security Misconfigurations (A05)**: General checks for insecure server settings.
- **CORS Misconfiguration**: Detects overly permissive Cross-Origin Resource Sharing.
- **Host Header Injection**: Tests for cache poisoning and password reset bypasses.
- **Rate Limit Bypass**: Probes for lack of throttling on sensitive endpoints.

### 🌐 Web-Specific Flaws
- **XSS (Cross-Site Scripting)**: In-depth detection of Reflected and Stored XSS.
- **SSRF (Server-Side Request Forgery)**: Tests if the server can be coerced into making internal requests.
- **XXE**: XML External Entity attacks.
- **GraphQL Abuse**: Probes for introspection and depth-limit issues.
- **Open Redirect**: Identifies unsafe user-controlled redirects.
- **Request Smuggling**: Detects desynchronization between front-end and back-end servers.

### 🐛 CVE Cross-Referencing
- **NVD Database Sync**: Detected service versions (from banner grabbing) are automatically cross-referenced with the **National Vulnerability Database**.
- **Version Detection**: Highly accurate version fingerprinting for web servers (Nginx, Apache, IIS) and common frameworks.
- **CVSS 3.1 Scoring**: Every finding is automatically assigned a normalized **CVSS score** for prioritization.

## ⚡ 4. Advanced Orchestration
- **Real-Time Live Scan**: Watch progress, logs, and findings stream in real-time via a high-performance websocket/polling bridge.
- **Modular Execution**: Run the full suite or target specific phases (e.g., *only* Recon or *only* OWASP checks).
- **Scan Control**: Full control to **Stop/Terminate** scans instantly if critical issues are found or resources need to be conserved.
- **Detailed Reporting**: Aggregates all findings into structured data for analysis.

## 🎨 5. Modern User Interface
- **Premium Glassmorphism UI**: High-fidelity dark mode interface with neon accents and fluid animations.
- **Interactive Dashboards**: Filter findings by severity, view technology breakdowns, and explore the attack surface map.
- **Activity Logs**: Detailed execution logs for debugging and deeper visibility into scan operations.

---

### 🚀 Stack Overview
- **Engine**: Python 3.x (Orchestration & Security Logic)
- **Backend**: Node.js / Express (API & Database Management)
- **Database**: Supabase / PostgreSQL (Persistent Storage)
- **Frontend**: React.js / Tailwind CSS (User Interface)
