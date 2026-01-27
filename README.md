# Vulnerability Scanner

<div align="center">

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![Node](https://img.shields.io/badge/node-18+-green.svg)

**Advanced Web Vulnerability Scanner with AI-Powered Analysis**

[Quick Start](#-quick-start) • [Features](#-features) • [Documentation](#-documentation) • [Demo](#-demo)

</div>

---

## 🎯 Overview

A comprehensive web vulnerability scanner that combines automated detection with AI-powered analysis. Built with modern technologies and designed for security professionals, developers, and learners.

### Key Highlights

- ✅ **14 Vulnerability Modules** - SQL Injection, XSS, SSRF, XXE, Command Injection, and more
- 🤖 **AI Assistant** - Multi-provider support (OpenAI, Anthropic, Google, Ollama)
- 🎓 **Educational** - Built-in knowledge base with learning resources
- 🔍 **Advanced Recon** - Subdomain enumeration, API discovery
- 📊 **Professional Reporting** - CWE/CVSS scoring, detailed evidence
- 🎨 **Modern UI** - Beautiful React interface with real-time updates

---

## 🚀 Quick Start

### One-Command Startup

**Windows:**
```bash
start.bat
```

**Linux/Mac:**
```bash
chmod +x start.sh
./start.sh
```

**Using NPM:**
```bash
npm install
npm start
```

That's it! Open http://localhost:5173 in your browser.

### First-Time Setup

```bash
# 1. Clone repository
git clone <your-repo-url>
cd vulnerability-scanner

# 2. Install all dependencies
npm run install:all

# 3. Start application
npm start
```

See [QUICKSTART.md](./QUICKSTART.md) for detailed instructions.

---

## ✨ Features

### 🔒 Vulnerability Detection

| Category | Modules | CVSS Range |
|----------|---------|------------|
| **Injection** | SQL, NoSQL, Command, XXE, XSS | 6.1 - 9.8 |
| **Authentication** | JWT, Session, Weak Credentials | 3.1 - 9.8 |
| **Access Control** | Path Traversal, IDOR | 7.5 - 8.1 |
| **Security Config** | CORS, Headers, SSL/TLS | 4.2 - 7.5 |
| **SSRF** | Server-Side Request Forgery | 8.6 |
| **File Upload** | Unrestricted Upload | 9.0 |

**Total: 14+ Detection Modules** | [View All Modules](./VULNERABILITY_MODULES.md)

### 🤖 AI-Powered Analysis

Choose your preferred AI provider:

- **OpenAI (GPT-4)** - Best quality analysis
- **Anthropic (Claude)** - Long context, detailed remediation
- **Google (Gemini)** - Free tier available
- **Ollama** - 100% free, runs locally, privacy-focused
- **Custom API** - Bring your own endpoint

**AI Features:**
- Plain English vulnerability explanations
- Custom remediation advice for your tech stack
- Personalized learning recommendations
- Risk assessment and exploitation scenarios
- Code fix suggestions with examples

[AI Integration Guide](./AI_INTEGRATION.md)

### 🔍 Advanced Reconnaissance

- **Subdomain Discovery**
  - DNS brute-force (150+ common subdomains)
  - Certificate Transparency logs
  - Search engine discovery
  - DNS zone transfer attempts

- **API Endpoint Discovery**
  - Common path probing (50+ patterns)
  - API documentation detection (Swagger, OpenAPI, GraphQL)
  - JavaScript analysis for hidden endpoints
  - Automatic categorization

[Reconnaissance Guide](./RECONNAISSANCE.md)

### 🎓 Educational Knowledge Base

- Detailed vulnerability explanations
- How it works (step-by-step)
- Real-world breach examples
- Vulnerable vs Secure code examples
- Prevention techniques
- Learning resources (PortSwigger, OWASP, HackTheBox)
- Recommended tools

### 📊 Professional Reporting

- **CWE Mappings** - 25+ vulnerability types
- **CVSS 3.1 Scoring** - Automated severity calculation
- **Evidence Collection** - Payloads, responses, proof-of-concept
- **Remediation Steps** - Actionable fix guidance
- **Export Options** - PDF, JSON, HTML reports

---

## 🏗️ Architecture

```
vulnerability-scanner/
├── frontend/          # React + Vite UI
├── backend/           # Node.js + Express API
├── scanner-core/      # Python scanning engine
│   ├── owasp/        # Vulnerability modules
│   ├── recon/        # Reconnaissance modules
│   ├── ai/           # AI assistant
│   ├── core/         # Core utilities (CVSS, CWE)
│   └── knowledge/    # Educational content
└── docs/             # Documentation
```

**Tech Stack:**
- Frontend: React, Vite, Tailwind CSS
- Backend: Node.js, Express, Supabase
- Scanner: Python 3.8+, Requests, BeautifulSoup
- AI: OpenAI, Anthropic, Google, Ollama APIs

---

## 📚 Documentation

| Document | Description |
|----------|-------------|
| [QUICKSTART.md](./QUICKSTART.md) | Installation and setup guide |
| [VULNERABILITY_MODULES.md](./VULNERABILITY_MODULES.md) | Complete module documentation |
| [AI_INTEGRATION.md](./AI_INTEGRATION.md) | AI assistant setup and usage |
| [RECONNAISSANCE.md](./RECONNAISSANCE.md) | Recon features guide |
| [CUSTOM_PAYLOADS.md](./CUSTOM_PAYLOADS.md) | Custom payload system |

---

## 🎨 Screenshots

### Dashboard
![Dashboard](./screenshots/dashboard.png)

### Live Scanning
![Live Scan](./screenshots/live-scan.png)

### Results & Analysis
![Results](./screenshots/results.png)

### Knowledge Base
![Knowledge Base](./screenshots/knowledge.png)

---

## 🛠️ Development

### Project Structure

```bash
# Start development servers
npm start                  # All services
npm run start:backend      # Backend only
npm run start:frontend     # Frontend only
npm run start:scanner      # Scanner only

# Build for production
npm run build

# Install dependencies
npm run install:all
```

### Adding New Modules

1. Create module in `scanner-core/owasp/`
2. Add CWE mapping in `core/cwe_database.py`
3. Add CVSS score in `core/cvss_calculator.py`
4. Add knowledge base entry in `knowledge/vulnerability_kb.py`
5. Update documentation

---

## 🔒 Security & Ethics

### ⚠️ Legal Notice

**IMPORTANT:** This tool is for authorized security testing only.

- ✅ Only scan systems you own or have explicit permission to test
- ✅ Respect robots.txt and rate limits
- ✅ Follow responsible disclosure practices
- ❌ Never use for unauthorized access or malicious purposes

**You are responsible for ensuring your use complies with all applicable laws.**

### Privacy

- API keys are encrypted at rest
- Use Ollama for 100% local, private scanning
- No data is sent to third parties (except chosen AI provider)
- All scan data stays on your infrastructure

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

---

## 📝 License

This project is licensed under the MIT License - see [LICENSE](./LICENSE) file for details.

---

## 🙏 Acknowledgments

- **OWASP** - Vulnerability classifications and testing guides
- **PortSwigger** - Web security research and education
- **MITRE** - CWE database
- **AI Providers** - OpenAI, Anthropic, Google, Ollama

---

## 📧 Contact

- **Issues**: [GitHub Issues](https://github.com/yourusername/vulnerability-scanner/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/vulnerability-scanner/discussions)

---

<div align="center">

**Built with ❤️ for the security community**

[⭐ Star this repo](https://github.com/yourusername/vulnerability-scanner) if you find it useful!

</div>
