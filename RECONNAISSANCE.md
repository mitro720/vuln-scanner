# Advanced Reconnaissance Guide

## 🎯 Overview

The scanner now includes **advanced reconnaissance capabilities** for comprehensive attack surface discovery:

1. **Subdomain Enumeration** - Multiple techniques to find subdomains
2. **API Discovery** - Intelligent API endpoint detection

---

## 🌐 Subdomain Discovery

### Features

✅ **DNS Brute-force** - Test common subdomain names
✅ **Certificate Transparency** - Query CT logs (crt.sh)
✅ **Search Engine Discovery** - Use public APIs
✅ **DNS Zone Transfer** - Attempt AXFR
✅ **Parallel Processing** - Fast multi-threaded scanning

### Usage

```python
from recon.subdomain_scanner import SubdomainScanner

# Create scanner
scanner = SubdomainScanner("example.com")

# Run all methods
results = scanner.scan(methods=['all'])

# Or specific methods
results = scanner.scan(methods=['certificate_transparency', 'dns_bruteforce'])

# Results
print(f"Found {results['count']} subdomains:")
for subdomain in results['subdomains']:
    print(f"  - {subdomain}")
```

### Discovery Methods

| Method | Speed | Accuracy | Requires |
|--------|-------|----------|----------|
| **Certificate Transparency** | ⚡ Fast | 🎯 High | Internet |
| **DNS Brute-force** | 🐌 Slow | 🎯 High | Wordlist |
| **Search Engine** | ⚡ Fast | 📊 Medium | API access |
| **Zone Transfer** | ⚡ Fast | 🎯 High | Misconfigured DNS |

### Custom Wordlist

Create your own subdomain wordlist:

```txt
# my_subdomains.txt
api
api-staging
api-prod
internal
secret
hidden
```

Use it:
```python
scanner = SubdomainScanner("example.com")
scanner.load_wordlist("my_subdomains.txt")
results = scanner.scan()
```

---

## 🔌 API Discovery

### Features

✅ **Common Path Probing** - Test 50+ common API paths
✅ **Documentation Detection** - Find Swagger, OpenAPI, GraphQL docs
✅ **JavaScript Analysis** - Extract endpoints from JS code
✅ **Endpoint Categorization** - Auto-categorize by type
✅ **Spec Parsing** - Parse OpenAPI/Swagger specifications

### Usage

```python
from recon.api_discovery import APIDiscovery

# Create scanner
api_scanner = APIDiscovery("https://example.com")

# Run discovery
results = api_scanner.discover(methods=['all'])

# Results
print(f"Found {results['count']} API endpoints:")
for category, endpoints in results['categorized'].items():
    print(f"\n{category.upper()}:")
    for endpoint in endpoints:
        print(f"  - {endpoint}")
```

### Discovery Methods

| Method | Description | Finds |
|--------|-------------|-------|
| **common_paths** | Probe known API paths | `/api`, `/v1`, `/rest`, etc. |
| **documentation** | Find API docs | Swagger, OpenAPI, GraphQL |
| **javascript** | Parse JS for endpoints | Fetch/Axios calls |

### Endpoint Categories

Automatically categorizes discovered endpoints:

- **auth** - Authentication/login endpoints
- **users** - User management
- **admin** - Administrative functions
- **data** - Data/CRUD operations
- **files** - File upload/download
- **other** - Miscellaneous

### Example Output

```json
{
  "base_url": "https://example.com",
  "count": 47,
  "endpoints": [
    "https://example.com/api/v1/users",
    "https://example.com/api/v1/auth/login",
    "https://example.com/api/v2/products",
    ...
  ],
  "documentation": {
    "https://example.com/swagger-ui.html": {
      "type": "Swagger/OpenAPI",
      "status": 200
    }
  },
  "categorized": {
    "auth": [
      "https://example.com/api/v1/auth/login",
      "https://example.com/oauth/token"
    ],
    "users": [
      "https://example.com/api/v1/users",
      "https://example.com/api/v1/profile"
    ]
  }
}
```

---

## 🚀 Integration with Scanner

### In Scan Configuration

```javascript
{
  target_url: "https://example.com",
  scan_type: "full",
  config: {
    subdomain: true,        // Enable subdomain discovery
    api: true,              // Enable API discovery
    subdomain_methods: ['certificate_transparency', 'dns_bruteforce'],
    api_methods: ['common_paths', 'documentation', 'javascript']
  }
}
```

### Scan Workflow

1. **Subdomain Discovery** → Find all subdomains
2. **API Discovery** → Find API endpoints on main domain + subdomains
3. **Web Crawling** → Crawl discovered URLs
4. **Vulnerability Scanning** → Test all discovered attack surface

---

## 📊 Performance

### Subdomain Discovery

- **Certificate Transparency**: ~5-10 seconds
- **DNS Brute-force** (200 subdomains): ~30-60 seconds
- **Search Engine**: ~5 seconds
- **Zone Transfer**: ~2 seconds

### API Discovery

- **Common Paths**: ~10-20 seconds
- **Documentation**: ~5 seconds
- **JavaScript Analysis**: ~30-60 seconds

---

## 🎯 Best Practices

### Subdomain Discovery

1. **Start with CT logs** - Fast and comprehensive
2. **Use custom wordlists** - Target-specific subdomains
3. **Combine methods** - Maximum coverage
4. **Respect rate limits** - Don't overwhelm DNS servers

### API Discovery

1. **Check documentation first** - Easiest way to find endpoints
2. **Analyze JavaScript** - Modern apps expose APIs in JS
3. **Test common paths** - Many APIs follow conventions
4. **Categorize findings** - Prioritize high-value endpoints

---

## 🔒 Ethical Considerations

> [!WARNING]
> **Legal Notice**
> - Only scan domains you own or have permission to test
> - Subdomain enumeration may trigger security alerts
> - Respect robots.txt and rate limits
> - Some techniques may be considered reconnaissance/OSINT

---

## 📚 Resources

**Subdomain Discovery:**
- Sublist3r: https://github.com/aboul3la/Sublist3r
- Amass: https://github.com/OWASP/Amass
- Certificate Transparency: https://crt.sh

**API Discovery:**
- OWASP API Security: https://owasp.org/www-project-api-security/
- Swagger/OpenAPI: https://swagger.io/
- Postman Collections: https://www.postman.com/

---

## 🛠️ Advanced Usage

### Combine with Vulnerability Scanning

```python
from recon.subdomain_scanner import SubdomainScanner
from recon.api_discovery import APIDiscovery
from owasp.a03_injection import SQLiModule

# 1. Find subdomains
subdomain_scanner = SubdomainScanner("example.com")
subdomain_results = subdomain_scanner.scan()

# 2. Find APIs on each subdomain
all_endpoints = []
for subdomain in subdomain_results['subdomains']:
    api_scanner = APIDiscovery(f"https://{subdomain}")
    api_results = api_scanner.discover()
    all_endpoints.extend(api_results['endpoints'])

# 3. Test for vulnerabilities
sqli_scanner = SQLiModule("https://example.com")
findings = sqli_scanner.scan(all_endpoints)
```

### Export Results

```python
import json

# Save subdomain results
with open('subdomains.json', 'w') as f:
    json.dump(subdomain_results, f, indent=2)

# Save API results
with open('api_endpoints.json', 'w') as f:
    json.dump(api_results, f, indent=2)
```

---

**Happy Hunting! 🎯**
