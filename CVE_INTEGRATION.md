# CVE Database Integration Guide

## Overview

The vulnerability scanner now includes CVE (Common Vulnerabilities and Exposures) database integration, transforming it from a basic port scanner into a comprehensive vulnerability assessment tool. When services are detected, the scanner automatically queries vulnerability databases to identify known CVEs affecting specific software versions.

## Features

- ✅ **Service Version Detection** - Banner grabbing for HTTP, SSH, FTP, SMTP, and more
- ✅ **CVE Database Integration** - NVD API and Vulners API support
- ✅ **Automatic CVE Matching** - Matches detected versions against known vulnerabilities
- ✅ **CVSS Scoring** - Severity ratings (Critical/High/Medium/Low) with CVSS scores
- ✅ **Remediation Guidance** - Actionable fix recommendations
- ✅ **Rate Limiting & Caching** - Efficient API usage with 24-hour cache

## Quick Start

### 1. Get an NVD API Key (Recommended)

1. Visit https://nvd.nist.gov/developers/request-an-api-key
2. Fill out the form with your email
3. Check your email for the API key
4. Add it to your `.env` file

### 2. Configure Environment

Update `backend/.env`:

```env
# CVE Database Configuration
CVE_PROVIDER=nvd          # Options: nvd, vulners, both
NVD_API_KEY=your_api_key_here
CVE_CACHE_ENABLED=true
CVE_CACHE_TTL=86400       # 24 hours
```

### 3. Run Database Migration

Execute the CVE tables migration in your Supabase dashboard:

```bash
# Copy the contents of backend/database/migration_001_cve_tables.sql
# and run it in Supabase SQL Editor
```

### 4. Install Python Dependencies

```bash
cd scanner-core
pip install -r requirements.txt
```

### 5. Run a Scan with CVE Detection

```bash
# Test the CVE integration
python test_cve_integration.py

# Or run a full scan
python test_scanner.py
```

## How It Works

### 1. Port Scanning with Version Detection

When a port is found open, the scanner:
- Identifies the service (HTTP, SSH, FTP, etc.)
- Performs banner grabbing to detect the software version
- Extracts product name and version number

Example:
```
Port 80: HTTP
  Product: apache
  Version: 2.4.49
  Banner: Apache/2.4.49 (Unix)
```

### 2. CVE Matching

For each detected service with version info:
- Checks local known vulnerability database
- Queries NVD/Vulners API for additional CVEs
- Matches version against affected version ranges
- Retrieves full CVE details (description, CVSS, references)

### 3. Finding Generation

Each CVE match creates a finding with:
- CVE ID and description
- Severity level (Critical/High/Medium/Low)
- CVSS score and vector
- Affected service and version
- Remediation recommendations
- References to NVD and other sources

## API Endpoints

### Get Services for a Scan
```http
GET /api/scans/:scanId/services
```

Returns all detected services with version information.

### Get CVEs for a Scan
```http
GET /api/scans/:scanId/cves
```

Returns all CVEs found in a scan with service details and severity summary.

### Get CVE Statistics
```http
GET /api/scans/:scanId/cve-stats
```

Returns CVE statistics including count by severity and average CVSS score.

### Get CVE by ID
```http
GET /api/cves/:cveId
```

Returns full details for a specific CVE.

## Configuration Options

### CVE Provider Selection

**NVD (Recommended)**
- Official NIST database
- Free with API key
- Rate limit: 50 requests/30s with key
- Most authoritative source

**Vulners**
- 100 free API credits/month
- Better for software version searches
- Free CVE ID lookups

**Both**
- Uses NVD as primary, Vulners as fallback
- Best coverage but uses both quotas

### Scan Configuration

Enable/disable CVE detection in scan config:

```json
{
  "port_scan": true,
  "cve_detection": true,
  "cve_provider": "nvd"
}
```

## Testing

### Unit Tests

Test individual components:

```bash
# Test CVE client
cd scanner-core
python -c "from cve.cve_client import NVDClient; client = NVDClient(); print(client.get_cve_by_id('CVE-2021-44228'))"

# Test version detector
python -c "from cve.version_detector import VersionDetector; d = VersionDetector(); print(d.detect_version('example.com', 80, 'HTTP'))"
```

### Integration Test

Run the comprehensive test suite:

```bash
python test_cve_integration.py
```

This tests:
1. NVD API connectivity
2. Version detection
3. CVE matching
4. Full scan workflow

## Troubleshooting

### No CVEs Found

- **Check API key**: Ensure NVD_API_KEY is set correctly
- **Rate limiting**: Wait 30 seconds between scans
- **Network issues**: Verify internet connectivity
- **No version detected**: Some services don't expose version info

### Version Detection Fails

- **Firewall blocking**: Some hosts block banner grabbing
- **Timeout**: Increase timeout in VersionDetector
- **Unknown service**: Add custom detection logic

### API Rate Limits

- **NVD**: 50 requests/30s with key, 5 without
- **Vulners**: 100 credits/month free tier
- **Solution**: Enable caching (CVE_CACHE_ENABLED=true)

## Example Output

```
🔍 Scanning target: scanme.nmap.org

Port 22: SSH
  Product: openssh
  Version: 7.4
  CVEs Found: 2
    - CVE-2018-15473 (Medium, CVSS: 5.3)
    - CVE-2019-6109 (Medium, CVSS: 4.3)

Port 80: HTTP
  Product: apache
  Version: 2.4.49
  CVEs Found: 2
    - CVE-2021-41773 (Critical, CVSS: 9.8)
    - CVE-2021-42013 (Critical, CVSS: 9.8)

Total: 4 CVE vulnerabilities detected
```

## Next Steps

- **Frontend Integration**: Display CVEs in the UI with severity badges
- **Authenticated Scanning**: Add SSH/SMB credentials for internal version checks
- **Custom CVE Database**: Add your own vulnerability mappings
- **Reporting**: Include CVEs in PDF/CSV reports

## Resources

- [NVD API Documentation](https://nvd.nist.gov/developers/vulnerabilities)
- [Vulners API Documentation](https://vulners.com/docs)
- [CVSS Calculator](https://www.first.org/cvss/calculator/3.1)
- [CVE Database](https://cve.mitre.org/)
