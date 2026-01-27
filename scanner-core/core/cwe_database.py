"""
Vulnerability Classification Database
CWE, CVE, and CVSS mappings for all vulnerability types
"""

# CWE (Common Weakness Enumeration) Database
# Maps vulnerability types to official CWE IDs

CWE_DATABASE = {
    # Injection Vulnerabilities
    "sql_injection": {
        "cwe_id": "CWE-89",
        "name": "SQL Injection",
        "description": "Improper Neutralization of Special Elements used in an SQL Command",
        "url": "https://cwe.mitre.org/data/definitions/89.html",
        "owasp": "A03:2021"
    },
    "xss_reflected": {
        "cwe_id": "CWE-79",
        "name": "Cross-site Scripting (Reflected)",
        "description": "Improper Neutralization of Input During Web Page Generation",
        "url": "https://cwe.mitre.org/data/definitions/79.html",
        "owasp": "A03:2021"
    },
    "xss_stored": {
        "cwe_id": "CWE-79",
        "name": "Cross-site Scripting (Stored)",
        "description": "Improper Neutralization of Input During Web Page Generation",
        "url": "https://cwe.mitre.org/data/definitions/79.html",
        "owasp": "A03:2021"
    },
    "xss_dom": {
        "cwe_id": "CWE-79",
        "name": "Cross-site Scripting (DOM-based)",
        "description": "Improper Neutralization of Input During Web Page Generation",
        "url": "https://cwe.mitre.org/data/definitions/79.html",
        "owasp": "A03:2021"
    },
    "command_injection": {
        "cwe_id": "CWE-78",
        "name": "OS Command Injection",
        "description": "Improper Neutralization of Special Elements used in an OS Command",
        "url": "https://cwe.mitre.org/data/definitions/78.html",
        "owasp": "A03:2021"
    },
    "ldap_injection": {
        "cwe_id": "CWE-90",
        "name": "LDAP Injection",
        "description": "Improper Neutralization of Special Elements used in an LDAP Query",
        "url": "https://cwe.mitre.org/data/definitions/90.html",
        "owasp": "A03:2021"
    },
    "xpath_injection": {
        "cwe_id": "CWE-643",
        "name": "XPath Injection",
        "description": "Improper Neutralization of Data within XPath Expressions",
        "url": "https://cwe.mitre.org/data/definitions/643.html",
        "owasp": "A03:2021"
    },
    "xxe": {
        "cwe_id": "CWE-611",
        "name": "XML External Entity (XXE)",
        "description": "Improper Restriction of XML External Entity Reference",
        "url": "https://cwe.mitre.org/data/definitions/611.html",
        "owasp": "A05:2021"
    },
    
    # Access Control
    "path_traversal": {
        "cwe_id": "CWE-22",
        "name": "Path Traversal",
        "description": "Improper Limitation of a Pathname to a Restricted Directory",
        "url": "https://cwe.mitre.org/data/definitions/22.html",
        "owasp": "A01:2021"
    },
    "idor": {
        "cwe_id": "CWE-639",
        "name": "Insecure Direct Object Reference (IDOR)",
        "description": "Authorization Bypass Through User-Controlled Key",
        "url": "https://cwe.mitre.org/data/definitions/639.html",
        "owasp": "A01:2021"
    },
    "broken_access_control": {
        "cwe_id": "CWE-284",
        "name": "Broken Access Control",
        "description": "Improper Access Control",
        "url": "https://cwe.mitre.org/data/definitions/284.html",
        "owasp": "A01:2021"
    },
    
    # Cryptographic Issues
    "weak_crypto": {
        "cwe_id": "CWE-327",
        "name": "Weak Cryptography",
        "description": "Use of a Broken or Risky Cryptographic Algorithm",
        "url": "https://cwe.mitre.org/data/definitions/327.html",
        "owasp": "A02:2021"
    },
    "insecure_tls": {
        "cwe_id": "CWE-326",
        "name": "Inadequate Encryption Strength",
        "description": "Inadequate Encryption Strength",
        "url": "https://cwe.mitre.org/data/definitions/326.html",
        "owasp": "A02:2021"
    },
    "missing_https": {
        "cwe_id": "CWE-319",
        "name": "Cleartext Transmission",
        "description": "Cleartext Transmission of Sensitive Information",
        "url": "https://cwe.mitre.org/data/definitions/319.html",
        "owasp": "A02:2021"
    },
    "sensitive_data_exposure": {
        "cwe_id": "CWE-200",
        "name": "Information Exposure",
        "description": "Exposure of Sensitive Information to an Unauthorized Actor",
        "url": "https://cwe.mitre.org/data/definitions/200.html",
        "owasp": "A02:2021"
    },
    
    # Security Misconfiguration
    "missing_security_headers": {
        "cwe_id": "CWE-693",
        "name": "Missing Security Headers",
        "description": "Protection Mechanism Failure",
        "url": "https://cwe.mitre.org/data/definitions/693.html",
        "owasp": "A05:2021"
    },
    "server_info_disclosure": {
        "cwe_id": "CWE-200",
        "name": "Server Information Disclosure",
        "description": "Exposure of Sensitive Information to an Unauthorized Actor",
        "url": "https://cwe.mitre.org/data/definitions/200.html",
        "owasp": "A05:2021"
    },
    "directory_listing": {
        "cwe_id": "CWE-548",
        "name": "Directory Listing",
        "description": "Exposure of Information Through Directory Listing",
        "url": "https://cwe.mitre.org/data/definitions/548.html",
        "owasp": "A05:2021"
    },
    
    # Authentication Issues
    "weak_password": {
        "cwe_id": "CWE-521",
        "name": "Weak Password Requirements",
        "description": "Weak Password Requirements",
        "url": "https://cwe.mitre.org/data/definitions/521.html",
        "owasp": "A07:2021"
    },
    "default_credentials": {
        "cwe_id": "CWE-798",
        "name": "Default Credentials",
        "description": "Use of Hard-coded Credentials",
        "url": "https://cwe.mitre.org/data/definitions/798.html",
        "owasp": "A07:2021"
    },
    "session_fixation": {
        "cwe_id": "CWE-384",
        "name": "Session Fixation",
        "description": "Session Fixation",
        "url": "https://cwe.mitre.org/data/definitions/384.html",
        "owasp": "A07:2021"
    },
    "insecure_cookie": {
        "cwe_id": "CWE-614",
        "name": "Insecure Cookie",
        "description": "Sensitive Cookie in HTTPS Session Without 'Secure' Attribute",
        "url": "https://cwe.mitre.org/data/definitions/614.html",
        "owasp": "A07:2021"
    },
    "jwt_vulnerability": {
        "cwe_id": "CWE-347",
        "name": "JWT Verification Failure",
        "description": "Improper Verification of Cryptographic Signature",
        "url": "https://cwe.mitre.org/data/definitions/347.html",
        "owasp": "A07:2021"
    },
    
    # SSRF
    "ssrf": {
        "cwe_id": "CWE-918",
        "name": "Server-Side Request Forgery (SSRF)",
        "description": "Server-Side Request Forgery",
        "url": "https://cwe.mitre.org/data/definitions/918.html",
        "owasp": "A10:2021"
    },
    
    # Other
    "csrf": {
        "cwe_id": "CWE-352",
        "name": "Cross-Site Request Forgery (CSRF)",
        "description": "Cross-Site Request Forgery",
        "url": "https://cwe.mitre.org/data/definitions/352.html",
        "owasp": "A01:2021"
    },
    "open_redirect": {
        "cwe_id": "CWE-601",
        "name": "Open Redirect",
        "description": "URL Redirection to Untrusted Site",
        "url": "https://cwe.mitre.org/data/definitions/601.html",
        "owasp": "A01:2021"
    },
    "clickjacking": {
        "cwe_id": "CWE-1021",
        "name": "Clickjacking",
        "description": "Improper Restriction of Rendered UI Layers or Frames",
        "url": "https://cwe.mitre.org/data/definitions/1021.html",
        "owasp": "A05:2021"
    },
    "outdated_component": {
        "cwe_id": "CWE-1104",
        "name": "Vulnerable Component",
        "description": "Use of Unmaintained Third Party Components",
        "url": "https://cwe.mitre.org/data/definitions/1104.html",
        "owasp": "A06:2021"
    },
    "insecure_deserialization": {
        "cwe_id": "CWE-502",
        "name": "Insecure Deserialization",
        "description": "Deserialization of Untrusted Data",
        "url": "https://cwe.mitre.org/data/definitions/502.html",
        "owasp": "A08:2021"
    },
    "file_upload": {
        "cwe_id": "CWE-434",
        "name": "Unrestricted File Upload",
        "description": "Unrestricted Upload of File with Dangerous Type",
        "url": "https://cwe.mitre.org/data/definitions/434.html",
        "owasp": "A04:2021"
    },
}


def get_cwe_info(vulnerability_type: str) -> dict:
    """Get CWE information for a vulnerability type"""
    return CWE_DATABASE.get(vulnerability_type, {
        "cwe_id": "CWE-Unknown",
        "name": vulnerability_type,
        "description": "Unknown vulnerability type",
        "url": "https://cwe.mitre.org/",
        "owasp": "Unknown"
    })
