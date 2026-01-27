"""
Form Fuzzer Module
Tests HTML forms for injection vulnerabilities
"""

import requests
from typing import List, Dict, Any
from urllib.parse import urljoin
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.payload_loader import payload_loader


class FormFuzzer:
    def __init__(self):
        # Load payloads
        self.sqli_payloads = payload_loader.load_payloads('sqli.txt')
        self.xss_payloads = payload_loader.load_payloads('xss.txt')
        
        # SQL error patterns
        self.sql_errors = [
            "SQL syntax",
            "mysql_fetch",
            "ORA-",
            "PostgreSQL",
            "SQLite",
            "Microsoft SQL Server",
            "Unclosed quotation",
            "ODBC",
        ]
        
        # XSS indicators
        self.xss_indicators = [
            "<script>",
            "alert(",
            "onerror=",
            "onload=",
        ]
    
    def test_form_sqli(self, form: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test form for SQL injection"""
        findings = []
        
        try:
            for payload in self.sqli_payloads[:10]:  # Limit to first 10 for speed
                # Build form data with payload in each field
                for input_field in form['inputs']:
                    if not input_field.get('name'):
                        continue
                        
                    form_data = {}
                    for field in form['inputs']:
                        if field.get('name'):
                            # Use payload for current field, default for others
                            if field['name'] == input_field['name']:
                                form_data[field['name']] = payload
                            else:
                                form_data[field['name']] = field.get('value', 'test')
                    
                    # Submit form
                    try:
                        if form['method'] == 'POST':
                            response = requests.post(form['action'], data=form_data, timeout=10)
                        else:
                            response = requests.get(form['action'], params=form_data, timeout=10)
                        
                        # Check for SQL errors
                        for error_pattern in self.sql_errors:
                            if error_pattern.lower() in response.text.lower():
                                findings.append({
                                    "name": "SQL Injection in Form",
                                    "severity": "critical",
                                    "owasp_category": "A03:2021",
                                    "url": form['url'],
                                    "parameter": input_field['name'],
                                    "confidence": 95,
                                    "technique": "Error-based (Form)",
                                    "evidence": {
                                        "payload": payload,
                                        "error_pattern": error_pattern,
                                        "method": form['method'],
                                        "action": form['action']
                                    },
                                    "poc": f"Submit form at {form['url']} with {input_field['name']}={payload}",
                                    "remediation": "Use parameterized queries for all database operations"
                                })
                                break
                    except requests.exceptions.RequestException:
                        continue
                        
        except Exception as e:
            print(f"Error testing form for SQLi: {str(e)}")
            
        return findings
    
    def test_form_xss(self, form: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test form for XSS"""
        findings = []
        
        try:
            for payload in self.xss_payloads[:10]:  # Limit to first 10
                for input_field in form['inputs']:
                    if not input_field.get('name'):
                        continue
                    
                    form_data = {}
                    for field in form['inputs']:
                        if field.get('name'):
                            if field['name'] == input_field['name']:
                                form_data[field['name']] = payload
                            else:
                                form_data[field['name']] = field.get('value', 'test')
                    
                    try:
                        if form['method'] == 'POST':
                            response = requests.post(form['action'], data=form_data, timeout=10)
                        else:
                            response = requests.get(form['action'], params=form_data, timeout=10)
                        
                        # Check if payload is reflected
                        if payload in response.text:
                            findings.append({
                                "name": "Cross-Site Scripting (XSS) in Form",
                                "severity": "high",
                                "owasp_category": "A03:2021",
                                "url": form['url'],
                                "parameter": input_field['name'],
                                "confidence": 90,
                                "technique": "Reflected XSS (Form)",
                                "evidence": {
                                    "payload": payload,
                                    "method": form['method'],
                                    "action": form['action']
                                },
                                "poc": f"Submit form at {form['url']} with {input_field['name']}={payload}",
                                "remediation": "Sanitize and encode all user input before reflecting it"
                            })
                            break
                    except requests.exceptions.RequestException:
                        continue
                        
        except Exception as e:
            print(f"Error testing form for XSS: {str(e)}")
            
        return findings
    
    def test_forms(self, forms: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Test all forms for vulnerabilities"""
        all_findings = []
        
        for form in forms:
            # Test SQLi
            sqli_findings = self.test_form_sqli(form)
            all_findings.extend(sqli_findings)
            
            # Test XSS
            xss_findings = self.test_form_xss(form)
            all_findings.extend(xss_findings)
            
        return all_findings
