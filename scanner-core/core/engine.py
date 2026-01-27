"""
SecureScan - Core Engine
Main scanning orchestrator
"""

import sys
import os

# CRITICAL: Add scanner-core directory to Python path so modules can be imported
# This ensures imports work regardless of where/how the script is executed
script_dir = os.path.dirname(os.path.abspath(__file__))  # core/
scanner_core_dir = os.path.dirname(script_dir)  # scanner-core/
if scanner_core_dir not in sys.path:
    sys.path.insert(0, scanner_core_dir)

import json
from datetime import datetime
from typing import Dict, List, Any


class ScanEngine:
    def __init__(self, target_url: str, config: Dict[str, Any]):
        self.target_url = target_url
        self.config = config
        self.findings = []
        self.metadata = {}
        self.progress = 0
        
    def emit_progress(self, phase: str, progress: int, message: str = ""):
        """Emit progress update"""
        data = {
            "phase": phase,
            "progress": progress,
            "message": message,
            "timestamp": datetime.utcnow().isoformat()
        }
        print(f"PROGRESS:{json.dumps(data)}", flush=True)
        self.progress = progress
        
    def emit_finding(self, finding: Dict[str, Any]):
        """Emit new finding"""
        self.findings.append(finding)
        print(f"FINDING:{json.dumps(finding)}", flush=True)
        
    def emit_error(self, error: str):
        """Emit error"""
        data = {
            "error": error,
            "timestamp": datetime.utcnow().isoformat()
        }
        print(f"ERROR:{json.dumps(data)}", flush=True)
        
    def run(self):
        """Main scan execution"""
        try:
            self.emit_progress("initialization", 0, "Starting scan...")
            
            # Phase 1: Reconnaissance
            if self.config.get("subdomain", True):
                self.emit_progress("reconnaissance", 10, "Discovering subdomains...")
                try:
                    from recon.subdomain_scanner import SubdomainScanner
                    scanner = SubdomainScanner(self.target_url)
                    recon_results = scanner.run()
                    self.metadata.update(recon_results)
                    self.emit_progress("reconnaissance", 15, f"Found {recon_results['total_subdomains']} subdomains")
                except Exception as e:
                    self.emit_error(f"Recon failed: {str(e)}")
                
            if self.config.get("waf", True):
                self.emit_progress("reconnaissance", 20, "Detecting WAF...")
                try:
                    from recon.waf_detect import WAFDetector
                    waf_detector = WAFDetector(self.target_url)
                    waf_results = waf_detector.detect()
                    self.metadata['waf'] = waf_results
                    if waf_results.get('waf_detected'):
                        wafs = ', '.join(waf_results.get('wafs', []))
                        self.emit_progress("reconnaissance", 22, f"WAF detected: {wafs}")
                except Exception as e:
                    self.emit_error(f"WAF detection failed: {str(e)}")
                    
            # Phase 2: Network Scanning
            if self.config.get("port_scan", True):
                self.emit_progress("network_scanning", 25, "Scanning ports...")
                try:
                    from recon.port_scanner import PortScanner
                    port_scanner = PortScanner(self.target_url)
                    port_results = port_scanner.scan()
                    self.metadata['ports'] = port_results
                    self.emit_progress("network_scanning", 30, f"Found {port_results['total_open']} open ports")
                except Exception as e:
                    self.emit_error(f"Port scan failed: {str(e)}")
                    
            # Phase 3: Web Crawling
            if self.config.get("crawl", True):
                self.emit_progress("web_crawling", 35, "Crawling web application...")
                try:
                    from recon.crawler import WebCrawler
                    crawler = WebCrawler(self.target_url, max_depth=2)
                    crawl_results = crawler.crawl()
                    self.metadata['crawl'] = crawl_results
                    
                    # IMPORTANT: Store discovered URLs for vulnerability testing
                    discovered_urls = crawl_results.get('urls', [])
                    self.metadata['discovered_urls'] = discovered_urls
                    
                    self.emit_progress("web_crawling", 40, f"Discovered {len(discovered_urls)} URLs, {len(crawl_results['forms'])} forms")
                    
                    # Test forms for vulnerabilities
                    if crawl_results.get('forms'):
                        self.emit_progress("form_testing", 42, f"Testing {len(crawl_results['forms'])} forms...")
                        try:
                            from recon.form_fuzzer import FormFuzzer
                            fuzzer = FormFuzzer()
                            form_findings = fuzzer.test_forms(crawl_results['forms'])
                            for finding in form_findings:
                                self.emit_finding(finding)
                            self.emit_progress("form_testing", 45, f"Found {len(form_findings)} vulnerabilities in forms")
                        except Exception as e:
                            self.emit_error(f"Form fuzzing failed: {str(e)}")
                except Exception as e:
                    self.emit_error(f"Crawling failed: {str(e)}")
                
            # Phase 4: Vulnerability Detection
            if self.config.get("owasp", True):
                self.emit_progress("vulnerability_detection", 50, "Running OWASP checks...")
                
                # Build list of URLs to test: target + discovered URLs
                urls_to_test = [self.target_url]
                if 'discovered_urls' in self.metadata and self.metadata['discovered_urls']:
                    urls_to_test.extend(self.metadata['discovered_urls'])
                    # Remove duplicates
                    urls_to_test = list(set(urls_to_test))
                
                self.emit_progress("vulnerability_detection", 52, f"Testing {len(urls_to_test)} URLs for vulnerabilities...")
                
                # Run Intensive SQL Injection Scan
                try:
                    from owasp.sql_injection_intensive import IntensiveSQLiScanner
                    sqli = IntensiveSQLiScanner(self.target_url)
                    findings = sqli.scan(urls_to_test)  # Test all discovered URLs
                    for finding in findings:
                        self.emit_finding(finding)
                    self.emit_progress("vulnerability_detection", 55, f"SQLi scan: {len(findings)} findings")
                except Exception as e:
                    self.emit_error(f"SQLi Scan failed: {str(e)}")

                # Run XSS Scan
                try:
                    from owasp.a03_xss import XSSModule
                    xss = XSSModule(self.target_url)
                    findings = xss.scan(urls_to_test)  # Test all discovered URLs
                    for finding in findings:
                        self.emit_finding(finding)
                except Exception as e:
                    self.emit_error(f"XSS Scan failed: {str(e)}")
                    
                # Run Intensive Command Injection Scan
                try:
                    from owasp.command_injection_intensive import IntensiveCommandInjectionScanner
                    cmd_inj = IntensiveCommandInjectionScanner(self.target_url)
                    findings = cmd_inj.scan(urls_to_test)  # Test all discovered URLs
                    for finding in findings:
                        self.emit_finding(finding)
                    self.emit_progress("vulnerability_detection", 60, f"Command Injection: {len(findings)} findings")
                except Exception as e:
                    self.emit_error(f"Command Injection Scan failed: {str(e)}")
                    
                # Run NoSQL Injection Scan
                try:
                    from owasp.nosql_injection import NoSQLInjectionModule
                    nosql = NoSQLInjectionModule(self.target_url)
                    findings = nosql.scan(urls_to_test)  # Test all discovered URLs
                    for finding in findings:
                        self.emit_finding(finding)
                except Exception as e:
                    self.emit_error(f"NoSQL Injection Scan failed: {str(e)}")
                    
                # Run SSRF Scan
                try:
                    from owasp.a10_ssrf import SSRFModule
                    ssrf = SSRFModule(self.target_url)
                    findings = ssrf.scan(urls_to_test)  # Test all discovered URLs
                    for finding in findings:
                        self.emit_finding(finding)
                except Exception as e:
                    self.emit_error(f"SSRF Scan failed: {str(e)}")
                    
                # Run XXE Scan
                try:
                    from owasp.xxe import XXEModule
                    xxe = XXEModule(self.target_url)
                    findings = xxe.scan(urls_to_test)  # Test all discovered URLs
                    for finding in findings:
                        self.emit_finding(finding)
                except Exception as e:
                    self.emit_error(f"XXE Scan failed: {str(e)}")
                    
                # Run CORS Scan
                try:
                    from owasp.cors import CORSModule
                    cors = CORSModule(self.target_url)
                    findings = cors.scan(urls_to_test)  # Test all discovered URLs
                    for finding in findings:
                        self.emit_finding(finding)
                except Exception as e:
                    self.emit_error(f"CORS Scan failed: {str(e)}")
                    
                # Run JWT Vulnerabilities Scan
                try:
                    from owasp.jwt_vulnerabilities import JWTModule
                    jwt = JWTModule(self.target_url)
                    findings = jwt.scan(urls_to_test)  # Test all discovered URLs
                    for finding in findings:
                        self.emit_finding(finding)
                except Exception as e:
                    self.emit_error(f"JWT Scan failed: {str(e)}")


                self.emit_progress("vulnerability_detection", 85, "OWASP checks completed")

            self.emit_progress("completed", 90, "Generating reports...")
            
            # Generate Report
            try:
                from reporting.report_generator import ReportGenerator
                generator = ReportGenerator()
                report_path = generator.generate_pdf({
                    "target_url": self.target_url,
                    "findings": self.findings,
                    "findings_count": len(self.findings)
                })
                self.metadata['report_path'] = report_path
                self.emit_progress("completed", 100, f"Report generated: {report_path}")
            except Exception as e:
                self.emit_error(f"Reporting failed: {str(e)}")
            
            # Return summary
            return {
                "status": "completed",
                "findings_count": len(self.findings),
                "metadata": self.metadata
            }
            
        except Exception as e:
            self.emit_error(str(e))
            return {
                "status": "failed",
                "error": str(e)
            }


def main():
    """Entry point for scanner"""
    if len(sys.argv) < 3:
        print("Usage: python engine.py <target_url> <config_json>")
        sys.exit(1)
        
    target_url = sys.argv[1]
    config = json.loads(sys.argv[2])
    
    engine = ScanEngine(target_url, config)
    result = engine.run()
    
    print(f"RESULT:{json.dumps(result)}", flush=True)


if __name__ == "__main__":
    main()
