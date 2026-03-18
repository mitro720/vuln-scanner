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
        """Emit new finding with enriched metadata (CVSS, CWE)"""
        try:
            from core.vulnerability import Vulnerability
            # Enrich the finding using the Vulnerability model
            v = Vulnerability.from_finding(finding)
            finding = v.to_dict()
        except Exception as e:
            # Fallback to original finding if enrichment fails
            pass
            
        self.findings.append(finding)
        print(f"FINDING:{json.dumps(finding)}", flush=True)
        
    def emit_error(self, error: str):
        """Emit error"""
        data = {
            "error": error,
            "timestamp": datetime.utcnow().isoformat()
        }
        print(f"ERROR:{json.dumps(data)}", flush=True)

    def emit_crawler_graph(self, graph_data: Dict[str, Any]):
        """Emit crawler graph data for the backend to persist"""
        print(f"CRAWLER_GRAPH:{json.dumps(graph_data)}", flush=True)
        
    def run(self, selected_phase: str = "all"):
        """Main scan execution with modular phase support"""
        try:
            self.emit_progress("initialization", 0, f"Starting {selected_phase} scan...")
            
            # Map of phases to methods
            phases = {
                "recon": self.run_recon,
                "discovery": self.run_discovery,
                "visual_survey": self.run_visual_survey,
                "network": self.run_network,
                "owasp": self.run_owasp,
                "cve": self.run_cve,
            }

            if selected_phase == "all":
                # Full sequential scan
                self.run_recon()
                self.run_discovery()
                self.run_visual_survey()
                self.run_network()
                self.run_owasp()
                self.run_cve()
            elif selected_phase in phases:
                # Run specific phase (handling dependencies if needed)
                # For now, we allow running phases independently as requested
                phases[selected_phase]()
            else:
                raise ValueError(f"Invalid scan phase: {selected_phase}")

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

    def run_recon(self):
        """Phase 1: Reconnaissance (Tech, WAF, Subdomains)"""
        self.emit_progress("reconnaissance", 5, "[Recon] Starting passive reconnaissance...")

        # 1a. Technology Fingerprinting
        self.emit_progress("reconnaissance", 6, "[Tech Fingerprint] Sending HTTP probe...")
        try:
            from recon.tech_detect import TechDetector
            tech = TechDetector(self.target_url)
            tech_results = tech.detect()
            self.metadata['technologies'] = tech_results
            detected = tech_results.get('technologies', [])
            server = tech_results.get('server', 'Unknown')
            self.emit_progress("reconnaissance", 8, f"[Tech Fingerprint] Detected: {', '.join(detected)} | Server: {server}")
        except Exception as e:
            self.emit_error(f"Tech detection failed: {str(e)}")

        # 1b. Subdomain Enumeration
        if self.config.get("subdomain", True):
            self.emit_progress("reconnaissance", 10, "[Subdomain Enum] Starting enumeration...")
            try:
                from recon.subdomain_scanner import SubdomainScanner
                scanner = SubdomainScanner(self.target_url)
                
                def handle_discovered(sub):
                    self.emit_progress("reconnaissance", 11, f"[Subdomain Enum] Discovered target: {sub}")
                
                def handle_live(url):
                    self.emit_progress("reconnaissance", 13, f"[Subdomain Enum] Live server found: {url}")
                    self.emit_finding({
                        "name": f"Live Subdomain Discovered",
                        "severity": "info",
                        "owasp_category": "Recon",
                        "url": url,
                        "description": "Discovered an active, live sub-domain responding to HTTP/HTTPS requests.",
                        "evidence": {"method": "DNS Resolution + HTTP/S Probing"},
                        "confidence": 100,
                        "poc": ""
                    })

                scanner.run(
                    on_discovered=handle_discovered,
                    on_live=handle_live
                )

                # Proceed to test for Subdomain Takeovers on the enumerated list
                self.emit_progress("reconnaissance", 14, "[Subdomain Takeover] Testing for dangling CNAMEs...")
                try:
                    from recon.subdomain_takeover import SubdomainTakeoverModule
                    takeover_scanner = SubdomainTakeoverModule(self.target_url)
                    takeover_findings = takeover_scanner.scan(scanner.live)
                    for find in takeover_findings:
                        self.emit_finding(find)
                except Exception as ex:
                    self.emit_error(f"Takeover detection failed: {str(ex)}")

                self.metadata.update({
                    'total_subdomains': len(scanner.discovered),
                    'live_servers': len(scanner.live)
                })
                total = len(scanner.discovered)
                live = len(scanner.live)
                self.emit_progress("reconnaissance", 15, f"[Subdomain Enum] Found {total} subdomains — {live} live")
            except Exception as e:
                self.emit_error(f"Subdomain enumeration failed: {str(e)}")

        # 1c. WAF Detection
        if self.config.get("waf", True):
            self.emit_progress("reconnaissance", 16, "[WAF Detect] Checking for signatures...")
            try:
                from recon.waf_detect import WAFDetector
                waf_detector = WAFDetector(self.target_url)
                waf_results = waf_detector.detect()
                self.metadata['waf'] = waf_results
                if waf_results.get('waf_detected'):
                    wafs = ', '.join(waf_results.get('wafs', []))
                    self.emit_progress("reconnaissance", 22, f"[WAF Detect] WAF identified: {wafs}")
                else:
                    self.emit_progress("reconnaissance", 22, "[WAF Detect] No WAF detected")
            except Exception as e:
                self.emit_error(f"WAF detection failed: {str(e)}")

        # 1d. Sensitive File Discovery
        if self.config.get("sensitive_files", True):
            self.emit_progress("reconnaissance", 23, "[Sensitive Files] Probing common configuration files...")
            try:
                from recon.sensitive_files import SensitiveFileScanner
                # Rate limited to 5 requests per second
                sf_scanner = SensitiveFileScanner(self.target_url, max_requests_per_second=5)
                sf_findings = sf_scanner.scan()
                for finding in sf_findings:
                    self.emit_finding(finding)
                self.emit_progress("reconnaissance", 24, f"[Sensitive Files] Probed files. Found {len(sf_findings)} exposures.")
            except Exception as e:
                self.emit_error(f"Sensitive file scanning failed: {str(e)}")

        # 1e. CMS Fingerprinting
        if self.config.get("cms_fingerprint", True):
            self.emit_progress("reconnaissance", 25, "[CMS] Fingerprinting content management systems...")
            try:
                from recon.cms_fingerprint import CMSFingerprinter
                cms_fingerprinter = CMSFingerprinter(self.target_url)
                cms_findings = cms_fingerprinter.scan()
                for finding in cms_findings:
                    self.emit_finding(finding)
                self.emit_progress("reconnaissance", 26, f"[CMS] Fingerprinting complete. Found {len(cms_findings)} CMS items.")
            except Exception as e:
                self.emit_error(f"CMS Fingerprinting failed: {str(e)}")

    def run_discovery(self):
        """Phase 2: Discovery (Web Crawling & API Detection)"""
        # 2a. Web Crawling
        if self.config.get("crawl", True):
            self.emit_progress("web_crawling", 35, "Crawling web application...")
            try:
                from recon.crawler import WebCrawler
                crawler = WebCrawler(self.target_url, max_depth=2)
                crawl_results = crawler.crawl()
                self.metadata['crawl'] = crawl_results
                # Emit graph data so the backend can save it for the "Attack Surface" view
                self.emit_crawler_graph(crawl_results)
                discovered_urls = crawl_results.get('urls', [])
                self.metadata['discovered_urls'] = discovered_urls
                self.emit_progress("web_crawling", 40, f"Discovered {len(discovered_urls)} URLs, {len(crawl_results.get('forms', []))} forms")
            except Exception as e:
                self.emit_error(f"Crawling failed: {str(e)}")

        # 2b. API Discovery
        if self.config.get("api_discovery", True):
            self.emit_progress("web_crawling", 42, "Discovering API endpoints...")
            try:
                from recon.api_discovery import APIDiscovery
                api_discoverer = APIDiscovery(self.target_url)
                api_results = api_discoverer.discover()
                self.metadata['api'] = api_results
                
                # Emit finding for documentation
                if api_results.get('documentation'):
                    for doc_url, details in api_results['documentation'].items():
                        self.emit_finding({
                            "name": f"Exposed API Documentation: {details.get('type')}",
                            "severity": "info",
                            "owasp_category": "Recon",
                            "url": doc_url,
                            "description": f"Found potentially exposed API documentation at {doc_url}.",
                            "confidence": 100,
                            "technique": "Active Probing",
                            "evidence": f"Server responded with {details.get('status')} at documentation endpoint."
                        })
                        
                self.emit_progress("web_crawling", 46, f"Discovered {api_results.get('count', 0)} API endpoints")
            except Exception as e:
                self.emit_error(f"API discovery failed: {str(e)}")

    def run_visual_survey(self):
        """Phase 2.5: Visual Survey (Screenshots)"""
        if self.config.get("visual_survey", True):
            self.emit_progress("visual_survey", 47, "Capturing visual surface (screenshots)...")
            try:
                from recon.visual_survey import VisualSurveyor
                # Determine backend public path - typically peer to scanner-core
                backend_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'backend')
                screenshot_dir = os.path.join(backend_dir, 'public', 'screenshots')
                
                surveyor = VisualSurveyor(output_dir=screenshot_dir)
                
                # We screenshot discovered URLs
                urls = list(set([self.target_url] + self.metadata.get('discovered_urls', [])[:10])) # Limit to 10 for performance
                
                results = surveyor.capture_batch(urls)
                self.metadata['screenshots'] = results
                self.emit_progress("visual_survey", 49, f"Captured {len(results)} screenshots")
            except Exception as e:
                self.emit_error(f"Visual survey failed: {str(e)}")

    def run_network(self):
        """Phase 3: Network Scanning"""
        if self.config.get("port_scan", True):
            port_list = "21,22,23,25,53,80,110,143,443,445,3306,3389,5432,5900,8000,8080,8443,27017"
            self.emit_progress("network_scanning", 25, f"[Port Scan] Probing common ports...")
            try:
                from recon.port_scanner import PortScanner
                port_scanner = PortScanner(self.target_url)
                port_results = port_scanner.scan(detect_version=self.config.get("cve_detection", True))
                self.metadata['ports'] = port_results
                open_ports = port_results.get('open_ports', [])
                if open_ports:
                    self.emit_progress("network_scanning", 30, f"[Port Scan] {len(open_ports)} open port(s) discovered")
                else:
                    self.emit_progress("network_scanning", 30, "[Port Scan] No open ports found")
            except Exception as e:
                self.emit_error(f"Port scan failed: {str(e)}")
    def run_owasp(self):
        """Phase 4: OWASP Vulnerability Testing"""
        if self.config.get("owasp", True):
            self.emit_progress("vulnerability_detection", 50, "Running OWASP checks...")
            urls_to_test = list(set([self.target_url] + self.metadata.get('discovered_urls', [])))
            
            scanners = [
                ("SQL Injection", "owasp.sql_injection_intensive", "IntensiveSQLiScanner"),
                ("XSS", "owasp.a03_xss", "XSSModule"),
                ("Command Injection", "owasp.command_injection_intensive", "IntensiveCommandInjectionScanner"),
                ("NoSQL Injection", "owasp.nosql_injection", "NoSQLInjectionModule"),
                ("Server-Side Template Injection", "owasp.ssti", "SSTIModule"),
                ("Host Header Injection", "owasp.host_header", "HostHeaderInjectionModule"),
                ("HTTP Request Smuggling", "owasp.request_smuggling", "RequestSmugglingModule"),
                ("SSRF", "owasp.a10_ssrf", "SSRFModule"),
                ("XXE", "owasp.xxe", "XXEModule"),
                ("CORS", "owasp.cors", "CORSModule"),
                ("JWT", "owasp.jwt_vulnerabilities", "JWTModule"),
                ("IDOR", "owasp.idor", "IDORModule"),
                ("Open Redirect", "owasp.open_redirect", "OpenRedirectModule"),
                ("CRLF Injection", "owasp.crlf", "CRLFModule"),
                ("LDAP Injection", "owasp.ldap_injection", "LDAPInjectionModule"),
                ("Mass Assignment", "owasp.mass_assignment", "MassAssignmentModule"),
                ("GraphQL Abuse", "owasp.graphql_abuse", "GraphQLAbuseModule"),
                ("Rate Limit Bypass", "owasp.rate_limit_bypass", "RateLimitBypassModule"),
            ]
            
            target_modules = self.config.get("target_modules", [])
            # Per-module timeout in seconds — prevents any single scanner from hanging the entire scan
            MODULE_TIMEOUT = 90
            total = len(scanners)

            import importlib
            import concurrent.futures

            for idx, (name, module_path, class_name) in enumerate(scanners):
                if target_modules and name not in target_modules and class_name not in target_modules:
                    continue

                pct = 50 + int((idx / total) * 33)  # spread progress 50% → 83%
                self.emit_progress("vulnerability_detection", pct, f"[{name}] Scanning...")

                def run_scanner(mp=module_path, cn=class_name):
                    mod = importlib.import_module(mp)
                    scanner_class = getattr(mod, cn)
                    scanner_inst = scanner_class(self.target_url)
                    # Pass discovered forms so the scanner can also fuzz POST parameters
                    forms = self.metadata.get('crawl', {}).get('forms', [])
                    if hasattr(scanner_inst, 'scan_with_forms'):
                        return scanner_inst.scan_with_forms(urls_to_test, forms)
                    return scanner_inst.scan(urls_to_test)

                try:
                    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                        future = executor.submit(run_scanner)
                        try:
                            findings = future.result(timeout=MODULE_TIMEOUT)
                        except concurrent.futures.TimeoutError:
                            self.emit_error(f"{name} scan timed out after {MODULE_TIMEOUT}s — skipping")
                            continue

                    # Enrich with Payload Lab PoCs
                    try:
                        from vulnerability.payload_lab import PayloadLab
                        lab = PayloadLab()
                        for finding in findings:
                            if not finding.get('pocs'):
                                f_url = finding.get('url', self.target_url)
                                param = None
                                if '?' in f_url:
                                    import urllib.parse
                                    query = urllib.parse.urlparse(f_url).query
                                    params = urllib.parse.parse_qs(query)
                                    if params: param = list(params.keys())[0]
                                finding['pocs'] = lab.generate_poc(finding['name'], f_url, param)
                    except Exception as lab_err:
                        self.emit_error(f"Payload Lab enrichment failed: {str(lab_err)}")

                    for finding in findings:
                        self.emit_finding(finding)
                except Exception as e:
                    self.emit_error(f"{name} Scan failed: {str(e)}")
            
            self.emit_progress("vulnerability_detection", 85, "OWASP checks completed")

    def run_cve(self):
        """Phase 5: CVE Matching"""
        if self.config.get("cve_detection", True) and 'ports' in self.metadata:
            open_ports = self.metadata['ports'].get('open_ports', [])
            if open_ports:
                self.emit_progress("cve_detection", 32, "[CVE Lookup] Matching services...")
                try:
                    from cve.cve_matcher import CVEMatcher
                    matcher = CVEMatcher()
                    cve_findings = []
                    for port_info in open_ports:
                        if port_info.get('version') or port_info.get('product'):
                            findings = matcher.match_service(port_info)
                            cve_findings.extend(findings)
                    for finding in cve_findings:
                        self.emit_finding(finding)
                    self.emit_progress("cve_detection", 34, f"[CVE Lookup] Found {len(cve_findings)} CVE(s)")
                except Exception as e:
                    self.emit_error(f"CVE detection failed: {str(e)}")


def main():
    """Entry point for scanner"""
    if len(sys.argv) < 3:
        print("Usage: python engine.py <target_url> <config_json> [phase]")
        sys.exit(1)
        
    target_url = sys.argv[1]
    config = json.loads(sys.argv[2])
    phase = sys.argv[3] if len(sys.argv) > 3 else "all"
    
    engine = ScanEngine(target_url, config)
    result = engine.run(selected_phase=phase)
    
    print(f"RESULT:{json.dumps(result)}", flush=True)


if __name__ == "__main__":
    main()
