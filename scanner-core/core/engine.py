"""
SecureScan - Core Engine
Main scanning orchestrator
"""

import sys
import os

# Robust root detection
def get_scanner_root():
    """Detect the root 'scanner-core' directory reliably"""
    current = os.path.abspath(__file__)
    # Search up to 5 levels for the root marker
    for _ in range(5):
        parent = os.path.dirname(current)
        basename = os.path.basename(parent)
        
        # If we are inside 'core', the scanner root is the parent of 'core'
        if basename == "core":
            return os.path.dirname(parent)
            
        # If we are in 'scanner-core', this is the root
        if basename == "scanner-core":
            return parent
            
        # Fallback for backend presence
        if os.path.exists(os.path.join(parent, "backend")):
            return parent
            
        current = parent
    return os.path.dirname(os.path.abspath(__file__))

scanner_core_dir = get_scanner_root()
if scanner_core_dir not in sys.path:
    sys.path.insert(0, scanner_core_dir)

import json
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    from dotenv import load_dotenv
    # Dynamically find backend/.env relative to scanner-core
    env_path = os.path.join(os.path.dirname(scanner_core_dir), "backend", ".env")
    if os.path.exists(env_path):
        load_dotenv(env_path)
    else:
        load_dotenv() # Fallback to cwd
except ImportError:
    pass
from datetime import datetime, timezone
from typing import Dict, List, Any
from urllib.parse import urlparse, urljoin


DEFAULT_CONFIG = {
    # Scanning Limits
    "max_crawl_depth": 3,
    "max_pages": 150,
    "screenshot_limit": 20,
    "module_timeout": 180,
    
    # Discovery/Logic
    "crawl": True,
    "subdomain": True,
    "waf": True,
    "sensitive_files": True,
    "cms_fingerprint": True,
    "visual_survey": True,
    "port_scan": True,
    "owasp": True,
    "cve_detection": True,
    "api_discovery": True,
    
    # HTTP/Stealth
    "request_delay": 0.3,
    "random_jitter": True,
    
    # Nuclei Fallback
    "nuclei_fallback": True,
    "nuclei_severity": ["critical", "high", "medium"],
    "nuclei_tags": ["generic", "cve", "misconfig", "exposure", "owasp"],
    
    "modules": [], # Specific modules to run
    "custom_payloads": [],
    
    # AI Assistant
    "ai_enabled": False,
    "ai_provider": "openai",
    "ai_api_key": "",
    "ai_base_url": "",
}

class ScanEngine:
    def __init__(self, target_url: str, config: Dict[str, Any] = None, scan_id: str = None):
        # Merge configuration with defaults
        self.config = {**DEFAULT_CONFIG, **(config or {})}
        
        # Ensure log directory exists
        # Ensure log directory exists relative to scanner core
        log_dir = os.path.join(get_scanner_root(), 'logs')
        os.makedirs(log_dir, exist_ok=True)
        self.log_path = os.path.join(log_dir, 'scanner-core.log')

        # Sanitize URL
        self.target_url = target_url.split('#')[0].rstrip('/')
        self.scan_id = scan_id

        # Support for multi-target scanning
        raw_targets = self.config.get('targets', [self.target_url])
        if not isinstance(raw_targets, list):
            raw_targets = [raw_targets]
            
        self.target_urls = list(set([t.split('#')[0].rstrip('/') for t in raw_targets if t]))
        
        self.findings = []
        self.metadata = {}
        self.progress = 0
        
        # --- Initialize Core Components ---
        from core.http_client import HttpClient
        self.http = HttpClient(self.config)
        
        # Initialize Auth Handler
        from core.auth_handler import AuthHandler
        self.auth = AuthHandler()
        
        # Initialize AI Assistant
        self.ai_assistant = None
        if self.config.get("ai_enabled"):
            try:
                from ai.assistant import AIAssistant
                self.ai_assistant = AIAssistant(
                    provider=self.config.get("ai_provider", "openai"),
                    api_key=self.config.get("ai_api_key"),
                    base_url=self.config.get("ai_base_url")
                )
            except Exception as e:
                import traceback
                traceback.print_exc()
        
        # Handle Pre-scan Authentication
        login_cfg = self.config.get("login_config")
        if login_cfg:
            self._authenticate(login_cfg)

    def scanner_log(self, message: str, level: str = "INFO"):
        """Log direct to scanner-core.log with severity level"""
        try:
            with open(self.log_path, 'a', encoding='utf-8') as f:
                timestamp = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
                f.write(f"{level}: [{timestamp}] {message}\n")
                f.flush()
        except: pass

    def _authenticate(self, cfg: Dict[str, Any]):
        """Attempt to login before starting scan"""
        login_url = cfg.get("login_url")
        username = cfg.get("username")
        password = cfg.get("password")
        
        if login_url and username and password:
            self.emit_progress("initialization", 2, f"Authenticating at {login_url}...")
            # Unpack field names if provided, else use defaults
            success = self.auth.login(
                login_url,
                username,
                password,
                user_field=cfg.get("username_field", "username"),
                pass_field=cfg.get("password_field", "password"),
                token_key=cfg.get("token_key")
            )
            
            if success:
                self.emit_progress("initialization", 3, "Authentication successful! Session captured.")
                # Sync cookies/headers to HttpClient
                self.http.set_cookies(self.auth.cookies)
                # If a token was captured (Bearer), set it
                for h, v in self.auth.headers.items():
                    if h.lower() == "authorization":
                        self.http.session.headers["Authorization"] = v
            else:
                self.emit_warning(f"Authentication failed at {login_url}. Proceeding as unauthenticated user.")

    def emit_progress(self, phase: str, progress: int, message: str = ""):
        """Emit progress update"""
        data = {
            "phase": phase,
            "progress": progress,
            "message": message,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        print(f"PROGRESS:{json.dumps(data)}", flush=True)
        self.progress = progress
        
    def emit_finding(self, finding: Dict[str, Any]):
        """Emit new finding with enriched metadata (CVSS, CWE) and PoC Screenshots"""
        try:
            from core.vulnerability import Vulnerability
            # Enrich the finding using the Vulnerability model
            v = Vulnerability.from_finding(finding)
            finding = v.to_dict()
        except Exception as e:
            # Fallback to original finding if enrichment fails
            pass
            
        # Automated PoC Screenshotting for all finding severities
        severity = finding.get('severity', '').lower()
        target_url = finding.get('url')
        
        if target_url:
            try:
                from recon.visual_survey import VisualSurveyor
                # Resolve path to backend public/screenshots using os.path for platform safety
                root_dir = get_scanner_root()
                parent_dir = os.path.dirname(root_dir)
                screenshot_dir = os.path.join(parent_dir, 'backend', 'public', 'screenshots', 'poc')
                
                # Ensure the poc directory exists
                if not os.path.exists(screenshot_dir):
                    os.makedirs(screenshot_dir, exist_ok=True)
                
                # Extract payload for reflection highlighting
                highlight_val = None
                evidence = finding.get('evidence', {})
                if isinstance(evidence, dict):
                    # Try to find the most 'visible' part of the finding to highlight
                    highlight_val = evidence.get('payload') or evidence.get('reflected_value')
                    
                    # If xss specific marker is used, highlight that part
                    if not highlight_val and 'xssTEST123' in str(evidence):
                        highlight_val = 'xssTEST123'
                
                surveyor = VisualSurveyor(output_dir=screenshot_dir)
                poc_result = surveyor.capture_poc(target_url, highlight_text=highlight_val)
                
                if poc_result and poc_result.get('filename'):
                    # Ensure evidence block exists
                    if 'evidence' not in finding or not isinstance(finding['evidence'], dict):
                        finding['evidence'] = {'raw': finding.get('evidence', '')}
                        
                    # Use forward slash for web URLs, but os.path for local checks
                    finding['evidence']['poc_screenshot'] = f"poc/{poc_result['filename']}"
                    
                    if poc_result.get('alert_captured') or poc_result.get('alert_text'):
                        finding['evidence']['alert_captured'] = poc_result.get('alert_captured') or poc_result.get('alert_text')
                        
            except Exception as e:
                self.emit_warning(f"Failed to capture PoC screenshot for {target_url}: {str(e)}")
            
        self.findings.append(finding)
        print(f"FINDING:{json.dumps(finding)}", flush=True)
        
    def emit_error(self, error: str, fatal: bool = True):
        """Emit error and log to auditor"""
        self.scanner_log(f"ENGINE ERROR: {error}", level="ERROR")
        data = {
            "error": error,
            "fatal": fatal,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        print(f"ERROR:{json.dumps(data)}", flush=True)

    def emit_warning(self, message: str):
        """Emit warning (non-fatal error) and log to auditor"""
        self.scanner_log(f"ENGINE WARNING: {message}", level="WARNING")
        data = {
            "message": message,
            "timestamp": datetime.utcnow().isoformat()
        }
        print(f"WARNING:{json.dumps(data)}", flush=True)

    def emit_crawler_graph(self, graph_data: Dict[str, Any]):
        """Emit crawler graph data for the backend to persist"""
        print(f"CRAWLER_GRAPH:{json.dumps(graph_data)}", flush=True)

    def emit_metadata(self, metadata: Dict[str, Any]):
        """Emit metadata updates for the backend to merge"""
        print(f"METADATA:{json.dumps(metadata)}", flush=True)
        
    def run(self, selected_phase: str = "all"):
        """Main scan execution with modular phase support"""
        try:
            self.emit_progress("initialization", 0, f"Starting {selected_phase} scan...")
            
            # --- Pre-scan Connectivity Check ---
            self.emit_progress("initialization", 1, f"Verifying connectivity to {self.target_url}...")
            try:
                # Use a simple HEAD or GET request to verify the target is up
                check_resp = self.http.get(self.target_url, timeout=15)
                if check_resp is None:
                    raise Exception(f"Target {self.target_url} is unreachable or failed to resolve. Please check the URL.")
                self.emit_progress("initialization", 2, "Target connectivity verified.")
            except Exception as conn_err:
                # Fatal error: cannot scan what we can't reach
                self.emit_error(f"Pre-scan check failed: {str(conn_err)}")
                return {
                    "status": "failed",
                    "error": f"Target unreachable: {str(conn_err)}"
                }

            # Map of phases to methods
            phases = {
                "recon": self.run_recon,
                "discovery": self.run_discovery,
                "visual_survey": self.run_visual_survey,
                "network": self.run_network,
                "owasp": self.run_owasp,
                "cve": self.run_cve,
                "ai_targeted": self.run_targeted_owasp
            }

            if selected_phase == "all":
                # Full sequential scan
                self.run_recon()
                self.run_discovery()
                self.run_visual_survey()
                self.run_network()
                if self.config.get("ai_enabled"):
                    self.run_targeted_owasp()
                else:
                    self.run_owasp()
                self.run_cve()
            elif selected_phase == "recon":
                # For the Wizard: Perform both passive recon and active discovery
                self.run_recon()
                self.run_discovery()
            elif selected_phase == "vuln_only":
                # Multi-phase vulnerability assessment (for interactive wizard continuation)
                self.run_network()
                if self.config.get("ai_enabled"):
                    self.run_targeted_owasp()
                else:
                    self.run_owasp()
                self.run_cve()
            elif selected_phase == "ai_targeted":
                # Targeted demo execution
                self.run_recon()
                self.run_discovery()
                self.run_targeted_owasp()
            elif selected_phase in phases:
                # Run specific phase (handling dependencies if needed)
                phases[selected_phase]()
            else:
                raise ValueError(f"Invalid scan phase: {selected_phase}")

            self.emit_progress("completed", 90, "Generating reports...")
            
            # Generate Report
            try:
                from reporting.report_generator import ReportGenerator
                import shutil
                
                generator = ReportGenerator(ai_assistant=self.ai_assistant)
                report_path = generator.generate_pdf({
                    "target_url": self.target_url,
                    "findings": self.findings,
                    "findings_count": len(self.findings)
                })
                
                # Copy to backend public folder for UI access
                try:
                    root_dir = get_scanner_root()
                    parent_dir = os.path.dirname(root_dir)
                    public_report_dir = os.path.join(parent_dir, 'backend', 'public', 'reports')
                    
                    if not os.path.exists(public_report_dir):
                        os.makedirs(public_report_dir, exist_ok=True)
                        
                    filename = os.path.basename(report_path)
                    shutil.copy2(report_path, os.path.join(public_report_dir, filename))
                    self.metadata['report_url'] = f"/reports/{filename}"
                except Exception as copy_err:
                    self.emit_warning(f"Failed to copy report to public folder: {str(copy_err)}")

                self.metadata['report_path'] = report_path
                self.emit_progress("completed", 100, f"Report generated: {report_path}")
            except Exception as e:
                self.emit_warning(f"Reporting failed: {str(e)}")
            
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
            tech = TechDetector(self.target_url, http_client=self.http)
            tech_results = tech.detect()
            self.metadata['technologies'] = tech_results
            detected = tech_results.get('technologies', [])
            server = tech_results.get('server', 'Unknown')
            self.emit_progress("reconnaissance", 8, f"[Tech Fingerprint] Detected: {', '.join(detected)} | Server: {server}")
            self.emit_metadata({'technologies': tech_results})
        except Exception as e:
            self.emit_warning(f"Tech detection failed: {str(e)}")
            # In Windows/NPM mode, metadata might be crucial for next steps
            # Ensure it's never completely missing
            if not hasattr(self, 'metadata'): self.metadata = {}

        # 1b. Subdomain Enumeration
        if self.config.get("subdomain", True):
            self.emit_progress("reconnaissance", 10, "[Subdomain Enum] Starting enumeration...")
            try:
                from recon.subdomain_scanner import SubdomainScanner
                scanner = SubdomainScanner(self.target_url)
                
                def handle_discovered(sub):
                    self.emit_progress("reconnaissance", 11, f"[Subdomain Enum] Discovered: {sub}")
                
                def handle_live(server_data):
                    url = server_data if isinstance(server_data, str) else server_data.get("url")
                    tech = server_data.get("tech") if isinstance(server_data, dict) else []
                    status = server_data.get("status_code") if isinstance(server_data, dict) else "?"
                    
                    self.emit_progress("reconnaissance", 13, f"[Subdomain Enum] Live: {url} [{status}]")
                    
                    evidence = {"method": "Go Tools (httpx)"}
                    if tech:
                        evidence["technologies"] = tech
                    if isinstance(server_data, dict):
                        evidence["status_code"] = status
                        evidence["title"] = server_data.get("title", "")
                        
                    self.emit_finding({
                        "name": f"Live Subdomain Discovered",
                        "severity": "info",
                        "owasp_category": "Recon",
                        "url": url,
                        "description": f"Discovered an active sub-domain: {url}. Title: {server_data.get('title', 'N/A') if isinstance(server_data, dict) else 'N/A'}",
                        "evidence": evidence,
                        "confidence": 100,
                        "poc": ""
                    })

                results = scanner.run(
                    on_discovered=handle_discovered,
                    on_live=handle_live
                )
                
                live_urls = results.get("live_urls", [])
                total_discovered = results.get("total_subdomains", 0)
                total_live = results.get("live_servers", 0)

                # Proceed to test for Subdomain Takeovers on the enumerated list
                if live_urls:
                    self.emit_progress("reconnaissance", 14, f"[Subdomain Takeover] Testing {len(live_urls)} targets...")
                    try:
                        from recon.subdomain_takeover import SubdomainTakeoverModule
                        takeover_scanner = SubdomainTakeoverModule(self.target_url)
                        takeover_findings = takeover_scanner.scan(live_urls)
                        for find in takeover_findings:
                            self.emit_finding(find)
                    except Exception as ex:
                        self.emit_warning(f"Takeover detection failed: {str(ex)}")

                self.metadata.update({
                    'total_subdomains': total_discovered,
                    'live_servers': total_live,
                    'live_data': results.get("live_data", [])
                })
                self.emit_progress("reconnaissance", 15, f"[Subdomain Enum] Complete: {total_discovered} found, {total_live} live")
            except Exception as e:
                self.emit_warning(f"Subdomain enumeration failed: {str(e)}")

        # 1c. WAF Detection
        if self.config.get("waf", True):
            self.emit_progress("reconnaissance", 16, "[WAF Detect] Checking for signatures...")
            try:
                from recon.waf_detect import WAFDetector
                waf_detector = WAFDetector(self.target_url, http_client=self.http)
                waf_results = waf_detector.detect()
                self.metadata['waf'] = waf_results
                
                if waf_results.get('waf_detected'):
                    # SHIELD ACTIVATED: Propagation of WAF signal to the shared HttpClient
                    self.http.waf_detected = True
                    wafs = ', '.join(waf_results.get('wafs', []))
                    self.emit_progress("reconnaissance", 22, f"  [!] WAF Identified: {wafs}. Entering stealth mode (slow-down active).")
                    self.emit_metadata({'waf': wafs})
                else:
                    self.emit_progress("reconnaissance", 22, "[WAF Detect] No WAF detected")
                    self.emit_metadata({'waf': 'None'})
            except Exception as e:
                self.emit_warning(f"WAF detection failed: {str(e)}")

        # 1d. Sensitive File Discovery
        if self.config.get("sensitive_files", True):
            self.emit_progress("reconnaissance", 23, "[Sensitive Files] Probing common configuration files...")
            try:
                from recon.sensitive_files import SensitiveFileScanner
                # Rate limited but now consistently using shared HttpClient
                sf_scanner = SensitiveFileScanner(self.target_url, http_client=self.http)
                sf_findings = sf_scanner.scan()
                for finding in sf_findings:
                    self.emit_finding(finding)
                self.emit_progress("reconnaissance", 24, f"[Sensitive Files] Probed files. Found {len(sf_findings)} exposures.")
            except Exception as e:
                self.emit_warning(f"Sensitive file scanning failed: {str(e)}")

        # 1e. CMS Fingerprinting
        if self.config.get("cms_fingerprint", True):
            self.emit_progress("reconnaissance", 25, "[CMS] Fingerprinting content management systems...")
            try:
                from recon.cms_fingerprint import CMSFingerprinter
                cms_fingerprinter = CMSFingerprinter(self.target_url, http_client=self.http)
                cms_findings = cms_fingerprinter.scan()
                for finding in cms_findings:
                    self.emit_finding(finding)
                self.emit_progress("reconnaissance", 26, f"[CMS] Fingerprinting complete. Found {len(cms_findings)} CMS items.")
            except Exception as e:
                self.emit_warning(f"CMS Fingerprinting failed: {str(e)}")

    def run_discovery(self):
        """Phase 2: Discovery (Web Crawling & API Detection)"""
        # 2a. Web Crawling
        if self.config.get("crawl", True):
            self.emit_progress("web_crawling", 35, "Crawling web application...")
            try:
                from recon.crawler import WebCrawler
                # Use configurable limits
                crawler = WebCrawler(
                    self.target_url, 
                    max_depth=self.config.get("max_crawl_depth", 3),
                    max_pages=self.config.get("max_pages", 150)
                )
                # Pass session headers (for UA and Auth propagation)
                # Important: Use the HttpClient session's headers
                crawl_results = crawler.crawl(extra_headers=dict(self.http.session.headers))
                
                # Store discovery data
                discovered_urls = crawl_results.get('urls', [])
                attack_surface = crawl_results.get('attack_surface', [])
                forms = crawl_results.get('forms', [])
                parameters = crawl_results.get('parameters', [])
                
                self.metadata['discovered_urls'] = discovered_urls
                self.metadata['crawl_stats'] = crawl_results.get('stats', {})
                self.metadata['attack_surface'] = attack_surface
                self.metadata['forms'] = forms
                self.metadata['extracted_parameters'] = parameters
                
                # Emit graph data for the backend
                self.emit_crawler_graph(crawl_results)
                self.emit_metadata({
                    'discovered_urls': discovered_urls,
                    'crawl_stats': crawl_results.get('stats', {}),
                    'attack_surface_entries': len(attack_surface),
                    'forms': len(forms)
                })
                
                self.emit_progress("web_crawling", 40, f"Discovered {len(discovered_urls)} URLs, {len(forms)} forms, {len(attack_surface)} attack vectors")
            except Exception as e:
                self.emit_warning(f"Crawling failed: {str(e)}")

        # 2b. API Discovery
        if self.config.get("api_discovery", True):
            self.emit_progress("web_crawling", 42, "Discovering API endpoints...")
            try:
                from recon.api_discovery import APIDiscovery
                api_discoverer = APIDiscovery(self.target_url)
                api_results = api_discoverer.discover()
                self.metadata['api'] = api_results
                self.emit_metadata({'api': api_results})
                
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
                self.emit_warning(f"API discovery failed: {str(e)}")

    def run_visual_survey(self):
        """Phase 2.5: Visual Survey (Screenshots)"""
        if self.config.get("visual_survey", True):
            self.emit_progress("visual_survey", 47, "Capturing visual surface (screenshots)...")
            try:
                from recon.visual_survey import VisualSurveyor
                # Go up from core/ to scanner-core/ to root, then backend/public/screenshots
                root_dir = get_scanner_root()
                parent_dir = os.path.dirname(root_dir)
                screenshot_dir = os.path.join(parent_dir, 'backend', 'public', 'screenshots')
                
                surveyor = VisualSurveyor(output_dir=screenshot_dir)
                
                # We screenshot discovered URLs (respect screenshot_limit)
                limit = self.config.get("screenshot_limit", 20)
                urls = list(set([self.target_url] + self.metadata.get('discovered_urls', [])[:limit]))
                
                def handle_capture(url, result):
                    self.emit_progress("visual_survey", 48, f"Captured screenshot: {url}")

                results = surveyor.capture_batch(urls, on_capture=handle_capture)
                self.metadata['screenshots'] = results
                self.emit_progress("visual_survey", 49, f"Captured {len(results)} screenshots")
            except Exception as e:
                self.emit_warning(f"Visual survey failed: {str(e)}")

    def run_network(self):
        """Phase 3: Network Scanning"""
        if self.config.get("port_scan", True):
            self.metadata['ports'] = {}
            targets = self.target_urls
            total_targets = len(targets)
            
            for idx, target in enumerate(targets):
                progress_step = 25 + int((idx / total_targets) * 10)
                self.emit_progress("network_scanning", progress_step, f"[Port Scan] Probing {target}...")
                try:
                    from recon.port_scanner import PortScanner
                    # Strip schema for port scanning if present
                    clean_target = target.replace('http://', '').replace('https://', '').split('/')[0]
                    port_scanner = PortScanner(clean_target)
                    port_results = port_scanner.scan(detect_version=self.config.get("cve_detection", True))
                    
                    # Store results per target
                    self.metadata['ports'][target] = port_results
                    
                    open_ports = port_results.get('open_ports', [])
                    if open_ports:
                        ports_str = ", ".join([str(p['port']) for p in open_ports])
                        self.emit_progress("network_scanning", progress_step + 1, f"  [+] Found ports on {target}: {ports_str}")
                        
                        # Emit findings for each open port for immediate UI feedback
                        for p in open_ports:
                            self.emit_finding({
                                "name": f"Open Port: {p['port']} ({p['service']})",
                                "severity": "info",
                                "owasp_category": "Network",
                                "url": f"{target}:{p['port']}",
                                "description": f"Port {p['port']} is open and running {p['service']}.",
                                "evidence": f"Service: {p.get('service')}, Product: {p.get('product', 'Unknown')}, Version: {p.get('version', 'Unknown')}",
                                "confidence": 100
                            })
                    else:
                        self.emit_progress("network_scanning", progress_step + 1, f"  [-] No common ports open on {target}")
                except Exception as e:
                    self.emit_warning(f"Port scan failed for {target}: {str(e)}")

    def run_targeted_owasp(self):
        """Phase 4.1: AI-Targeted Vulnerability Testing"""
        try:
            from ai.ai_strategist import get_ai_strategy
        except Exception as e:
            self.emit_warning(f"AI Strategist module unavailable: {e}. Falling back to full scan.")
            return self.run_owasp()
            
        self.emit_progress("vulnerability_detection", 40, "Consulting AI Strategist for targeted attack plan...")
        
        try:
            ai_key = self.config.get("ai_api_key", os.environ.get("GROQ_API_KEY", ""))
            
            strategies = get_ai_strategy(
                surface={
                    'attack_surface': self.metadata.get('attack_surface', []),
                    'forms': self.metadata.get('forms', []),
                    'attack_surface_entries': len(self.metadata.get('attack_surface', [])),
                    'forms_count': len(self.metadata.get('forms', []))
                },
                metadata={"target": self.target_url},
                use_ai=True,
                provider="groq",
                api_key=ai_key
            )
            
            self.emit_progress("vulnerability_detection", 50, f"AI generated {len(strategies)} targeted strategies.")
            
            PYTHON_MODULE_MAP = {
                "Server-Side Template Injection": ("owasp.ssti", "IntensiveSSTIScanner"),
                "SQL Injection": ("owasp.sql_injection_intensive", "IntensiveSQLiScanner"),
                "NoSQL Injection": ("owasp.nosql_injection", "IntensiveNoSQLScanner"),
                "Command Injection": ("owasp.command_injection_intensive", "IntensiveCommandInjectionScanner"),
                "LDAP Injection": ("owasp.ldap_injection", "IntensiveLDAPScanner"),
                "XXE": ("owasp.xxe", "IntensiveXXEScanner"),
                "CRLF Injection": ("owasp.crlf", "IntensiveCRLFScanner"),
                "IDOR": ("owasp.idor", "IntensiveIDORScanner"),
                "JWT": ("owasp.jwt_vulnerabilities", "IntensiveJWTScanner"),
                "Mass Assignment": ("owasp.mass_assignment", "MassAssignmentModule"),
                "A01: Access Control": ("owasp.a01_access_control", "IntensiveAccessControlScanner"),
                "CORS": ("owasp.cors", "IntensiveCORSScanner"),
                "Host Header Injection": ("owasp.host_header", "IntensiveHostHeaderScanner"),
                "Rate Limit Bypass": ("owasp.rate_limit_bypass", "IntensiveRateLimitScanner"),
                "XSS": ("owasp.a03_xss", "IntensiveXSSScanner"),
                "SSRF": ("owasp.a10_ssrf", "IntensiveSSRFScanner"),
                "GraphQL Abuse": ("owasp.graphql_abuse", "GraphQLAbuseModule"),
                "Security Misconfiguration": ("owasp.a05_misconfig", "IntensiveMisconfigScanner"),
                "Open Redirect": ("owasp.open_redirect", "IntensiveOpenRedirectScanner"),
                "HTTP Request Smuggling": ("owasp.request_smuggling", "IntensiveRequestSmugglingScanner"),
            }

            HEAVY_MODULES = [
                "SQL Injection", "NoSQL Injection", "Command Injection", 
                "SSRF", "XXE", "Server-Side Template Injection", "LDAP Injection",
                "HTTP Request Smuggling"
            ]

            import importlib
            import inspect

            # --- TIER 1: THE SURGICAL STRIKE (Priority 1 & 2) ---
            high_priority = [s for s in strategies if s.priority <= 2]
            self.emit_progress("vulnerability_detection", 55, f"Starting Tier 1: Surgical Strike on {len(high_priority)} high-value targets.")
            
            for idx, strategy in enumerate(high_priority):
                pct = 55 + int((idx / max(len(high_priority), 1)) * 25)
                self.emit_progress("vulnerability_detection", pct, 
                                  f"  [Tier 1] {strategy.target_url}: {', '.join(strategy.recommended_modules)}")
                
                self.emit_finding({
                    "name": "AI Attack Strategy (Tier 1)",
                    "severity": "info",
                    "owasp_category": "Planning",
                    "url": strategy.target_url,
                    "description": f"Priority 1/2 Surgical Strike: {strategy.reasoning}",
                    "evidence": {"modules": strategy.recommended_modules, "confidence": strategy.confidence, "priority": strategy.priority},
                    "confidence": 100
                })
                
                target_vectors = self._get_vectors_with_context(strategy.target_url)
                for mod_name in strategy.recommended_modules:
                    self._run_single_targeted_module(strategy.target_url, mod_name, PYTHON_MODULE_MAP, vectors=target_vectors)

            # --- TIER 2: THE SWEEP (Priority 3+ and Supplemental) ---
            remaining = [s for s in strategies if s.priority > 2]
            self.emit_progress("vulnerability_detection", 80, f"Starting Tier 2: The Sweep on {len(remaining)} targets.")
            
            for idx, strategy in enumerate(remaining):
                # For sweep, we might want to prioritize lighter modules if desired, 
                # but here we follow AI recommendations faithfully.
                self.emit_progress("vulnerability_detection", 80, f"  [Tier 2] Broader testing on {strategy.target_url}")
                target_vectors = self._get_vectors_with_context(strategy.target_url)
                for mod_name in strategy.recommended_modules:
                    self._run_single_targeted_module(strategy.target_url, mod_name, PYTHON_MODULE_MAP, vectors=target_vectors)

            # --- CATCH-ALL SAFETY NET ---
            # Ensure every unique URL in the attack surface gets at least a baseline scan 
            # if it wasn't already covered by the AI strategy.
            strategy_urls = set(s.target_url for s in strategies)
            all_surface_urls = set(e.get('url') for e in self.metadata.get('attack_surface', []) if e.get('url'))
            untested_urls = all_surface_urls - strategy_urls
            
            if untested_urls:
                self.emit_progress("vulnerability_detection", 90, f"Running Safety Net sweep on {len(untested_urls)} remaining endpoints.")
                baseline_modules = ["XSS", "Security Misconfiguration", "Open Redirect"]
                for url in list(untested_urls)[:20]: # Limit catch-all to prevent bloat
                    target_vectors = self._get_vectors_with_context(url)
                    for mod_name in baseline_modules:
                        self._run_single_targeted_module(url, mod_name, PYTHON_MODULE_MAP, vectors=target_vectors)

        except Exception as e:
            self.emit_warning(f"AI Strategy failed: {e}. Falling back to standard OWASP scan.")
            self.run_owasp()

    def _get_vectors_with_context(self, target_url):
        """Build context (sibling parameters) for attack vectors matching the target"""
        attack_surface = self.metadata.get('attack_surface', [])
        forms = self.metadata.get('forms', [])
        
        vectors = [v.copy() for v in attack_surface if v.get('url') == target_url]
        
        for v in vectors:
            target_param = v['parameter']
            context = {}
            for form in forms:
                url_match = form.get('url') == target_url or form.get('action') == target_url
                if not url_match: continue
                form_params = form.get('parameters', []) or form.get('inputs', [])
                param_names = [p if isinstance(p, str) else p.get('name') for p in form_params]
                if target_param in param_names:
                    for p in form_params:
                        name = p if isinstance(p, str) else p.get('name')
                        if name and name != target_param:
                            context[name] = 'test' if isinstance(p, str) else p.get('value', '1')
                    break
            v['context'] = context
        return vectors

    def _run_single_targeted_module(self, target_url, mod_name, module_map, vectors=None):
        """Helper to execute a single module vs a single target URL"""
        if mod_name not in module_map:
            return
            
        mod_path, class_name = module_map[mod_name]
        try:
            import importlib
            import inspect
            module = importlib.import_module(mod_path)
            scanner_class = getattr(module, class_name)
            
            sig = inspect.signature(scanner_class.__init__)
            if 'http_client' in sig.parameters:
                module_inst = scanner_class(self.target_url, http_client=self.http)
            else:
                module_inst = scanner_class(self.target_url)

            # --- Inject Custom Payloads ---
            custom_payloads = self.config.get("custom_payloads", [])
            if hasattr(module_inst, 'payloads') and isinstance(module_inst.payloads, list) and custom_payloads:
                for cp in custom_payloads:
                    if module_inst.payloads and isinstance(module_inst.payloads[0], dict):
                        np = module_inst.payloads[0].copy()
                        np["payload"] = cp
                        if "expected" in np: np["expected"] = "__NO_MATCH__"
                        module_inst.payloads.append(np)
                    else:
                        module_inst.payloads.append(cp)

            results_container = []
            scan_sig = inspect.signature(module_inst.scan)

            def _run_scan(container):
                try:
                    # In targeted mode, we configure kwargs based on scanner signature
                    kwargs = {}
                    if 'urls' in scan_sig.parameters:
                        kwargs['urls'] = [target_url]
                    if vectors is not None and 'attack_surface' in scan_sig.parameters:
                        kwargs['attack_surface'] = vectors
                        
                    if kwargs:
                        container.extend(module_inst.scan(**kwargs))
                    else:
                        container.extend(module_inst.scan())
                except Exception:
                    pass

            import threading
            t = threading.Thread(target=_run_scan, args=(results_container,), daemon=True)
            t.start()
            
            # DYNAMIC TIMEOUT: 5s per URL, min 60s, max 300s
            m_timeout = self.config.get("module_timeout", max(60, min(300, 1 * 5))) 
            t.join(timeout=m_timeout) 
            
            # [FIX] Emit findings even if the thread is still alive (timeout happened)
            # This prevents data loss when a scanner thread hangs but has findings.
            if t.is_alive():
                 self.emit_warning(f"Module '{mod_name}' vs {target_url} timed out after {m_timeout}s. Emitting partial results.")
            
            for finding in results_container:
                self.emit_finding(finding)
        except Exception:
            pass

    def run_owasp(self):
        """Phase 4: Vulnerability Testing (Custom Python Modules first, Nuclei as fallback)"""
        if self.config.get("owasp", True):
            custom_payloads = self.config.get("custom_payloads", [])
            
            # ─────────────────────────────────────────────────────────────
            # PHASE A: Custom Python OWASP Modules (PRIMARY)
            # ─────────────────────────────────────────────────────────────
            PYTHON_MODULE_MAP = {
                "Server-Side Template Injection": ("owasp.ssti", "IntensiveSSTIScanner"),
                "SQL Injection": ("owasp.sql_injection_intensive", "IntensiveSQLiScanner"),
                "NoSQL Injection": ("owasp.nosql_injection", "IntensiveNoSQLScanner"),
                "Command Injection": ("owasp.command_injection_intensive", "IntensiveCommandInjectionScanner"),
                "LDAP Injection": ("owasp.ldap_injection", "IntensiveLDAPScanner"),
                "XXE": ("owasp.xxe", "IntensiveXXEScanner"),
                "CRLF Injection": ("owasp.crlf", "IntensiveCRLFScanner"),
                "IDOR": ("owasp.idor", "IntensiveIDORScanner"),
                "JWT": ("owasp.jwt_vulnerabilities", "IntensiveJWTScanner"),
                "Mass Assignment": ("owasp.mass_assignment", "MassAssignmentModule"),
                "A01: Access Control": ("owasp.a01_access_control", "IntensiveAccessControlScanner"),
                "CORS": ("owasp.cors", "IntensiveCORSScanner"),
                "Host Header Injection": ("owasp.host_header", "IntensiveHostHeaderScanner"),
                "Rate Limit Bypass": ("owasp.rate_limit_bypass", "IntensiveRateLimitScanner"),
                "XSS": ("owasp.a03_xss", "IntensiveXSSScanner"),
                "SSRF": ("owasp.a10_ssrf", "IntensiveSSRFScanner"),
                "GraphQL Abuse": ("owasp.graphql_abuse", "GraphQLAbuseModule"),
                "Security Misconfiguration": ("owasp.a05_misconfig", "IntensiveMisconfigScanner"),
                "Open Redirect": ("owasp.open_redirect", "IntensiveOpenRedirectScanner"),
                "HTTP Request Smuggling": ("owasp.request_smuggling", "IntensiveRequestSmugglingScanner"),
            }

            # Resolve which modules to run: if none specified, run ALL
            target_modules = self.config.get("modules", self.config.get("target_modules", []))
            if not target_modules:
                target_modules = list(PYTHON_MODULE_MAP.keys())

            import importlib
            import inspect
            from bs4 import BeautifulSoup
            from urllib.parse import urljoin, urlencode

            for idx, target in enumerate(self.target_urls):
                pct = 50 + int((idx / max(len(self.target_urls), 1)) * 20)
                self.emit_progress("vulnerability_detection", pct, f"Running OWASP modules on: {target}")

                # 1. Pool potential URLs for parameter discovery
                # We combine the main target with any URLs found by the crawler
                discovery_pool = list(set([target] + self.metadata.get('discovered_urls', [])))
                
                urls_to_test = []
                
                # 2. Heuristic Blind Parameter Discovery (Advanced Widening)
                self.emit_progress("vulnerability_detection", pct + 1, "[Blind Discovery] Probing for hidden parameters (Heuristic)...")
                try:
                    from recon.param_discovery import ParamDiscovery
                    pd = ParamDiscovery(target, http_client=self.http)
                    
                    # Run discovery on top 10 discovered pages
                    hidden_params_map = pd.discover(discovery_pool[:10])
                    
                    for pool_url, params in hidden_params_map.items():
                        if params:
                            self.emit_progress("vulnerability_detection", pct + 1, f"  [!] Found hidden params on {pool_url}: {', '.join(params)}")
                            
                            # Add to test pool
                            query_params = {p: 'securescan_fuzz' for p in params}
                            separator = "&" if "?" in pool_url else "?"
                            fuzzed_url = f"{pool_url}{separator}{urlencode(query_params)}"
                            urls_to_test.append(fuzzed_url)
                            
                            # Emit an info finding for visibility
                            self.emit_finding({
                                "name": "Hidden Parameter Discovered",
                                "severity": "info",
                                "owasp_category": "Discovery",
                                "url": pool_url,
                                "description": f"Heuristic analysis detected hidden parameters that are not present in the HTML: {', '.join(params)}",
                                "evidence": {"params": params, "method": "Heuristic Divergence Analysis"},
                                "confidence": 90
                            })
                except Exception as e:
                    self.emit_warning(f"Blind discovery failed: {str(e)}")

                # 3. Deep Parameter & Form Extraction
                self.emit_progress("vulnerability_detection", pct + 2, "[Param Discovery] Extracting visible surface area...")
                
                # --- NEW: Inject Katana's Extracted Attack Surface ---
                attack_surface = self.metadata.get('attack_surface', [])
                if attack_surface:
                    self.emit_progress("vulnerability_detection", pct + 2, f"  [+] Integrating {len(attack_surface)} Katana attack surface entries...")
                    for entry in attack_surface:
                        try:
                            # Generate a testable URL for the engine using the parameter
                            base_url = entry.get('url')
                            param = entry.get('parameter')
                            if base_url and param:
                                # This ensures the engine tests this specific parameter
                                fuzz_url = f"{base_url}{'&' if '?' in base_url else '?'}{param}=securescan_fuzz"
                                urls_to_test.append(fuzz_url)
                        except Exception:
                            pass

                # --- Fallback/Supplemental: BeautifulSoup Extraction ---
                for pool_url in discovery_pool[:50]: # Search up to 50 discovered pages for params
                    try:
                        # Skip static files in discovery
                        if any(pool_url.lower().endswith(ext) for ext in ['.png', '.jpg', '.jpeg', '.gif', '.css', '.pdf']):
                            continue
                            
                        resp = self.http.get(pool_url, timeout=10)
                        if not resp or not resp.text:
                            continue
                            
                        soup = BeautifulSoup(resp.text, 'html.parser')
                        
                        # a) Regular links with parameters
                        for a in soup.find_all('a', href=True):
                            href = a['href']
                            full_url = urljoin(pool_url, href)
                            if '?' in full_url and '=' in full_url:
                                if urlparse(target).netloc == urlparse(full_url).netloc:
                                    urls_to_test.append(full_url)
                        
                        # b) Forms (GET and POST actions)
                        for form in soup.find_all('form'):
                            action = form.get('action', '')
                            method = form.get('method', 'get').lower()
                            if action:
                                full_url = urljoin(pool_url, action)
                                if urlparse(target).netloc == urlparse(full_url).netloc:
                                    # For GET forms, we can often fuzz the action directly if we see inputs
                                    if method == 'get':
                                        inputs = [i.get('name') for i in form.find_all('input') if i.get('name')]
                                        if inputs:
                                            fuzz_url = full_url + "?" + "&".join([f"{i}=fuzz" for i in inputs])
                                            urls_to_test.append(fuzz_url)
                                    else:
                                        # POST forms are handled by specific modules if they support forms
                                        urls_to_test.append(full_url)
                                        
                    except Exception:
                        continue
                
                # 3. Hidden Parameter Fuzzing (Widening the attack surface)
                self.emit_progress("vulnerability_detection", pct + 1, "[Param Fuzz] Probing for hidden parameters...")
                common_params = ['debug', 'admin', 'test', 'dev', 'load', 'file', 'page', 'id', 'user', 'config', 'log', 'cmd']
                for pool_url in discovery_pool[:10]: # Probing top 10 discovery pages
                    try:
                        # Simple probe for common parameters
                        query_params = {p: 'securescan_test' for p in common_params}
                        fuzz_url = pool_url + ("&" if "?" in pool_url else "?") + urlencode(query_params)
                        urls_to_test.append(fuzz_url)
                    except: continue

                # 4. Clean and Limit
                # Filter out obvious duplicates and static content
                urls_to_test = list(set(urls_to_test))
                
                # SMART LIMITING: Prioritize URLs with more parameters
                urls_to_test.sort(key=lambda u: (u.count('='), len(u)), reverse=True)
                urls_to_test = urls_to_test[:50] # Increased limit to 50 due to better parsing
                
                if not urls_to_test:
                    urls_to_test = [target] # Fallback to base target
                    
                self.emit_progress("vulnerability_detection", pct + 1,
                                   f"  → Found {len(discovery_pool)} pages. Extracted {len(urls_to_test)} unique surface areas to test.")

                for mod_name in target_modules:
                    if mod_name not in PYTHON_MODULE_MAP:
                        continue
                    mod_path, class_name = PYTHON_MODULE_MAP[mod_name]
                    try:
                        module = importlib.import_module(mod_path)
                        scanner_class = getattr(module, class_name)
                        
                        # Check if scanner accepts http_client
                        sig = inspect.signature(scanner_class.__init__)
                        if 'http_client' in sig.parameters:
                            module_inst = scanner_class(target, http_client=self.http)
                        else:
                            module_inst = scanner_class(target)

                        # Inject custom user payloads
                        if hasattr(module_inst, 'payloads') and isinstance(module_inst.payloads, list) and custom_payloads:
                            for cp in custom_payloads:
                                if module_inst.payloads and isinstance(module_inst.payloads[0], dict):
                                    np = module_inst.payloads[0].copy()
                                    np["payload"] = cp
                                    if "expected" in np:
                                        np["expected"] = "__NO_MATCH__"
                                    module_inst.payloads.append(np)
                                else:
                                    module_inst.payloads.append(cp)

                        results = []
                        results_container = []
                        scan_sig = inspect.signature(module_inst.scan)

                        def _run_scan(container):
                            try:
                                # Check if module supports enhanced attack_surface vectors (POST support)
                                if 'attack_surface' in scan_sig.parameters:
                                    surface = self.metadata.get('attack_surface', [])
                                    container.extend(module_inst.scan(urls_to_test, surface))
                                elif 'urls' in scan_sig.parameters:
                                    container.extend(module_inst.scan(urls_to_test))
                                else:
                                    container.extend(module_inst.scan())
                            except Exception:
                                pass

                        import threading
                        t = threading.Thread(target=_run_scan, args=(results_container,), daemon=True)
                        t.start()
                        
                        # DYNAMIC TIMEOUT: 5s per URL, min 60s, max 300s
                        m_timeout = self.config.get("module_timeout", max(60, min(300, len(urls_to_test) * 5)))
                        t.join(timeout=m_timeout) 
                        # [FIX] Always use results_container to prevent data loss on timeout
                        if t.is_alive():
                            self.emit_warning(f"Module '{mod_name}' timed out after {m_timeout}s. Emitting partial results.")
                        
                        for finding in results_container:
                            self.emit_finding(finding)

                        if results:
                            self.emit_progress("vulnerability_detection", pct + 2,
                                               f"  ✓ {mod_name}: {len(results)} finding(s)")
                    except Exception as emod:
                        self.emit_warning(f"Module '{mod_name}' failed: {str(emod)}")

            if custom_payloads:
                self.emit_progress("vulnerability_detection", 72,
                                   f"Custom payloads ({len(custom_payloads)}) injected into modules above.")

            self.emit_progress("vulnerability_detection", 74, "Custom OWASP module checks completed.")

            # ─────────────────────────────────────────────────────────────
            # PHASE B: Nuclei (Final Mop-up / Broad Fallback)
            # ─────────────────────────────────────────────────────────────
            if self.config.get("nuclei_fallback", True):
                try:
                    from vulnerability.nuclei_scanner import NucleiScanner

                    for idx, target in enumerate(self.target_urls):
                        pct = 75 + int((idx / max(len(self.target_urls), 1)) * 10)
                        self.emit_progress("vulnerability_detection", pct, f"[Nuclei Mop-up] Finalizing scan on: {target}")

                        scanner = NucleiScanner(target)
                        
                        # Broad scan strategy for better findings
                        # We use severity and generic tags if no specific modules are forced
                        broad_severity = self.config.get("nuclei_severity", ["critical", "high", "medium"])
                        broad_tags = self.config.get("nuclei_tags", ["generic", "cve", "misconfig", "exposure", "owasp"])

                        def handle_finding(finding):
                            # Optionally enrich with PayloadLab
                            try:
                                from vulnerability.payload_lab import PayloadLab
                                lab = PayloadLab()
                                
                                # Add custom payloads logic to PayloadLab dynamically
                                if custom_payloads:
                                    cat = lab._map_to_category(finding['name'])
                                    if cat not in lab.payload_templates:
                                        lab.payload_templates[cat] = []
                                    for cp in custom_payloads:
                                        lab.payload_templates[cat].append({"name": "Custom User Payload", "payload": cp})
                                
                                if not finding.get('pocs'):
                                    f_url = finding.get('url', target)
                                    param = None
                                    if '?' in f_url:
                                        import urllib.parse
                                        query = urllib.parse.urlparse(f_url).query
                                        params = urllib.parse.parse_qs(query)
                                        if params: param = list(params.keys())[0]
                                    finding['pocs'] = lab.generate_poc(finding['name'], f_url, param)
                            except Exception:
                                pass
                                
                            self.emit_finding(finding)

                        # Run the scan with fallback logic
                        scanner.scan(
                            selected_modules=target_modules, 
                            on_finding=handle_finding,
                            severity=broad_severity,
                            tags=broad_tags
                        )
                        
                except Exception as e:
                    self.emit_warning(f"Nuclei Fallback failed: {str(e)}")

            self.emit_progress("vulnerability_detection", 85, "Vulnerability testing completed.")

    def run_cve(self):
        """Phase 5: CVE Matching"""
        if self.config.get("cve_detection", True) and 'ports' in self.metadata:
            self.emit_progress("cve_detection", 32, "[CVE Lookup] Matching services...")
            try:
                from cve.cve_matcher import CVEMatcher
                matcher = CVEMatcher()
                
                for target, port_results in self.metadata['ports'].items():
                    open_ports = port_results.get('open_ports', [])
                    if open_ports:
                        cve_findings = []
                        for port_info in open_ports:
                            if port_info.get('version') or port_info.get('product'):
                                # Add target context to the finding later
                                findings = matcher.match_service(port_info)
                                cve_findings.extend(findings)
                        
                        for finding in cve_findings:
                            # Ensure finding URL reflects the target
                            finding['url'] = target
                            self.emit_finding(finding)
                
                self.emit_progress("cve_detection", 34, "CVE enrichment completed")
            except Exception as e:
                self.emit_error(f"CVE detection failed: {str(e)}")


def main():
    """Entry point for scanner"""
    if len(sys.argv) < 3:
        print("Usage: python engine.py <target_url> <config_json> [phase] [scan_id]")
        sys.exit(1)
        
    target_url = sys.argv[1]
    config = json.loads(sys.argv[2])
    phase = sys.argv[3] if len(sys.argv) > 3 else "all"
    scan_id = sys.argv[4] if len(sys.argv) > 4 else None
    
    engine = ScanEngine(target_url, config, scan_id=scan_id)
    result = engine.run(selected_phase=phase)
    
    print(f"RESULT:{json.dumps(result)}", flush=True)


if __name__ == "__main__":
    main()
