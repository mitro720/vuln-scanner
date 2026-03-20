import socket
from urllib.parse import urlparse
from typing import List, Dict, Any

class RequestSmugglingModule:
    """
    Detects potential HTTP Request Smuggling (CL.TE or TE.CL) vulnerabilities.
    Sends raw malformed HTTP requests over sockets since Python's requests library 
    will automatically fix invalid TE/CL headers.
    """
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.parsed = urlparse(target_url)
        self.host = self.parsed.netloc.split(':')[0]
        self.port = self.parsed.port or (443 if self.parsed.scheme == 'https' else 80)
        
    def scan(self, urls: List[str]) -> List[Dict[str, Any]]:
        findings = []
        
        # Testing the base URL is enough for infrastructure-level smuggling detection
        if not urls:
            return findings
            
        url = urls[0]
        self.parsed = urlparse(url)
        self.host = self.parsed.netloc.split(':')[0]
        self.port = self.parsed.port or (443 if self.parsed.scheme == 'https' else 80)
        
        try:
            # Send a CL.TE probe (Content-Length is used by frontend, Transfer-Encoding by backend)
            # This probe is designed to cause a timeout on the backend if vulnerable
            # because the backend waits for the next chunk, but the frontend stopped sending.
            
            cl_te_payload = (
                f"POST {self.parsed.path or '/'} HTTP/1.1\r\n"
                f"Host: {self.host}\r\n"
                "Content-Type: application/x-www-form-urlencoded\r\n"
                "Content-Length: 4\r\n"
                "Transfer-Encoding: chunked\r\n"
                "\r\n"
                "1\r\n"
                "Z\r\n"
                "Q\r\n"
            )
            
            if self.send_probe(cl_te_payload, timeout=5) == "timeout":
                findings.append({
                    "name": "HTTP Request Smuggling (CL.TE Probe)",
                    "severity": "high",
                    "owasp_category": "A05:2021", # Security Misconfiguration / Routing
                    "url": url,
                    "description": "The server infrastructure appears vulnerable to HTTP Request Smuggling (CL.TE). A malformed request with both Content-Length and Transfer-Encoding headers caused a timeout, suggesting the frontend and backend servers disagree on request boundaries.",
                    "confidence": 75,
                    "technique": "Time-based Inference (CL.TE Payload)",
                    "evidence": "A timeout occurred when sending a specific CL.TE payload, which forces standard robust servers to reject with 400 Bad Request immediately.",
                    "poc": cl_te_payload.replace('\r', '\\r').replace('\n', '\\n'),
                    "remediation": "Disable connection reuse between frontend and backend servers, or configure both to parse HTTP headers consistently (e.g., rejecting requests with both CL and TE headers)."
                })
        except Exception as e:
            pass
            
        return findings
        
    def send_probe(self, payload: str, timeout: int = 5) -> str:
        """Sends a raw payload over a socket and returns 'timeout' if it hangs."""
        import ssl
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            if self.port == 443:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=self.host)
                
            sock.connect((self.host, self.port))
            sock.sendall(payload.encode('utf-8'))
            
            # Try to receive data
            response = sock.recv(4096)
            sock.close()
            
            if response:
                return "response"
            return "empty"
            
        except socket.timeout:
            return "timeout"
        except Exception as e:
            return "error"
