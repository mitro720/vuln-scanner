"""
Port Scanner Module
Performs network reconnaissance to identify open ports and services
"""

import socket
import concurrent.futures
from typing import List, Dict, Any
from urllib.parse import urlparse

class PortScanner:
    def __init__(self, target_url: str):
        self.target_url = target_url
        parsed = urlparse(target_url)
        self.target_host = parsed.hostname or target_url
        
        # Common ports to scan
        self.common_ports = [
            21,    # FTP
            22,    # SSH
            23,    # Telnet
            25,    # SMTP
            53,    # DNS
            80,    # HTTP
            110,   # POP3
            143,   # IMAP
            443,   # HTTPS
            445,   # SMB
            3306,  # MySQL
            3389,  # RDP
            5432,  # PostgreSQL
            5900,  # VNC
            8000,  # HTTP Alt
            8080,  # HTTP Proxy
            8443,  # HTTPS Alt
            27017, # MongoDB
        ]
        
    def scan_port(self, port: int, timeout: float = 1.0, detect_version: bool = True) -> Dict[str, Any]:
        """Scan a single port with optional version detection"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((self.target_host, port))
            sock.close()
            
            if result == 0:
                service = self._identify_service(port)
                port_info = {
                    'port': port,
                    'state': 'open',
                    'service': service
                }
                
                # Add version detection if enabled
                if detect_version:
                    try:
                        from cve.version_detector import VersionDetector
                        detector = VersionDetector(timeout=timeout)
                        version_info = detector.detect_version(self.target_host, port, service)
                        
                        if version_info.get('version'):
                            port_info['version'] = version_info['version']
                        if version_info.get('banner'):
                            port_info['banner'] = version_info['banner']
                        if version_info.get('product'):
                            port_info['product'] = version_info['product']
                    except Exception as e:
                        # Version detection failed, continue without it
                        pass
                
                return port_info
        except socket.gaierror:
            return None
        except socket.error:
            return None
            
        return None

        
    def _identify_service(self, port: int) -> str:
        """Identify common services by port"""
        services = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            445: 'SMB',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            5900: 'VNC',
            8000: 'HTTP-Alt',
            8080: 'HTTP-Proxy',
            8443: 'HTTPS-Alt',
            27017: 'MongoDB',
        }
        return services.get(port, 'Unknown')
        
    def scan(self, ports: List[int] = None, max_workers: int = 50, detect_version: bool = True) -> Dict[str, Any]:
        """Scan multiple ports concurrently with optional version detection"""
        if ports is None:
            ports = self.common_ports
            
        open_ports = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_port = {
                executor.submit(self.scan_port, port, 1.0, detect_version): port 
                for port in ports
            }
            
            for future in concurrent.futures.as_completed(future_to_port):
                result = future.result()
                if result:
                    open_ports.append(result)
                    
        return {
            'target': self.target_host,
            'open_ports': open_ports,
            'total_scanned': len(ports),
            'total_open': len(open_ports)
        }


if __name__ == "__main__":
    # Test
    scanner = PortScanner("example.com")
    results = scanner.scan()
    print(f"Found {results['total_open']} open ports:")
    for port_info in results['open_ports']:
        print(f"  Port {port_info['port']}: {port_info['service']}")
