"""
Service Version Detector
Detects service versions through banner grabbing and fingerprinting
"""

import socket
import ssl
import re
from typing import Dict, Optional, Tuple
from urllib.parse import urlparse
import requests

class VersionDetector:
    """Detects service versions for common protocols"""
    
    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout
    
    def detect_version(self, host: str, port: int, service: str) -> Dict[str, Optional[str]]:
        """
        Detect service version
        
        Args:
            host: Target hostname or IP
            port: Port number
            service: Service name (e.g., 'HTTP', 'SSH', 'FTP')
        
        Returns:
            Dictionary with 'version' and 'banner' keys
        """
        service_upper = service.upper()
        
        # Route to appropriate detection method
        if service_upper in ['HTTP', 'HTTPS', 'HTTP-ALT', 'HTTP-PROXY', 'HTTPS-ALT']:
            return self._detect_http_version(host, port, service_upper)
        elif service_upper == 'SSH':
            return self._detect_ssh_version(host, port)
        elif service_upper == 'FTP':
            return self._detect_ftp_version(host, port)
        elif service_upper == 'SMTP':
            return self._detect_smtp_version(host, port)
        elif service_upper in ['MYSQL', 'POSTGRESQL', 'MONGODB']:
            return self._detect_database_version(host, port, service_upper)
        else:
            # Generic banner grab
            return self._generic_banner_grab(host, port)
    
    def _detect_http_version(self, host: str, port: int, service: str) -> Dict[str, Optional[str]]:
        """Detect HTTP server version from headers"""
        try:
            protocol = 'https' if 'HTTPS' in service else 'http'
            url = f"{protocol}://{host}:{port}/"
            
            response = requests.get(
                url,
                timeout=self.timeout,
                verify=False,  # Don't verify SSL for scanning
                allow_redirects=False
            )
            
            # Get Server header
            server_header = response.headers.get('Server', '')
            
            if server_header:
                version = self._parse_http_server_version(server_header)
                return {
                    'version': version,
                    'banner': server_header,
                    'product': self._extract_product_name(server_header)
                }
            
            return {'version': None, 'banner': None, 'product': None}
            
        except Exception as e:
            return {'version': None, 'banner': None, 'product': None}
    
    def _parse_http_server_version(self, server_header: str) -> Optional[str]:
        """Parse version from HTTP Server header"""
        # Common patterns:
        # "Apache/2.4.49 (Unix)"
        # "nginx/1.18.0"
        # "Microsoft-IIS/10.0"
        
        patterns = [
            r'Apache/(\d+\.\d+\.\d+)',
            r'nginx/(\d+\.\d+\.\d+)',
            r'Microsoft-IIS/(\d+\.\d+)',
            r'lighttpd/(\d+\.\d+\.\d+)',
            r'(\d+\.\d+\.\d+)',  # Generic version pattern
        ]
        
        for pattern in patterns:
            match = re.search(pattern, server_header)
            if match:
                return match.group(1)
        
        return None
    
    def _extract_product_name(self, server_header: str) -> Optional[str]:
        """Extract product name from server header"""
        # Extract the product name (e.g., "Apache", "nginx")
        match = re.match(r'^([a-zA-Z\-]+)', server_header)
        if match:
            return match.group(1).lower()
        return None
    
    def _detect_ssh_version(self, host: str, port: int) -> Dict[str, Optional[str]]:
        """Detect SSH version from banner"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))
            
            # SSH sends banner immediately
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            # Banner format: "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3"
            version = self._parse_ssh_banner(banner)
            
            return {
                'version': version,
                'banner': banner,
                'product': 'openssh' if 'OpenSSH' in banner else 'ssh'
            }
            
        except Exception as e:
            return {'version': None, 'banner': None, 'product': None}
    
    def _parse_ssh_banner(self, banner: str) -> Optional[str]:
        """Parse SSH version from banner"""
        # Pattern: "SSH-2.0-OpenSSH_8.2p1"
        match = re.search(r'OpenSSH[_\s](\d+\.\d+p?\d*)', banner)
        if match:
            return match.group(1)
        
        # Generic SSH version
        match = re.search(r'SSH-(\d+\.\d+)', banner)
        if match:
            return match.group(1)
        
        return None
    
    def _detect_ftp_version(self, host: str, port: int) -> Dict[str, Optional[str]]:
        """Detect FTP version from banner"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))
            
            # FTP sends banner on connect
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            # Banner format: "220 ProFTPD 1.3.5 Server (Debian)"
            version = self._parse_ftp_banner(banner)
            
            return {
                'version': version,
                'banner': banner,
                'product': self._extract_ftp_product(banner)
            }
            
        except Exception as e:
            return {'version': None, 'banner': None, 'product': None}
    
    def _parse_ftp_banner(self, banner: str) -> Optional[str]:
        """Parse FTP version from banner"""
        patterns = [
            r'ProFTPD[/\s](\d+\.\d+\.\d+)',
            r'vsftpd[/\s](\d+\.\d+\.\d+)',
            r'FileZilla Server[/\s](\d+\.\d+\.\d+)',
            r'(\d+\.\d+\.\d+)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, banner)
            if match:
                return match.group(1)
        
        return None
    
    def _extract_ftp_product(self, banner: str) -> Optional[str]:
        """Extract FTP product name"""
        if 'ProFTPD' in banner:
            return 'proftpd'
        elif 'vsftpd' in banner:
            return 'vsftpd'
        elif 'FileZilla' in banner:
            return 'filezilla'
        return 'ftp'
    
    def _detect_smtp_version(self, host: str, port: int) -> Dict[str, Optional[str]]:
        """Detect SMTP version from banner"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))
            
            # SMTP sends banner on connect
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            # Banner format: "220 mail.example.com ESMTP Postfix"
            version = self._parse_smtp_banner(banner)
            
            return {
                'version': version,
                'banner': banner,
                'product': self._extract_smtp_product(banner)
            }
            
        except Exception as e:
            return {'version': None, 'banner': None, 'product': None}
    
    def _parse_smtp_banner(self, banner: str) -> Optional[str]:
        """Parse SMTP version from banner"""
        patterns = [
            r'Postfix[/\s](\d+\.\d+\.\d+)',
            r'Sendmail[/\s](\d+\.\d+\.\d+)',
            r'Exim[/\s](\d+\.\d+)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, banner)
            if match:
                return match.group(1)
        
        return None
    
    def _extract_smtp_product(self, banner: str) -> Optional[str]:
        """Extract SMTP product name"""
        if 'Postfix' in banner:
            return 'postfix'
        elif 'Sendmail' in banner:
            return 'sendmail'
        elif 'Exim' in banner:
            return 'exim'
        return 'smtp'
    
    def _detect_database_version(self, host: str, port: int, service: str) -> Dict[str, Optional[str]]:
        """Detect database version (limited without authentication)"""
        # Database version detection typically requires authentication
        # We can only do basic banner grabbing
        return self._generic_banner_grab(host, port)
    
    def _generic_banner_grab(self, host: str, port: int) -> Dict[str, Optional[str]]:
        """Generic banner grabbing for unknown services"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))
            
            # Try to receive banner
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            if banner:
                # Try to extract version with generic pattern
                match = re.search(r'(\d+\.\d+\.\d+)', banner)
                version = match.group(1) if match else None
                
                return {
                    'version': version,
                    'banner': banner,
                    'product': None
                }
            
            return {'version': None, 'banner': None, 'product': None}
            
        except Exception as e:
            return {'version': None, 'banner': None, 'product': None}
    
    def normalize_version(self, version: str) -> str:
        """
        Normalize version string for comparison
        
        Args:
            version: Version string (e.g., "2.4.49", "8.2p1")
        
        Returns:
            Normalized version string
        """
        if not version:
            return ""
        
        # Remove common suffixes
        version = re.sub(r'[a-z]+\d*$', '', version, flags=re.IGNORECASE)
        
        # Ensure we have at least major.minor format
        parts = version.split('.')
        while len(parts) < 2:
            parts.append('0')
        
        return '.'.join(parts[:3])  # Keep only major.minor.patch


if __name__ == "__main__":
    # Test version detection
    detector = VersionDetector()
    
    # Test HTTP
    print("Testing HTTP version detection...")
    result = detector.detect_version("example.com", 80, "HTTP")
    print(f"  Version: {result['version']}")
    print(f"  Banner: {result['banner']}")
    print(f"  Product: {result['product']}")
