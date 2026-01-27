"""
Target validation and configuration
"""

from urllib.parse import urlparse
from typing import Dict, Any


class Target:
    def __init__(self, url: str):
        self.url = url
        self.parsed = urlparse(url)
        self.hostname = self.parsed.hostname
        self.scheme = self.parsed.scheme
        self.port = self.parsed.port or (443 if self.scheme == 'https' else 80)
        self.path = self.parsed.path or '/'
        
    def validate(self) -> bool:
        """Validate target URL"""
        if not self.scheme in ['http', 'https']:
            raise ValueError("Invalid URL scheme. Must be http or https")
            
        if not self.hostname:
            raise ValueError("Invalid hostname")
            
        return True
        
    def get_base_url(self) -> str:
        """Get base URL"""
        return f"{self.scheme}://{self.hostname}:{self.port}"
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "url": self.url,
            "hostname": self.hostname,
            "scheme": self.scheme,
            "port": self.port,
            "path": self.path
        }
