"""
Authentication Handler
Manages valid sessions, cookies, and login sequences.
"""

import requests
import json
from typing import Dict, Any, Optional

class AuthHandler:
    def __init__(self):
        self.session = requests.Session()
        self.headers = {}
        self.cookies = {}
        
    def set_auth_token(self, token: str, token_type: str = "Bearer"):
        """Set Authorization header manually"""
        self.headers["Authorization"] = f"{token_type} {token}"
        self.session.headers.update(self.headers)
        
    def set_cookies(self, cookies: Dict[str, str]):
        """Set session cookies manually"""
        self.cookies = cookies
        self.session.cookies.update(cookies)
        
    def login(self, login_url: str, username: str, password: str, user_field: str = "username", pass_field: str = "password", token_key: str = None) -> bool:
        """
        Attempt to login and capture session
        
        Args:
            login_url: URL to POST credentials to
            username: The username/email value
            password: The password value
            user_field: The form field name for username (e.g., 'email', 'login')
            pass_field: The form field name for password (e.g., 'password', 'pwd')
            token_key: Optional JSON key to extract token from response (e.g., 'access_token')
        """
        try:
            # Construct the payload dynamically
            credentials = {
                user_field: username,
                pass_field: password
            }
            
            # Use JSON by default, fallback to form-encoding if needed (future improvement)
            response = self.session.post(login_url, json=credentials, timeout=10)
            
            if response.status_code == 200 or response.status_code == 302:
                # 1. Check for token in response body
                if token_key:
                    try:
                        data = response.json()
                        token = data.get(token_key)
                        if token:
                            self.set_auth_token(token)
                            return True
                    except:
                        pass
                        
                # 2. Check for Cookies (handled automatically by session, or captured manually)
                if self.session.cookies or response.cookies:
                    self.cookies = self.session.cookies.get_dict()
                    return True
                    
            return False
        except Exception as e:
            print(f"Login failed: {e}")
            return False
            
    def get_authenticated_session(self) -> requests.Session:
        """Get the configured session object"""
        return self.session

    def verify_session(self, verify_url: str) -> bool:
        """Check if current session is valid by hitting a protected endpoint"""
        try:
            response = self.session.get(verify_url, timeout=5)
            # 200 OK usually means authorized, 401/403 means failed
            return response.status_code == 200
        except:
            return False
