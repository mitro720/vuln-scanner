"""
Web Crawler for attack surface discovery
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from typing import Set, List, Dict, Any


class WebCrawler:
    def __init__(self, base_url: str, max_depth: int = 3):
        self.base_url = base_url
        self.max_depth = max_depth
        self.visited_urls = set()
        self.discovered_urls = set()
        self.forms = []
        self.parsed_base = urlparse(base_url)
        
    def is_valid_url(self, url: str) -> bool:
        """Check if URL belongs to target domain"""
        parsed = urlparse(url)
        return parsed.netloc == self.parsed_base.netloc
        
    def extract_links(self, html: str, current_url: str) -> Set[str]:
        """Extract all links from HTML"""
        soup = BeautifulSoup(html, 'html.parser')
        links = set()
        
        for tag in soup.find_all('a', href=True):
            url = urljoin(current_url, tag['href'])
            # Remove fragments
            url = url.split('#')[0]
            if self.is_valid_url(url):
                links.add(url)
                
        return links
        
    def extract_forms(self, html: str, current_url: str) -> List[Dict[str, Any]]:
        """Extract all forms from HTML"""
        soup = BeautifulSoup(html, 'html.parser')
        forms = []
        
        for form in soup.find_all('form'):
            form_data = {
                'url': current_url,
                'action': urljoin(current_url, form.get('action', '')),
                'method': form.get('method', 'get').upper(),
                'inputs': []
            }
            
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                form_data['inputs'].append({
                    'name': input_tag.get('name'),
                    'type': input_tag.get('type', 'text'),
                    'value': input_tag.get('value', '')
                })
                
            forms.append(form_data)
            
        return forms
        
    def crawl(self, url: str = None, depth: int = 0) -> Dict[str, Any]:
        """Crawl website starting from URL"""
        if url is None:
            url = self.base_url
            
        if depth > self.max_depth or url in self.visited_urls:
            return {
                "urls": list(self.discovered_urls),
                "forms": self.forms
            }
            
        self.visited_urls.add(url)
        self.discovered_urls.add(url)
        
        try:
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200 and 'text/html' in response.headers.get('Content-Type', ''):
                # Extract links
                links = self.extract_links(response.text, url)
                
                # Extract forms
                forms = self.extract_forms(response.text, url)
                self.forms.extend(forms)
                
                # Recursively crawl discovered links
                for link in links:
                    if link not in self.visited_urls:
                        self.crawl(link, depth + 1)
                        
        except Exception as e:
            print(f"Error crawling {url}: {str(e)}")
            
        return {
            "urls": list(self.discovered_urls),
            "forms": self.forms
        }
