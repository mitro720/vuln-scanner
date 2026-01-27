"""
Payload Loader Utility
Loads custom payloads from files for vulnerability scanning
"""

import os
from typing import List, Dict, Any
import json


class PayloadLoader:
    def __init__(self, payloads_dir: str = "payloads"):
        self.payloads_dir = payloads_dir
        self.cache = {}
        
    def load_payloads(self, filename: str) -> List[str]:
        """
        Load payloads from a file
        
        Supported formats:
        - .txt: One payload per line
        - .json: JSON array of payloads
        
        Args:
            filename: Name of the payload file (e.g., 'sqli.txt', 'xss.json')
            
        Returns:
            List of payload strings
        """
        # Check cache first
        if filename in self.cache:
            return self.cache[filename]
            
        filepath = os.path.join(self.payloads_dir, filename)
        
        if not os.path.exists(filepath):
            print(f"Warning: Payload file not found: {filepath}")
            return []
            
        try:
            payloads = []
            
            # Load based on file extension
            if filename.endswith('.txt'):
                with open(filepath, 'r', encoding='utf-8') as f:
                    payloads = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                    
            elif filename.endswith('.json'):
                with open(filepath, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        payloads = data
                    elif isinstance(data, dict) and 'payloads' in data:
                        payloads = data['payloads']
                        
            # Cache the payloads
            self.cache[filename] = payloads
            
            print(f"Loaded {len(payloads)} payloads from {filename}")
            return payloads
            
        except Exception as e:
            print(f"Error loading payloads from {filename}: {str(e)}")
            return []
            
    def load_multiple(self, filenames: List[str]) -> List[str]:
        """
        Load payloads from multiple files and combine them
        
        Args:
            filenames: List of payload file names
            
        Returns:
            Combined list of all payloads
        """
        all_payloads = []
        
        for filename in filenames:
            payloads = self.load_payloads(filename)
            all_payloads.extend(payloads)
            
        return all_payloads
        
    def merge_with_defaults(self, default_payloads: List[str], custom_files: List[str] = None) -> List[str]:
        """
        Merge default payloads with custom payloads from files
        
        Args:
            default_payloads: Built-in default payloads
            custom_files: Optional list of custom payload files
            
        Returns:
            Combined list of payloads (defaults + custom)
        """
        if not custom_files:
            return default_payloads
            
        custom_payloads = self.load_multiple(custom_files)
        
        # Combine and remove duplicates while preserving order
        all_payloads = default_payloads + custom_payloads
        seen = set()
        unique_payloads = []
        
        for payload in all_payloads:
            if payload not in seen:
                seen.add(payload)
                unique_payloads.append(payload)
                
        return unique_payloads
        
    def create_payload_file(self, filename: str, payloads: List[str], description: str = ""):
        """
        Create a new payload file
        
        Args:
            filename: Name of the file to create
            payloads: List of payloads to write
            description: Optional description comment
        """
        os.makedirs(self.payloads_dir, exist_ok=True)
        filepath = os.path.join(self.payloads_dir, filename)
        
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                if description:
                    f.write(f"# {description}\n")
                    f.write(f"# Total payloads: {len(payloads)}\n\n")
                    
                for payload in payloads:
                    f.write(f"{payload}\n")
                    
            print(f"Created payload file: {filepath}")
            
        except Exception as e:
            print(f"Error creating payload file: {str(e)}")


# Global payload loader instance
payload_loader = PayloadLoader()
