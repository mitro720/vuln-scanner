import sys
import os

# Add the project's scanner-core to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'scanner-core'))

from owasp.a03_xss import XSSModule

def test():
    print("Initializing XSS Module...")
    module = XSSModule("http://localhost:3000")
    print("Running scan on vulnerable endpoint...")
    findings = module.scan(["http://localhost:3000/vuln?q=test"])
    
    print(f"Found {len(findings)} findings.")
    for f in findings:
        print(f.get('name', 'Unknown'))
        print(f.get('evidence', {}))

if __name__ == "__main__":
    test()
