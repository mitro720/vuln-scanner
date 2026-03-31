import http.server
import socketserver
import urllib.parse
import html

class VulnerableHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        
        if parsed.path == '/vuln':
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            
            # Vulnerable Reflected XSS
            q = params.get('q', [''])[0]
            # Deliberately NOT escaping q
            resp = f"<html><body>You searched for: {q}</body></html>"
            self.wfile.write(resp.encode("utf-8"))
        else:
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b'<html><body><h1>Test App</h1><a href="/vuln?q=test">Vuln</a></body></html>')

PORT = 3000
with socketserver.TCPServer(("", PORT), VulnerableHandler) as httpd:
    print(f"Serving at port {PORT}")
    httpd.serve_forever()
