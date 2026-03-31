const express = require('express');
const app = express();
const PORT = 3005;

// Basic Homepage
app.get('/', (req, res) => {
    res.send(`
        <html>
            <body>
                <h1>Vulnerable Test App (Target)</h1>
                <ul>
                    <li><a href="/vuln?q=test">Reflected XSS</a></li>
                    <li><a href="/api/user?id=1">SQL Injection (Simulated)</a></li>
                    <li><a href="/api/fetch?url=https://google.com">SSRF Endpoint</a></li>
                    <li><a href="/hello?name=User">SSTI (Simulated)</a></li>
                    <li><a href="/admin">Hidden Admin Panel</a></li>
                </ul>
            </body>
        </html>
    `);
});

// 1. Reflected XSS (Classic)
app.get('/vuln', (req, res) => {
    const q = req.query.q || '';
    // DELIBERATELY VULNERABLE: No sanitization
    res.send(`<html><body><h1>Search Results</h1><p>You searched for: ${q}</p></body></html>`);
});

// 2. SQL Injection (Simulated)
app.get('/api/user', (req, res) => {
    const id = req.query.id || '';
    
    // Simulate Time-based Blind SQLi
    if (id.includes('SLEEP(') || id.includes('pg_sleep(') || id.includes('WAITFOR DELAY')) {
        console.log(`[!] SQLi Time-based payload detected: ${id}`);
        setTimeout(() => {
            res.json({ id: 1, username: 'admin', note: 'Injected!' });
        }, 5000);
        return;
    }
    
    // Simulate Error-based SQLi
    if (id.includes("'")) {
        res.status(500).send("SQL State: 42601. Error: syntax error at or near \"'\"");
        return;
    }
    
    res.json({ id: 1, username: 'admin' });
});

// 3. SSRF (Server-Side Request Forgery)
app.get('/api/fetch', (req, res) => {
    const targetUrl = req.query.url || '';
    
    if (!targetUrl) return res.status(400).send("Missing URL");

    console.log(`[!] SSRF Attempt: ${targetUrl}`);
    
    // Simulate Cloud Metadata Leak
    if (targetUrl.includes('169.254.169.254')) {
        return res.send("ami-id: ami-12345678\ninstance-id: i-0abcdef1234567890\nlocal-hostname: ip-10-0-0-1.ec2.internal");
    }
    
    // Simulate Internal Service Leak
    if (targetUrl.includes('localhost') || targetUrl.includes('127.0.0.1')) {
        return res.send("<h1>Internal Service</h1><p>Welcome to the private dashboard.</p>");
    }

    res.send(`[Proxy Content from ${targetUrl}] Mocked content...`);
});

// 4. SSTI (Server-Side Template Injection)
app.get('/hello', (req, res) => {
    const name = req.query.name || '';
    
    // Detect basic mathematical expressions used to test SSTI (e.g., {{7*7}} or ${7*7})
    if (name.includes('{{') && name.includes('7*7')) {
        return res.send(`Hello 49`);
    }
    
    res.send(`Hello ${name}`);
});

// 5. Sensitive File Exposures
app.get('/.env', (req, res) => {
    res.send("DB_PASSWORD=supersecret\nAWS_SECRET_KEY=AKIA_MOCKED_KEY\nJWT_SECRET=shhhh_its_a_secret");
});

app.get('/.git/config', (req, res) => {
    res.send("[core]\n\trepositoryformatversion = 0\n\tfilemode = false\n\tbare = false\n[remote \"origin\"]\n\turl = https://github.com/org/private-repo.git");
});

// 6. CORS Misconfiguration
app.get('/api/data', (req, res) => {
    res.header("Access-Control-Allow-Origin", "*"); // Insecure wildcard
    res.header("Access-Control-Allow-Credentials", "true");
    res.json({ sensitive_data: "This is cross-origin accessible!" });
});

// 7. Hidden Admin (for discovery testing)
app.get('/admin', (req, res) => {
    res.send("<h1>Admin Panel</h1><p>Only for internal use.</p>");
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`
🚀 Vulnerable Test App LIVE
   URL: http://localhost:${PORT}
   
   Endpoints:
   - XSS: /vuln?q=<script>alert(1)</script>
   - SQLi: /api/user?id=1' OR 1=1--
   - SSRF: /api/fetch?url=http://169.254.169.254/latest/meta-data/
   - SSTI: /hello?name={{7*7}}
   - Sensitive: /.env, /.git/config
    `);
});
