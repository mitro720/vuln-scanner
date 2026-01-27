import React, { useState } from 'react'
import { Book, Code, Shield, ExternalLink, ChevronDown, ChevronUp } from 'lucide-react'

const KnowledgeBase = () => {
    const [selectedVuln, setSelectedVuln] = useState(null)
    const [expandedSections, setExpandedSections] = useState({})

    const vulnerabilities = [
        {
            id: 'sql_injection',
            name: 'SQL Injection',
            category: 'Injection',
            difficulty: 'Medium',
            cvss: 9.8,
            cwe: 'CWE-89',
        },
        {
            id: 'xss',
            name: 'Cross-Site Scripting (XSS)',
            category: 'Injection',
            difficulty: 'Easy to Medium',
            cvss: 6.1,
            cwe: 'CWE-79',
        },
        {
            id: 'command_injection',
            name: 'OS Command Injection',
            category: 'Injection',
            difficulty: 'Medium',
            cvss: 9.8,
            cwe: 'CWE-78',
        },
        {
            id: 'xxe',
            name: 'XML External Entity (XXE)',
            category: 'Injection',
            difficulty: 'Medium to Hard',
            cvss: 8.2,
            cwe: 'CWE-611',
        },
    ]

    const toggleSection = (section) => {
        setExpandedSections(prev => ({
            ...prev,
            [section]: !prev[section]
        }))
    }

    const getDifficultyColor = (difficulty) => {
        if (difficulty.includes('Easy')) return 'text-green-600 bg-green-100'
        if (difficulty.includes('Medium')) return 'text-yellow-600 bg-yellow-100'
        return 'text-red-600 bg-red-100'
    }

    return (
        <div className="max-w-7xl mx-auto px-4">
            <div className="mb-8">
                <h1 className="text-4xl font-bold text-gradient mb-2">Knowledge Base</h1>
                <p className="text-gray-600">Learn about web vulnerabilities, detection techniques, and prevention methods</p>
            </div>

            <div className="grid grid-cols-3 gap-6">
                {/* Vulnerability List */}
                <div className="col-span-1">
                    <div className="bg-white rounded-xl shadow-lg p-6">
                        <h2 className="text-xl font-bold text-gray-800 mb-4 flex items-center">
                            <Book className="mr-2" size={20} />
                            Vulnerabilities
                        </h2>
                        <div className="space-y-2">
                            {vulnerabilities.map((vuln) => (
                                <div
                                    key={vuln.id}
                                    onClick={() => setSelectedVuln(vuln)}
                                    className={`p-4 rounded-lg cursor-pointer transition-all hover:shadow-md ${selectedVuln?.id === vuln.id
                                        ? 'bg-gradient-to-r from-purple-50 to-pink-50 ring-2 ring-purple-500'
                                        : 'bg-gray-50 hover:bg-gray-100'
                                        }`}
                                >
                                    <h3 className="font-semibold text-gray-800">{vuln.name}</h3>
                                    <div className="flex items-center justify-between mt-2">
                                        <span className={`text-xs px-2 py-1 rounded-full ${getDifficultyColor(vuln.difficulty)}`}>
                                            {vuln.difficulty}
                                        </span>
                                        <span className="text-xs text-gray-500">{vuln.cwe}</span>
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>
                </div>

                {/* Vulnerability Details */}
                <div className="col-span-2">
                    {selectedVuln ? (
                        <div className="bg-white rounded-xl shadow-lg p-8 space-y-6">
                            <div>
                                <h2 className="text-3xl font-bold text-gray-800 mb-2">{selectedVuln.name}</h2>
                                <div className="flex items-center space-x-4">
                                    <span className="text-sm text-gray-600">{selectedVuln.category}</span>
                                    <span className={`text-xs px-3 py-1 rounded-full ${getDifficultyColor(selectedVuln.difficulty)}`}>
                                        {selectedVuln.difficulty}
                                    </span>
                                    <span className="text-sm font-semibold text-purple-600">CVSS: {selectedVuln.cvss}</span>
                                </div>
                            </div>

                            {/* Description */}
                            <div className="bg-gradient-to-r from-blue-50 to-indigo-50 p-4 rounded-lg border border-blue-200">
                                <h3 className="font-semibold text-gray-800 mb-2 flex items-center">
                                    <Shield className="mr-2" size={18} />
                                    What is it?
                                </h3>
                                <p className="text-gray-700 text-sm leading-relaxed">
                                    {selectedVuln.id === 'sql_injection' && "SQL Injection is a code injection technique that exploits security vulnerabilities in an application's database layer. Attackers can insert malicious SQL statements into entry fields for execution."}
                                    {selectedVuln.id === 'xss' && "Cross-Site Scripting (XSS) allows attackers to inject malicious scripts into web pages viewed by other users. These scripts can steal cookies, session tokens, or other sensitive information."}
                                    {selectedVuln.id === 'command_injection' && "Command Injection allows attackers to execute arbitrary operating system commands on the server. This can lead to complete system compromise, data theft, or denial of service."}
                                    {selectedVuln.id === 'xxe' && "XXE attacks exploit vulnerable XML parsers to access local files, perform SSRF attacks, or cause denial of service."}
                                </p>
                            </div>

                            {/* How it Works */}
                            <div>
                                <button
                                    onClick={() => toggleSection('how_it_works')}
                                    className="w-full flex items-center justify-between p-4 bg-gray-50 rounded-lg hover:bg-gray-100 transition-colors"
                                >
                                    <h3 className="font-semibold text-gray-800">How It Works</h3>
                                    {expandedSections['how_it_works'] ? <ChevronUp size={20} /> : <ChevronDown size={20} />}
                                </button>
                                {expandedSections['how_it_works'] && (
                                    <div className="mt-4 p-4 bg-gray-50 rounded-lg">
                                        <ol className="list-decimal list-inside space-y-2 text-sm text-gray-700">
                                            <li>User input is accepted without proper validation</li>
                                            <li>Malicious payload is injected through input fields</li>
                                            <li>Application processes the malicious input</li>
                                            <li>Attacker gains unauthorized access or executes commands</li>
                                        </ol>
                                    </div>
                                )}
                            </div>

                            {/* Code Examples */}
                            <div>
                                <button
                                    onClick={() => toggleSection('code_examples')}
                                    className="w-full flex items-center justify-between p-4 bg-gray-50 rounded-lg hover:bg-gray-100 transition-colors"
                                >
                                    <h3 className="font-semibold text-gray-800 flex items-center">
                                        <Code className="mr-2" size={18} />
                                        Code Examples
                                    </h3>
                                    {expandedSections['code_examples'] ? <ChevronUp size={20} /> : <ChevronDown size={20} />}
                                </button>
                                {expandedSections['code_examples'] && (
                                    <div className="mt-4 space-y-4">
                                        <div>
                                            <h4 className="text-sm font-semibold text-red-600 mb-2">❌ Vulnerable Code</h4>
                                            <pre className="bg-gray-900 text-red-400 p-4 rounded-lg text-xs overflow-x-auto">
                                                {selectedVuln.id === 'sql_injection' && `# Python - VULNERABLE
username = request.GET['username']
query = f"SELECT * FROM users WHERE username = '{username}'"
cursor.execute(query)`}
                                                {selectedVuln.id === 'xss' && `// JavaScript - VULNERABLE
const username = req.query.username;
res.send(\`<h1>Welcome \${username}</h1>\`);`}
                                            </pre>
                                        </div>
                                        <div>
                                            <h4 className="text-sm font-semibold text-green-600 mb-2">✅ Secure Code</h4>
                                            <pre className="bg-gray-900 text-green-400 p-4 rounded-lg text-xs overflow-x-auto">
                                                {selectedVuln.id === 'sql_injection' && `# Python - SECURE
username = request.GET['username']
query = "SELECT * FROM users WHERE username = %s"
cursor.execute(query, (username,))`}
                                                {selectedVuln.id === 'xss' && `// JavaScript - SECURE
const username = req.query.username;
const escaped = escapeHtml(username);
res.send(\`<h1>Welcome \${escaped}</h1>\`);`}
                                            </pre>
                                        </div>
                                    </div>
                                )}
                            </div>

                            {/* Prevention */}
                            <div>
                                <h3 className="font-semibold text-gray-800 mb-3">Prevention Methods</h3>
                                <ul className="space-y-2">
                                    {selectedVuln.id === 'sql_injection' && (
                                        <>
                                            <li className="flex items-start">
                                                <span className="text-green-500 mr-2">✓</span>
                                                <span className="text-sm text-gray-700">Use parameterized queries (prepared statements)</span>
                                            </li>
                                            <li className="flex items-start">
                                                <span className="text-green-500 mr-2">✓</span>
                                                <span className="text-sm text-gray-700">Employ ORM frameworks with built-in protection</span>
                                            </li>
                                            <li className="flex items-start">
                                                <span className="text-green-500 mr-2">✓</span>
                                                <span className="text-sm text-gray-700">Validate and sanitize all user inputs</span>
                                            </li>
                                        </>
                                    )}
                                    {selectedVuln.id === 'xss' && (
                                        <>
                                            <li className="flex items-start">
                                                <span className="text-green-500 mr-2">✓</span>
                                                <span className="text-sm text-gray-700">Encode all output data (HTML, JavaScript, URL)</span>
                                            </li>
                                            <li className="flex items-start">
                                                <span className="text-green-500 mr-2">✓</span>
                                                <span className="text-sm text-gray-700">Use Content Security Policy (CSP)</span>
                                            </li>
                                            <li className="flex items-start">
                                                <span className="text-green-500 mr-2">✓</span>
                                                <span className="text-sm text-gray-700">Use modern frameworks with auto-escaping</span>
                                            </li>
                                        </>
                                    )}
                                </ul>
                            </div>

                            {/* Learning Resources */}
                            <div>
                                <h3 className="font-semibold text-gray-800 mb-3">Learning Resources</h3>
                                <div className="space-y-2">
                                    <a
                                        href="https://portswigger.net/web-security"
                                        target="_blank"
                                        rel="noopener noreferrer"
                                        className="flex items-center justify-between p-3 bg-purple-50 rounded-lg hover:bg-purple-100 transition-colors"
                                    >
                                        <div>
                                            <p className="font-medium text-gray-800">PortSwigger Web Security Academy</p>
                                            <p className="text-xs text-gray-600">Free interactive tutorials</p>
                                        </div>
                                        <ExternalLink size={16} className="text-purple-600" />
                                    </a>
                                    <a
                                        href="https://owasp.org"
                                        target="_blank"
                                        rel="noopener noreferrer"
                                        className="flex items-center justify-between p-3 bg-purple-50 rounded-lg hover:bg-purple-100 transition-colors"
                                    >
                                        <div>
                                            <p className="font-medium text-gray-800">OWASP Documentation</p>
                                            <p className="text-xs text-gray-600">Comprehensive security guides</p>
                                        </div>
                                        <ExternalLink size={16} className="text-purple-600" />
                                    </a>
                                    <a
                                        href="https://www.hackthebox.com"
                                        target="_blank"
                                        rel="noopener noreferrer"
                                        className="flex items-center justify-between p-3 bg-purple-50 rounded-lg hover:bg-purple-100 transition-colors"
                                    >
                                        <div>
                                            <p className="font-medium text-gray-800">HackTheBox</p>
                                            <p className="text-xs text-gray-600">Practice labs and CTF challenges</p>
                                        </div>
                                        <ExternalLink size={16} className="text-purple-600" />
                                    </a>
                                </div>
                            </div>
                        </div>
                    ) : (
                        <div className="bg-white rounded-xl shadow-lg p-8 flex items-center justify-center h-full min-h-[600px]">
                            <div className="text-center text-gray-400">
                                <Book size={64} className="mx-auto mb-4" />
                                <p className="text-lg">Select a vulnerability to learn more</p>
                            </div>
                        </div>
                    )}
                </div>
            </div>
        </div>
    )
}

export default KnowledgeBase
