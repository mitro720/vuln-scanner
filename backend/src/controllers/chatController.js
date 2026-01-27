// Basic AI Logic Controller
// In a real production environment, you would call OpenAI/Anthropic/Gemini APIs here.
// For now, we simulate an intelligent security expert agent.

export const chatWithAI = async (req, res, next) => {
    try {
        const { message, history } = req.body
        const userQuery = message.toLowerCase()

        // Mock Intelligent Response Logic
        let reply = "I'm not sure about that specific detail yet, but I can help you interpret scan results or explain vulnerability types."

        if (userQuery.includes('sql') || userQuery.includes('injection')) {
            reply = "SQL Injection (SQLi) is a critical vulnerability where attackers can interfere with detailed database queries. To fix this, you should use **Parameterized Queries** or **Prepared Statements** instead of concatenating user input directly into SQL strings."
        } else if (userQuery.includes('xss') || userQuery.includes('scripting')) {
            reply = "Cross-Site Scripting (XSS) allows attackers to inject malicious scripts into web pages viewed by other users. \n\n**Remediation:**\n1. Output Encoding (convert special chars to HTML entities)\n2. Implement Content Security Policy (CSP)\n3. Validate all input on arrival."
        } else if (userQuery.includes('hello') || userQuery.includes('hi')) {
            reply = "Hello! I'm ready to help you secure your application. Do you have a specific finding you want me to analyze?"
        } else if (userQuery.includes('report') || userQuery.includes('pdf')) {
            reply = "You can generate professional PDF reports from the 'Results' page after a scan completes. The report includes an executive summary and detailed remediation steps for your team."
        } else if (userQuery.includes('critical') || userQuery.includes('high')) {
            reply = "Critical findings should be addressed immediately as they likely allow for remote code execution or data exfiltration. High severity issues often lead to significant access or data loss and should be prioritized next."
        } else if (userQuery.includes('scan') && userQuery.includes('start')) {
            reply = "To start a new scan, click the **'New Scan'** button in the sidebar. You can choose a Quick Scan for speed or a Full Scan for comprehensive coverage including all OWASP checks."
        }

        // Simulate network delay for "thinking"
        setTimeout(() => {
            res.json({
                success: true,
                reply: reply
            })
        }, 1000)

    } catch (error) {
        next(error)
    }
}
