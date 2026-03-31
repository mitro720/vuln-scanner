/**
 * AI Controller — vulnerability analysis & remediation advisor
 * Proxies requests to the Python AI assistant or an AI provider directly
 */
import { AppError } from '../middleware/errorHandler.js'
import supabase from '../config/supabase.js'

const AI_PROVIDER = process.env.AI_PROVIDER || 'openai'
const AI_API_KEY = process.env.AI_API_KEY || ''
const OLLAMA_URL = process.env.OLLAMA_URL || 'http://localhost:11434'

/* ── Shared system prompt ─────────────────────────────────────────────── */
const SYSTEM_PROMPT = `You are SecureScan AI, an expert cybersecurity assistant specializing in vulnerability analysis and remediation. You help security professionals understand and fix the vulnerabilities found by the SecureScan vulnerability scanner. 

When given a finding, provide:
- Clear plain-English explanation
- Business impact assessment 
- Specific, actionable remediation steps with code examples where helpful
- References to OWASP, CWE, or related CVEs

Always be concise, technical, and accurate. Format responses with markdown.`

/* ── Provider dispatchers ─────────────────────────────────────────────── */
async function callOpenAI(messages, apiKey) {
    const res = await fetch('https://api.openai.com/v1/chat/completions', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ model: 'gpt-4o-mini', messages, temperature: 0.4 }),
    })
    if (!res.ok) throw new Error(`OpenAI error: ${res.status}`)
    const d = await res.json()
    return d.choices[0].message.content
}

async function callAnthropic(messages, apiKey) {
    const system = messages.find(m => m.role === 'system')?.content || SYSTEM_PROMPT
    const userMessages = messages.filter(m => m.role !== 'system')
    const res = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: { 'x-api-key': apiKey, 'anthropic-version': '2023-06-01', 'Content-Type': 'application/json' },
        body: JSON.stringify({ model: 'claude-3-5-haiku-20241022', max_tokens: 1024, system, messages: userMessages }),
    })
    if (!res.ok) throw new Error(`Anthropic error: ${res.status}`)
    const d = await res.json()
    return d.content[0].text
}

async function callGoogle(messages, apiKey) {
    const prompt = messages.map(m => `${m.role}: ${m.content}`).join('\n')
    const res = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${apiKey}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ contents: [{ parts: [{ text: prompt }] }] }),
    })
    if (!res.ok) throw new Error(`Google error: ${res.status}`)
    const d = await res.json()
    return d.candidates[0].content.parts[0].text
}

async function callOllama(messages) {
    const prompt = messages.map(m => `${m.role}: ${m.content}`).join('\n\n')
    const res = await fetch(`${OLLAMA_URL}/api/generate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ model: process.env.OLLAMA_MODEL || 'llama3.2', prompt, stream: false }),
    })
    if (!res.ok) throw new Error(`Ollama error: ${res.status}`)
    const d = await res.json()
    return d.response
}

async function callGroq(messages, apiKey) {
    const res = await fetch('https://api.groq.com/openai/v1/chat/completions', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ model: 'llama-3.3-70b-versatile', messages, temperature: 0.4 }),
    })
    if (!res.ok) throw new Error(`Groq error: ${res.status}`)
    const d = await res.json()
    return d.choices[0].message.content
}

async function dispatchAI(messages, provider, apiKey) {
    switch ((provider || AI_PROVIDER).toLowerCase()) {
        case 'openai': return callOpenAI(messages, apiKey || AI_API_KEY)
        case 'anthropic': return callAnthropic(messages, apiKey || AI_API_KEY)
        case 'google': return callGoogle(messages, apiKey || AI_API_KEY)
        case 'ollama': return callOllama(messages)
        case 'groq': return callGroq(messages, apiKey || AI_API_KEY)
        default: throw new Error(`Unknown AI provider: ${provider}`)
    }
}

/* ── Build finding context string ─────────────────────────────────────── */
function findingContext(finding) {
    return `
**Vulnerability:** ${finding.name || 'Unknown'}
**Severity:** ${finding.severity || 'N/A'}
**CVSS Score:** ${finding.cvss_score || 'N/A'}
**OWASP Category:** ${finding.owasp || 'N/A'}
**CWE:** ${finding.cwe || 'N/A'}
**Affected URL:** ${finding.url || 'N/A'}
**Description:** ${finding.description || 'N/A'}
**Evidence:** ${typeof finding.evidence === 'object' ? JSON.stringify(finding.evidence) : (finding.evidence || 'N/A')}
`.trim()
}

/* ── Controllers ─────────────────────────────────────────────────────── */

// POST /api/ai/chat — general chat with optional finding context
export const aiChat = async (req, res, next) => {
    try {
        const { messages, findingId, provider, apiKey } = req.body

        if (!messages?.length) throw new AppError('Messages required', 400)

        let enrichedSystem = SYSTEM_PROMPT

        // If a findingId is provided, inject its context into the system prompt
        if (findingId) {
            const { data: finding } = await supabase
                .from('findings').select('*').eq('id', findingId).single()
            if (finding) {
                enrichedSystem += `\n\n## Current Finding Context\n${findingContext(finding)}`
            }
        }

        const fullMessages = [
            { role: 'system', content: enrichedSystem },
            ...messages,
        ]

        const reply = await dispatchAI(fullMessages, provider, apiKey)

        res.json({ success: true, data: { reply } })
    } catch (err) {
        next(err)
    }
}

// POST /api/ai/analyze — deep analysis of a single finding
export const analyzeFinding = async (req, res, next) => {
    try {
        const { findingId, finding: inlineFinding, provider, apiKey } = req.body

        let finding = inlineFinding
        if (!finding && findingId) {
            const { data } = await supabase.from('findings').select('*').eq('id', findingId).single()
            finding = data
        }
        if (!finding) throw new AppError('Finding required', 400)

        const messages = [
            { role: 'system', content: SYSTEM_PROMPT },
            {
                role: 'user',
                content: `Analyze this vulnerability and provide:
1. Plain-English explanation (2-3 sentences)
2. Business impact & risk assessment
3. How an attacker could exploit this (attack scenario)
4. Remediation priority (Critical / High / Medium / Low) with reasoning

${findingContext(finding)}

Format your response in clear markdown sections.`,
            },
        ]

        const reply = await dispatchAI(messages, provider, apiKey)
        res.json({ success: true, data: { analysis: reply } })
    } catch (err) {
        next(err)
    }
}

// POST /api/ai/remediate — specific code/config fix for a finding
export const remediateFinding = async (req, res, next) => {
    try {
        const { findingId, finding: inlineFinding, techStack, provider, apiKey } = req.body

        let finding = inlineFinding
        if (!finding && findingId) {
            const { data } = await supabase.from('findings').select('*').eq('id', findingId).single()
            finding = data
        }
        if (!finding) throw new AppError('Finding required', 400)

        const techInfo = techStack?.length ? `\n**Tech Stack:** ${techStack.join(', ')}` : ''

        const messages = [
            { role: 'system', content: SYSTEM_PROMPT },
            {
                role: 'user',
                content: `Provide specific remediation guidance for this vulnerability.
${findingContext(finding)}${techInfo}

Provide:
1. **Quick Fix** — immediate mitigation steps
2. **Code Example** — code snippet showing the fix (language-appropriate)
3. **Configuration Changes** — any config/header/setting updates needed
4. **Verification Steps** — how to confirm the fix works
5. **Prevention** — best practices to prevent this class of vulnerability

Be specific and actionable.`,
            },
        ]

        const reply = await dispatchAI(messages, provider, apiKey)
        res.json({ success: true, data: { remediation: reply } })
    } catch (err) {
        next(err)
    }
}

// POST /api/ai/summary — generate executive summary for an entire scan
export const generateScanSummary = async (req, res, next) => {
    try {
        const { scanId, provider, apiKey } = req.body

        if (!scanId) throw new AppError('Scan ID required', 400)

        // Fetch scan and findings
        const { data: scan } = await supabase.from('scans').select('*').eq('id', scanId).single()
        const { data: findings } = await supabase.from('findings').select('*').eq('scan_id', scanId)

        if (!scan) throw new AppError('Scan not found', 400)

        const findingsSummary = findings.map(f => `- ${f.name} (${f.severity}): ${f.url}`).join('\n')

        const messages = [
            { role: 'system', content: SYSTEM_PROMPT },
            {
                role: 'user',
                content: `Generate an executive summary for a security scan of ${scan.target_url}.
                
**Scan Type:** ${scan.scan_type}
**Findings Count:** ${findings.length}
**Target:** ${scan.target_url}

**Findings List:**
${findingsSummary}

Please provide:
1. **Executive Overview** — High-level summary of the security posture.
2. **Key Risks** — The most critical issues discovered.
3. **Strategic Recommendations** — Long-term improvements.
4. **Conclusion** — Overall assessment.

Format with clear markdown headers.`,
            },
        ]

        const reply = await dispatchAI(messages, provider, apiKey)
        res.json({ success: true, data: { summary: reply } })
    } catch (err) {
        next(err)
    }
}

// POST /api/ai/test — test provider connection
export const testConnection = async (req, res, next) => {
    try {
        const { provider, apiKey } = req.body
        const messages = [
            { role: 'system', content: 'You are a helpful assistant.' },
            { role: 'user', content: 'Reply with exactly: {"status":"ok"}' },
        ]
        const reply = await dispatchAI(messages, provider, apiKey)
        res.json({ success: true, data: { provider, reply } })
    } catch (err) {
        res.status(400).json({ success: false, error: err.message })
    }
}
