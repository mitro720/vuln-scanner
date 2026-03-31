import { useState, useEffect } from 'react'
import { CheckCircle, AlertCircle, Loader, Eye, EyeOff, ExternalLink } from 'lucide-react'

const PROVIDERS = [
    { id: 'openai', label: 'OpenAI', model: 'gpt-4o-mini', needsKey: true, docs: 'https://platform.openai.com/api-keys' },
    { id: 'anthropic', label: 'Anthropic Claude', model: 'claude-3-5-haiku', needsKey: true, docs: 'https://console.anthropic.com/settings/keys' },
    { id: 'google', label: 'Google Gemini', model: 'gemini-1.5-flash', needsKey: true, docs: 'https://aistudio.google.com/apikey' },
    { id: 'ollama', label: 'Ollama (Local)', model: 'llama3.2 (self-hosted)', needsKey: false, docs: 'https://ollama.ai' },
]

const STORAGE_KEY = 'securescan_ai_settings'

const AISettings = () => {
    const [settings, setSettings] = useState({ provider: 'openai', apiKey: '', ollamaUrl: 'http://localhost:11434', model: '' })
    const [showKey, setShowKey] = useState(false)
    const [testing, setTesting] = useState(false)
    const [testResult, setTestResult] = useState(null) // null | 'ok' | 'error'
    const [testMsg, setTestMsg] = useState('')
    const [saved, setSaved] = useState(false)

    useEffect(() => {
        try {
            const stored = JSON.parse(localStorage.getItem(STORAGE_KEY) || '{}')
            if (stored.provider) setSettings(s => ({ ...s, ...stored }))
        } catch { }
    }, [])

    const save = () => {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(settings))
        setSaved(true)
        setTimeout(() => setSaved(false), 2000)
    }

    const test = async () => {
        setTesting(true)
        setTestResult(null)
        try {
            const res = await fetch('http://localhost:5000/api/ai/test', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ provider: settings.provider, apiKey: settings.apiKey }),
            })
            const data = await res.json()
            if (data.success) {
                setTestResult('ok')
                setTestMsg('Connection successful ✓')
            } else {
                setTestResult('error')
                setTestMsg(data.error || 'Connection failed')
            }
        } catch (e) {
            setTestResult('error')
            setTestMsg('Cannot reach backend server')
        } finally {
            setTesting(false)
        }
    }

    const activeProvider = PROVIDERS.find(p => p.id === settings.provider)

    return (
        <div className="bg-gray-900 rounded-xl p-8 border border-gray-800">
            <h2 className="text-2xl font-bold text-white mb-2">AI Remediation Advisor</h2>
            <p className="text-gray-400 text-sm mb-6">
                Configure your AI provider to enable vulnerability analysis, remediation suggestions, and the AI chat assistant.
            </p>

            {/* Provider selection */}
            <div className="mb-6">
                <label className="block text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">AI Provider</label>
                <div className="grid grid-cols-2 gap-3">
                    {PROVIDERS.map(p => (
                        <button key={p.id} onClick={() => setSettings({ ...settings, provider: p.id })}
                            className={`p-4 rounded-xl border-2 text-left transition-all ${settings.provider === p.id ? 'border-purple-500 bg-purple-500/10' : 'border-gray-700 hover:border-gray-600 bg-gray-800/50'}`}>
                            <div className="flex items-center justify-between">
                                <span className="font-semibold text-white text-sm">{p.label}</span>
                                {settings.provider === p.id && <div className="w-2.5 h-2.5 bg-purple-500 rounded-full" />}
                            </div>
                            <p className="text-xs text-gray-400 mt-1">{p.model}</p>
                            {!p.needsKey && <span className="text-xs text-green-400 mt-1 block">No API key required</span>}
                        </button>
                    ))}
                </div>
            </div>

            {/* API Key (shown only if needed) */}
            {activeProvider?.needsKey && (
                <div className="mb-6">
                    <div className="flex items-center justify-between mb-2">
                        <label className="text-xs font-semibold text-gray-400 uppercase tracking-wider">API Key</label>
                        <a href={activeProvider?.docs} target="_blank" rel="noopener noreferrer"
                            className="text-xs text-purple-400 hover:text-purple-300 flex items-center space-x-1">
                            <span>Get API key</span><ExternalLink size={10} />
                        </a>
                    </div>
                    <div className="relative">
                        <input
                            type={showKey ? 'text' : 'password'}
                            value={settings.apiKey}
                            onChange={e => setSettings({ ...settings, apiKey: e.target.value })}
                            placeholder="sk-…"
                            className="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-xl text-white text-sm focus:ring-1 focus:ring-purple-500 outline-none pr-12 font-mono"
                        />
                        <button onClick={() => setShowKey(!showKey)}
                            className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300">
                            {showKey ? <EyeOff size={16} /> : <Eye size={16} />}
                        </button>
                    </div>
                    <p className="text-xs text-gray-600 mt-1">Stored locally in your browser. Never sent anywhere except the AI provider API.</p>
                </div>
            )}

            {/* Ollama URL */}
            {settings.provider === 'ollama' && (
                <div className="mb-6">
                    <label className="block text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">Ollama Server URL</label>
                    <input
                        type="text"
                        value={settings.ollamaUrl}
                        onChange={e => setSettings({ ...settings, ollamaUrl: e.target.value })}
                        className="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-xl text-white text-sm focus:ring-1 focus:ring-purple-500 outline-none font-mono"
                    />
                    <p className="text-xs text-gray-500 mt-1">Default: http://localhost:11434 — make sure Ollama is running with llama3.2 pulled</p>
                </div>
            )}

            {/* Test Result */}
            {testResult && (
                <div className={`flex items-center space-x-2 p-3 rounded-lg mb-4 text-sm ${testResult === 'ok' ? 'bg-green-900/30 border border-green-700/40 text-green-300' : 'bg-red-900/30 border border-red-700/40 text-red-300'}`}>
                    {testResult === 'ok' ? <CheckCircle size={15} /> : <AlertCircle size={15} />}
                    <span>{testMsg}</span>
                </div>
            )}

            {/* Action Buttons */}
            <div className="flex space-x-3">
                <button onClick={test} disabled={testing}
                    className="flex items-center space-x-2 px-5 py-2.5 border border-gray-600 text-gray-300 rounded-xl hover:bg-gray-800 transition-colors text-sm disabled:opacity-50">
                    {testing ? <Loader size={14} className="animate-spin" /> : <CheckCircle size={14} />}
                    <span>{testing ? 'Testing…' : 'Test Connection'}</span>
                </button>
                <button onClick={save}
                    className={`px-5 py-2.5 font-semibold rounded-xl text-sm transition-all ${saved ? 'bg-green-600 text-white' : 'gradient-bg text-white hover:shadow-lg hover:shadow-purple-500/20'}`}>
                    {saved ? '✓ Saved!' : 'Save Settings'}
                </button>
            </div>
        </div>
    )
}

export default AISettings
