import React, { useState } from 'react'
import { Settings, Save, TestTube, CheckCircle, XCircle, Loader } from 'lucide-react'

const AISettings = () => {
    const [config, setConfig] = useState({
        enabled: false,
        provider: 'openai',
        apiKey: '',
        baseUrl: '',
        model: 'gpt-4'
    })

    const [testing, setTesting] = useState(false)
    const [testResult, setTestResult] = useState(null)

    const providers = [
        { id: 'openai', name: 'OpenAI (GPT-4)', requiresKey: true, defaultModel: 'gpt-4' },
        { id: 'anthropic', name: 'Anthropic (Claude)', requiresKey: true, defaultModel: 'claude-3-5-sonnet-20241022' },
        { id: 'google', name: 'Google (Gemini)', requiresKey: true, defaultModel: 'gemini-pro' },
        { id: 'ollama', name: 'Ollama (Local)', requiresKey: false, defaultModel: 'llama2' },
        { id: 'custom', name: 'Custom API', requiresKey: true, defaultModel: '' }
    ]

    const handleProviderChange = (providerId) => {
        const provider = providers.find(p => p.id === providerId)
        setConfig({
            ...config,
            provider: providerId,
            model: provider.defaultModel,
            baseUrl: providerId === 'ollama' ? 'http://localhost:11434/api/generate' : ''
        })
    }

    const testConnection = async () => {
        setTesting(true)
        setTestResult(null)

        try {
            const response = await fetch('/api/ai/test', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(config)
            })

            const result = await response.json()
            setTestResult(result)
        } catch (error) {
            setTestResult({
                success: false,
                error: error.message
            })
        } finally {
            setTesting(false)
        }
    }

    const saveSettings = async () => {
        try {
            await fetch('/api/settings/ai', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(config)
            })
            alert('AI settings saved successfully!')
        } catch (error) {
            alert('Failed to save settings: ' + error.message)
        }
    }

    const selectedProvider = providers.find(p => p.id === config.provider)

    return (
        <div className="max-w-4xl mx-auto">
            <div className="bg-white rounded-xl shadow-lg p-8">
                <div className="flex items-center mb-6">
                    <Settings className="mr-3 text-purple-600" size={28} />
                    <h2 className="text-3xl font-bold text-gray-800">AI Assistant Settings</h2>
                </div>

                <div className="space-y-6">
                    {/* Enable AI */}
                    <div className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
                        <div>
                            <h3 className="font-semibold text-gray-800">Enable AI Assistant</h3>
                            <p className="text-sm text-gray-600">Get AI-powered vulnerability analysis and remediation advice</p>
                        </div>
                        <label className="relative inline-flex items-center cursor-pointer">
                            <input
                                type="checkbox"
                                checked={config.enabled}
                                onChange={(e) => setConfig({ ...config, enabled: e.target.checked })}
                                className="sr-only peer"
                            />
                            <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-purple-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-purple-600"></div>
                        </label>
                    </div>

                    {config.enabled && (
                        <>
                            {/* Provider Selection */}
                            <div>
                                <label className="block text-sm font-semibold text-gray-700 mb-2">
                                    AI Provider
                                </label>
                                <select
                                    value={config.provider}
                                    onChange={(e) => handleProviderChange(e.target.value)}
                                    className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent"
                                >
                                    {providers.map(provider => (
                                        <option key={provider.id} value={provider.id}>
                                            {provider.name}
                                        </option>
                                    ))}
                                </select>
                                <p className="mt-2 text-xs text-gray-500">
                                    Choose your preferred AI provider. Ollama runs locally and is free.
                                </p>
                            </div>

                            {/* API Key */}
                            {selectedProvider?.requiresKey && (
                                <div>
                                    <label className="block text-sm font-semibold text-gray-700 mb-2">
                                        API Key
                                    </label>
                                    <input
                                        type="password"
                                        value={config.apiKey}
                                        onChange={(e) => setConfig({ ...config, apiKey: e.target.value })}
                                        placeholder="sk-..."
                                        className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent font-mono text-sm"
                                    />
                                    <p className="mt-2 text-xs text-gray-500">
                                        Your API key is stored securely and never shared.
                                    </p>
                                </div>
                            )}

                            {/* Model */}
                            <div>
                                <label className="block text-sm font-semibold text-gray-700 mb-2">
                                    Model
                                </label>
                                <input
                                    type="text"
                                    value={config.model}
                                    onChange={(e) => setConfig({ ...config, model: e.target.value })}
                                    placeholder="gpt-4"
                                    className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent"
                                />
                            </div>

                            {/* Custom Base URL */}
                            {(config.provider === 'custom' || config.provider === 'ollama') && (
                                <div>
                                    <label className="block text-sm font-semibold text-gray-700 mb-2">
                                        Base URL
                                    </label>
                                    <input
                                        type="text"
                                        value={config.baseUrl}
                                        onChange={(e) => setConfig({ ...config, baseUrl: e.target.value })}
                                        placeholder="http://localhost:11434/api/generate"
                                        className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent font-mono text-sm"
                                    />
                                </div>
                            )}

                            {/* Test Connection */}
                            <div className="border-t pt-6">
                                <button
                                    onClick={testConnection}
                                    disabled={testing || !config.apiKey && selectedProvider?.requiresKey}
                                    className="flex items-center space-x-2 px-6 py-3 bg-purple-100 text-purple-700 rounded-lg hover:bg-purple-200 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                                >
                                    {testing ? (
                                        <>
                                            <Loader className="animate-spin" size={18} />
                                            <span>Testing...</span>
                                        </>
                                    ) : (
                                        <>
                                            <TestTube size={18} />
                                            <span>Test Connection</span>
                                        </>
                                    )}
                                </button>

                                {testResult && (
                                    <div className={`mt-4 p-4 rounded-lg ${testResult.success ? 'bg-green-50 border border-green-200' : 'bg-red-50 border border-red-200'}`}>
                                        <div className="flex items-center space-x-2">
                                            {testResult.success ? (
                                                <>
                                                    <CheckCircle className="text-green-600" size={20} />
                                                    <span className="font-semibold text-green-800">Connection Successful!</span>
                                                </>
                                            ) : (
                                                <>
                                                    <XCircle className="text-red-600" size={20} />
                                                    <span className="font-semibold text-red-800">Connection Failed</span>
                                                </>
                                            )}
                                        </div>
                                        {testResult.error && (
                                            <p className="mt-2 text-sm text-red-700">{testResult.error}</p>
                                        )}
                                    </div>
                                )}
                            </div>

                            {/* Features Info */}
                            <div className="bg-gradient-to-r from-purple-50 to-pink-50 p-6 rounded-lg border border-purple-200">
                                <h3 className="font-semibold text-gray-800 mb-3">AI Features</h3>
                                <ul className="space-y-2 text-sm text-gray-700">
                                    <li className="flex items-start">
                                        <span className="text-purple-600 mr-2">✓</span>
                                        <span>Plain English vulnerability explanations</span>
                                    </li>
                                    <li className="flex items-start">
                                        <span className="text-purple-600 mr-2">✓</span>
                                        <span>Custom remediation advice based on your tech stack</span>
                                    </li>
                                    <li className="flex items-start">
                                        <span className="text-purple-600 mr-2">✓</span>
                                        <span>Personalized learning recommendations</span>
                                    </li>
                                    <li className="flex items-start">
                                        <span className="text-purple-600 mr-2">✓</span>
                                        <span>Risk assessment and exploitation scenarios</span>
                                    </li>
                                    <li className="flex items-start">
                                        <span className="text-purple-600 mr-2">✓</span>
                                        <span>Code fix suggestions with examples</span>
                                    </li>
                                </ul>
                            </div>
                        </>
                    )}

                    {/* Save Button */}
                    <div className="flex justify-end pt-6 border-t">
                        <button
                            onClick={saveSettings}
                            className="flex items-center space-x-2 px-6 py-3 gradient-bg text-white rounded-lg hover:shadow-lg transition-all"
                        >
                            <Save size={18} />
                            <span>Save Settings</span>
                        </button>
                    </div>
                </div>
            </div>
        </div>
    )
}

export default AISettings
