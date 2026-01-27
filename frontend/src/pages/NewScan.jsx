import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Zap, Search, Settings as SettingsIcon } from 'lucide-react'

const NewScan = () => {
    const navigate = useNavigate()
    const [scanType, setScanType] = useState('full')
    const [targetUrl, setTargetUrl] = useState('')
    const [loading, setLoading] = useState(false)
    const [options, setOptions] = useState({
        subdomain: true,
        api: true,
        owasp: true,
        auth: false,
        waf: true,
        tech: true,
    })

    const handleStartScan = async () => {
        if (!targetUrl) return

        setLoading(true)
        try {
            const response = await fetch('http://localhost:5000/api/scans', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    target_url: targetUrl,
                    scan_type: scanType,
                    config: options
                })
            })

            if (response.ok) {
                const data = await response.json()
                // Navigate to live scan page with real scan ID
                navigate(`/scan/${data.data.id}`)
            } else {
                alert('Failed to start scan. Please check your target URL.')
            }
        } catch (error) {
            console.error('Error starting scan:', error)
            alert('Failed to connect to backend. Make sure the server is running.')
        } finally {
            setLoading(false)
        }
    }

    const scanTypes = [
        {
            id: 'quick',
            name: 'Quick Scan',
            icon: Zap,
            duration: '~5-10 minutes',
            description: 'Fast scan with high-confidence checks only',
        },
        {
            id: 'full',
            name: 'Full Scan',
            icon: Search,
            duration: '~30-60 minutes',
            description: 'Comprehensive scan with all OWASP modules',
        },
        {
            id: 'custom',
            name: 'Custom',
            icon: SettingsIcon,
            duration: 'Variable',
            description: 'Configure your own scan parameters',
        },
    ]

    const scanOptions = [
        { key: 'subdomain', label: 'Subdomain Discovery', icon: '🌐', description: 'Find subdomains' },
        { key: 'api', label: 'API Discovery', icon: '🔌', description: 'Detect API endpoints' },
        { key: 'owasp', label: 'OWASP Top 10', icon: '🛡️', description: 'All vulnerability checks' },
        { key: 'auth', label: 'Authenticated Scan', icon: '🔐', description: 'Scan behind login' },
        { key: 'waf', label: 'WAF Detection', icon: '🚧', description: 'Detect security controls' },
        { key: 'tech', label: 'Tech Fingerprinting', icon: '🔬', description: 'Identify technologies' },
    ]

    return (
        <div className="max-w-4xl mx-auto px-4">
            <h1 className="text-4xl font-bold mb-8 text-gradient">
                New Scan
            </h1>

            <div className="bg-white rounded-xl shadow-lg p-8">
                {/* Target URL */}
                <div className="mb-6">
                    <label className="block text-sm font-semibold text-gray-700 mb-2">
                        Target URL
                    </label>
                    <input
                        type="text"
                        value={targetUrl}
                        onChange={(e) => setTargetUrl(e.target.value)}
                        placeholder="https://example.com"
                        className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent outline-none transition-all"
                    />
                    <p className="text-xs text-gray-500 mt-1">
                        Ensure you have permission to scan this target
                    </p>
                </div>

                {/* Scan Type */}
                <div className="mb-6">
                    <label className="block text-sm font-semibold text-gray-700 mb-3">
                        Scan Type
                    </label>
                    <div className="grid grid-cols-3 gap-4">
                        {scanTypes.map((type) => {
                            const Icon = type.icon
                            return (
                                <button
                                    key={type.id}
                                    onClick={() => setScanType(type.id)}
                                    className={`p-4 rounded-lg border-2 transition-all text-left ${scanType === type.id
                                        ? 'border-purple-500 bg-purple-50 shadow-md'
                                        : 'border-gray-200 hover:border-purple-300'
                                        }`}
                                >
                                    <Icon className="mb-2 text-purple-600" size={24} />
                                    <div className="font-semibold text-gray-800">{type.name}</div>
                                    <div className="text-xs text-gray-500 mt-1">{type.duration}</div>
                                    <div className="text-xs text-gray-600 mt-2">{type.description}</div>
                                </button>
                            )
                        })}
                    </div>
                </div>

                {/* Scan Options */}
                <div className="mb-6">
                    <label className="block text-sm font-semibold text-gray-700 mb-3">
                        Scan Options
                    </label>
                    <div className="grid grid-cols-2 gap-4">
                        {scanOptions.map((option) => (
                            <label
                                key={option.key}
                                className="flex items-start space-x-3 p-4 bg-gray-50 rounded-lg hover:bg-gray-100 cursor-pointer transition-colors"
                            >
                                <input
                                    type="checkbox"
                                    checked={options[option.key]}
                                    onChange={(e) => setOptions({ ...options, [option.key]: e.target.checked })}
                                    className="w-5 h-5 text-purple-600 rounded focus:ring-purple-500 mt-0.5"
                                />
                                <div className="flex-1">
                                    <div className="flex items-center space-x-2">
                                        <span className="text-xl">{option.icon}</span>
                                        <span className="font-medium text-gray-700">{option.label}</span>
                                    </div>
                                    <p className="text-xs text-gray-500 mt-1">{option.description}</p>
                                </div>
                            </label>
                        ))}
                    </div>
                </div>

                {/* Authentication Details (if enabled) */}
                {options.auth && (
                    <div className="mb-6 p-4 bg-blue-50 border border-blue-200 rounded-lg">
                        <h4 className="font-semibold text-blue-900 mb-3">Authentication Details</h4>
                        <div className="grid grid-cols-2 gap-4">
                            <input
                                type="text"
                                placeholder="Username or Email"
                                className="px-4 py-2 border border-blue-300 rounded-lg focus:ring-2 focus:ring-blue-500 outline-none"
                            />
                            <input
                                type="password"
                                placeholder="Password"
                                className="px-4 py-2 border border-blue-300 rounded-lg focus:ring-2 focus:ring-blue-500 outline-none"
                            />
                        </div>
                        <p className="text-xs text-blue-700 mt-2">
                            Credentials are encrypted and never stored
                        </p>
                    </div>
                )}

                {/* Start Scan Button */}
                <button
                    onClick={handleStartScan}
                    disabled={!targetUrl || loading}
                    className="w-full py-4 gradient-bg text-white font-semibold rounded-lg hover:shadow-lg transform hover:scale-[1.02] transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed disabled:transform-none"
                >
                    <span className="text-xl mr-2">🚀</span>
                    {loading ? 'Starting Scan...' : 'Start Scan'}
                </button>
            </div>
        </div>
    )
}

export default NewScan
