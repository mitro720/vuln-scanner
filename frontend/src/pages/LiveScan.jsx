import { useState, useEffect } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { CheckCircle, Circle, Loader } from 'lucide-react'

const LiveScan = () => {
    const { id } = useParams()
    const navigate = useNavigate()
    const [scan, setScan] = useState(null)
    const [findings, setFindings] = useState([])
    const [loading, setLoading] = useState(true)

    // Fetch scan data and findings
    useEffect(() => {
        const fetchScanData = async () => {
            try {
                // Fetch scan details
                const scanRes = await fetch(`http://localhost:5000/api/scans/${id}`)
                if (scanRes.ok) {
                    const scanData = await scanRes.json()
                    setScan(scanData.data)

                    // If scan is completed, redirect to results
                    if (scanData.data.status === 'completed') {
                        setTimeout(() => navigate(`/results/${id}`), 2000)
                    }
                }

                // Fetch findings
                const findingsRes = await fetch(`http://localhost:5000/api/scans/${id}/findings`)
                if (findingsRes.ok) {
                    const findingsData = await findingsRes.json()
                    setFindings(findingsData.data || [])
                }
            } catch (error) {
                console.error('Error fetching scan data:', error)
            } finally {
                setLoading(false)
            }
        }

        fetchScanData()

        // Poll every 2 seconds while scan is running
        const interval = setInterval(fetchScanData, 2000)
        return () => clearInterval(interval)
    }, [id, navigate])

    if (loading) {
        return <div className="p-8 text-center">Loading scan...</div>
    }

    if (!scan) {
        return <div className="p-8 text-center">Scan not found.</div>
    }

    // Calculate severity counts
    const severityCounts = findings.reduce((acc, finding) => {
        const sev = finding.severity || 'info'
        acc[sev] = (acc[sev] || 0) + 1
        return acc
    }, {})

    const progress = scan.progress || 0
    const currentPhase = scan.current_phase || 'Initializing'
    const isRunning = scan.status === 'running'
    const isFailed = scan.status === 'failed'

    return (
        <div className="max-w-6xl mx-auto px-4">
            <h1 className="text-4xl font-bold mb-8 text-gradient">
                Live Scan
            </h1>

            <div className="bg-white rounded-xl shadow-lg p-8 mb-6">
                {/* Scan Header */}
                <div className="flex items-center justify-between mb-6">
                    <div>
                        <h2 className="text-2xl font-bold text-gray-800">{scan.target_url || 'Unknown Target'}</h2>
                        <p className="text-gray-500">
                            Started: {scan.created_at ? new Date(scan.created_at).toLocaleString() : 'Unknown'}
                        </p>
                    </div>
                    <div className="flex items-center space-x-2">
                        {isRunning && (
                            <>
                                <div className="w-3 h-3 bg-blue-500 rounded-full animate-pulse"></div>
                                <span className="text-blue-500 font-semibold">SCANNING</span>
                            </>
                        )}
                        {isFailed && (
                            <>
                                <div className="w-3 h-3 bg-red-500 rounded-full"></div>
                                <span className="text-red-500 font-semibold">FAILED</span>
                            </>
                        )}
                        {scan.status === 'completed' && (
                            <>
                                <div className="w-3 h-3 bg-green-500 rounded-full"></div>
                                <span className="text-green-500 font-semibold">COMPLETED</span>
                            </>
                        )}
                    </div>
                </div>

                {/* Progress Bar */}
                <div className="mb-6">
                    <div className="flex justify-between mb-2">
                        <span className="text-sm font-semibold text-gray-700">{currentPhase}</span>
                        <span className="text-sm font-semibold text-gray-700">{progress}%</span>
                    </div>
                    <div className="w-full bg-gray-200 rounded-full h-3 overflow-hidden">
                        <div
                            className="h-3 gradient-bg rounded-full transition-all duration-500 relative"
                            style={{ width: `${progress}%` }}
                        >
                            {isRunning && (
                                <div className="absolute inset-0 bg-white opacity-30 animate-scan"></div>
                            )}
                        </div>
                    </div>
                </div>

                {/* Recent Findings */}
                {findings.length > 0 && (
                    <div className="space-y-3">
                        <h3 className="text-lg font-semibold text-gray-800 mb-3">Recent Findings</h3>
                        {findings.slice(-5).reverse().map((finding, index) => (
                            <div key={index} className="flex items-start space-x-3 p-3 bg-gray-50 rounded-lg">
                                {finding.severity === 'critical' && <span className="text-red-500 text-xl">⚠</span>}
                                {finding.severity === 'high' && <span className="text-orange-500 text-xl">⚠</span>}
                                {finding.severity === 'medium' && <span className="text-yellow-500 text-xl">⚠</span>}
                                {finding.severity === 'low' && <span className="text-blue-500 text-xl">ℹ</span>}
                                <div className="flex-1">
                                    <p className={`font-semibold ${finding.severity === 'critical' ? 'text-red-600' :
                                            finding.severity === 'high' ? 'text-orange-600' :
                                                finding.severity === 'medium' ? 'text-yellow-600' :
                                                    'text-gray-600'
                                        }`}>
                                        {finding.name}
                                    </p>
                                    <p className="text-sm text-gray-500">{finding.url}</p>
                                </div>
                                <span className="text-xs bg-gray-200 px-2 py-1 rounded">
                                    {finding.confidence}% confidence
                                </span>
                            </div>
                        ))}
                    </div>
                )}
            </div>

            {/* Quick Stats */}
            <div className="grid grid-cols-4 gap-4">
                <div className="bg-white rounded-lg shadow p-4 text-center">
                    <div className="text-2xl font-bold text-red-500">{severityCounts.critical || 0}</div>
                    <div className="text-sm text-gray-600">Critical</div>
                </div>
                <div className="bg-white rounded-lg shadow p-4 text-center">
                    <div className="text-2xl font-bold text-orange-500">{severityCounts.high || 0}</div>
                    <div className="text-sm text-gray-600">High</div>
                </div>
                <div className="bg-white rounded-lg shadow p-4 text-center">
                    <div className="text-2xl font-bold text-yellow-500">{severityCounts.medium || 0}</div>
                    <div className="text-sm text-gray-600">Medium</div>
                </div>
                <div className="bg-white rounded-lg shadow p-4 text-center">
                    <div className="text-2xl font-bold text-blue-500">{severityCounts.low || 0}</div>
                    <div className="text-sm text-gray-600">Low</div>
                </div>
            </div>
        </div>
    )
}

export default LiveScan
