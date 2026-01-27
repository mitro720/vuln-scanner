import { useState, useEffect } from 'react'
import { useParams } from 'react-router-dom'
import SeverityBadge from '../components/common/SeverityBadge'
import { Download, FileText, AlertCircle } from 'lucide-react'

const Results = () => {
    const { id } = useParams()
    const [findings, setFindings] = useState([])
    const [scanDetails, setScanDetails] = useState(null)
    const [selectedFinding, setSelectedFinding] = useState(null)
    const [loading, setLoading] = useState(true)

    useEffect(() => {
        const fetchResults = async () => {
            try {
                // Fetch Scan Details
                const scanRes = await fetch(`http://localhost:5000/api/scans/${id}`)
                const scanData = await scanRes.json()
                setScanDetails(scanData?.data || scanData)

                // Fetch Findings
                const findingsRes = await fetch(`http://localhost:5000/api/scans/${id}/findings`)
                const findingsData = await findingsRes.json()

                // Normalize the findings data
                const normalizedFindings = (findingsData?.data || findingsData || []).map(finding => ({
                    ...finding,
                    // Ensure remediation is always an array
                    remediation: Array.isArray(finding.remediation)
                        ? finding.remediation
                        : typeof finding.remediation === 'string'
                            ? finding.remediation.split('\n').filter(Boolean)
                            : ['No remediation steps available'],
                    // Ensure evidence and poc are strings
                    evidence: finding.evidence || 'No evidence available',
                    poc: finding.poc || 'No proof of concept available'
                }))

                setFindings(normalizedFindings)

                if (normalizedFindings.length > 0) {
                    setSelectedFinding(normalizedFindings[0])
                }
            } catch (error) {
                console.error("Error fetching results:", error)
            } finally {
                setLoading(false)
            }
        }
        fetchResults()
    }, [id])


    if (loading) return <div className="p-8 text-center">Loading results...</div>
    if (!scanDetails) return <div className="p-8 text-center">Scan not found.</div>
    if (findings.length === 0) {
        return (
            <div className="max-w-7xl mx-auto px-4">
                <h1 className="text-4xl font-bold text-gradient mb-8">Scan Results</h1>
                <div className="bg-white rounded-xl shadow-lg p-12 text-center">
                    <AlertCircle size={64} className="mx-auto mb-4 text-gray-400" />
                    <h2 className="text-2xl font-bold text-gray-700 mb-2">No Vulnerabilities Found</h2>
                    <p className="text-gray-500">This scan completed successfully with no security issues detected.</p>
                </div>
            </div>
        )
    }


    return (
        <div className="max-w-7xl mx-auto px-4">
            <div className="flex items-center justify-between mb-8">
                <h1 className="text-4xl font-bold text-gradient">Scan Results</h1>
                <div className="flex space-x-3">
                    <button className="flex items-center space-x-2 px-4 py-2 bg-white border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors">
                        <Download size={18} />
                        <span>Export PDF</span>
                    </button>
                    <button className="flex items-center space-x-2 px-4 py-2 gradient-bg text-white rounded-lg hover:shadow-lg transition-all">
                        <FileText size={18} />
                        <span>Full Report</span>
                    </button>
                </div>
            </div>

            <div className="grid grid-cols-3 gap-6">
                {/* Findings List */}
                <div className="col-span-1 space-y-3">
                    <h3 className="text-lg font-semibold text-gray-700 mb-4">
                        Findings ({findings.length})
                    </h3>
                    {findings.map((finding) => (
                        <div
                            key={finding.id}
                            onClick={() => setSelectedFinding(finding)}
                            className={`p-4 bg-white rounded-lg shadow cursor-pointer transition-all hover:shadow-lg ${selectedFinding?.id === finding.id ? 'ring-2 ring-purple-500' : ''
                                }`}
                        >
                            <div className="flex items-center justify-between mb-2">
                                <SeverityBadge severity={finding.severity} size="sm" />
                                <span className="text-xs text-gray-500">{finding.confidence}%</span>
                            </div>
                            <h3 className="font-semibold text-gray-800">{finding.name}</h3>
                            <p className="text-xs text-gray-500 mt-1">{finding.owasp}</p>
                        </div>
                    ))}
                </div>

                {/* Finding Details */}
                <div className="col-span-2">
                    {selectedFinding ? (
                        <div className="bg-white rounded-xl shadow-lg p-8">
                            <div className="flex items-center justify-between mb-6">
                                <h2 className="text-3xl font-bold text-gray-800">{selectedFinding.name}</h2>
                                <SeverityBadge severity={selectedFinding.severity} size="lg" />
                            </div>

                            <div className="space-y-6">
                                <div className="grid grid-cols-2 gap-4">
                                    <div>
                                        <h3 className="text-sm font-semibold text-gray-500 mb-2">OWASP Category</h3>
                                        <p className="text-lg text-gray-800">{selectedFinding.owasp}</p>
                                    </div>
                                    <div>
                                        <h3 className="text-sm font-semibold text-gray-500 mb-2">CWE</h3>
                                        <a
                                            href={`https://cwe.mitre.org/data/definitions/${selectedFinding.cwe?.replace('CWE-', '')}.html`}
                                            target="_blank"
                                            rel="noopener noreferrer"
                                            className="text-lg text-purple-600 hover:underline"
                                        >
                                            {selectedFinding.cwe || 'N/A'}
                                        </a>
                                    </div>
                                </div>

                                {/* CVSS Score Display */}
                                {selectedFinding.cvss_score && (
                                    <div className="bg-gradient-to-r from-gray-50 to-gray-100 p-4 rounded-lg border border-gray-200">
                                        <div className="flex items-center justify-between">
                                            <div>
                                                <h3 className="text-sm font-semibold text-gray-500 mb-1">CVSS 3.1 Score</h3>
                                                <div className="flex items-center space-x-3">
                                                    <span className={`text-3xl font-bold ${selectedFinding.cvss_score >= 9 ? 'text-red-600' :
                                                        selectedFinding.cvss_score >= 7 ? 'text-orange-500' :
                                                            selectedFinding.cvss_score >= 4 ? 'text-yellow-500' :
                                                                'text-green-500'
                                                        }`}>
                                                        {selectedFinding.cvss_score}
                                                    </span>
                                                    <span className={`px-3 py-1 rounded-full text-sm font-semibold ${selectedFinding.cvss_score >= 9 ? 'bg-red-100 text-red-700' :
                                                        selectedFinding.cvss_score >= 7 ? 'bg-orange-100 text-orange-700' :
                                                            selectedFinding.cvss_score >= 4 ? 'bg-yellow-100 text-yellow-700' :
                                                                'bg-green-100 text-green-700'
                                                        }`}>
                                                        {selectedFinding.cvss_score >= 9 ? 'CRITICAL' :
                                                            selectedFinding.cvss_score >= 7 ? 'HIGH' :
                                                                selectedFinding.cvss_score >= 4 ? 'MEDIUM' : 'LOW'}
                                                    </span>
                                                </div>
                                            </div>
                                            <div className="text-right">
                                                <h3 className="text-sm font-semibold text-gray-500 mb-1">Vector String</h3>
                                                <code className="text-xs bg-gray-200 px-2 py-1 rounded font-mono">
                                                    {selectedFinding.cvss_vector}
                                                </code>
                                            </div>
                                        </div>
                                    </div>
                                )}

                                <div>
                                    <h3 className="text-sm font-semibold text-gray-500 mb-2">Location</h3>
                                    <code className="block bg-gray-100 p-3 rounded-lg text-sm font-mono">
                                        {selectedFinding.url}
                                    </code>
                                </div>

                                <div>
                                    <h3 className="text-sm font-semibold text-gray-500 mb-2">Confidence</h3>
                                    <div className="flex items-center space-x-3">
                                        <div className="flex-1 bg-gray-200 rounded-full h-2">
                                            <div
                                                className="gradient-bg h-2 rounded-full transition-all"
                                                style={{ width: `${selectedFinding.confidence}%` }}
                                            ></div>
                                        </div>
                                        <span className="font-semibold text-gray-800">
                                            {selectedFinding.confidence}%
                                        </span>
                                    </div>
                                </div>

                                <div>
                                    <h3 className="text-sm font-semibold text-gray-500 mb-2">
                                        Detection Technique
                                    </h3>
                                    <p className="text-gray-800">{selectedFinding.technique}</p>
                                </div>

                                <div>
                                    <h3 className="text-sm font-semibold text-gray-500 mb-2">Evidence</h3>
                                    <pre className="bg-gray-900 text-green-400 p-4 rounded-lg text-sm overflow-x-auto font-mono">
                                        {selectedFinding.evidence}
                                    </pre>
                                </div>

                                <div>
                                    <h3 className="text-sm font-semibold text-gray-500 mb-2">Proof of Concept</h3>
                                    <pre className="bg-gray-900 text-blue-400 p-4 rounded-lg text-sm overflow-x-auto font-mono">
                                        {selectedFinding.poc}
                                    </pre>
                                </div>

                                <div>
                                    <h3 className="text-sm font-semibold text-gray-500 mb-2">Remediation</h3>
                                    <ul className="list-disc list-inside space-y-1 text-gray-700">
                                        {selectedFinding.remediation.map((item, index) => (
                                            <li key={index}>{item}</li>
                                        ))}
                                    </ul>
                                </div>

                                <div className="flex space-x-3 pt-4">
                                    <button className="flex-1 py-3 gradient-bg text-white font-semibold rounded-lg hover:shadow-lg transition-all">
                                        Export Finding
                                    </button>
                                    <button className="flex-1 py-3 border-2 border-gray-300 text-gray-700 font-semibold rounded-lg hover:border-purple-500 transition-all">
                                        Mark as False Positive
                                    </button>
                                </div>
                            </div>
                        </div>
                    ) : (
                        <div className="bg-white rounded-xl shadow-lg p-8 flex items-center justify-center h-full min-h-[500px]">
                            <div className="text-center text-gray-400">
                                <AlertCircle size={64} className="mx-auto mb-4" />
                                <p className="text-lg">Select a finding to view details</p>
                            </div>
                        </div>
                    )}
                </div>
            </div>
        </div>
    )
}

export default Results
