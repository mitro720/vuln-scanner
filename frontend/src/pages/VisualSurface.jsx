import { useState, useEffect } from 'react'
import { useParams, Link } from 'react-router-dom'
import { Globe, Clock, Camera, ChevronLeft, Maximize2, ExternalLink, Search } from 'lucide-react'

const API = 'http://localhost:5000/api'

const VisualSurface = () => {
    const { id } = useParams()
    const [scan, setScan] = useState(null)
    const [screenshots, setScreenshots] = useState([])
    const [loading, setLoading] = useState(true)
    const [selectedImg, setSelectedImg] = useState(null)
    const [searchTerm, setSearchTerm] = useState('')

    useEffect(() => {
        const load = async () => {
            try {
                const res = await fetch(`${API}/scans/${id}`)
                const data = await res.json()
                const s = data?.data || data
                setScan(s)
                setScreenshots(s.metadata?.screenshots || [])
            } catch (err) {
                console.error('Failed to load visual survey:', err)
            } finally {
                setLoading(false)
            }
        }
        if (id) load()
    }, [id])

    const filtered = screenshots.filter(s =>
        s.url.toLowerCase().includes(searchTerm.toLowerCase())
    )

    if (loading) return (
        <div className="flex items-center justify-center min-h-[60vh]">
            <div className="w-10 h-10 border-4 border-purple-500 border-t-transparent rounded-full animate-spin" />
        </div>
    )

    return (
        <div className="max-w-7xl mx-auto px-4 pb-20">
            {/* Header */}
            <div className="flex items-center justify-between mb-8">
                <div className="flex items-center space-x-4">
                    <Link to={`/results/${id}`} className="p-2 bg-gray-800 rounded-lg hover:bg-gray-700 transition-colors text-gray-400">
                        <ChevronLeft size={20} />
                    </Link>
                    <div>
                        <h1 className="text-3xl font-bold text-gradient">Visual Attack Surface</h1>
                        <p className="text-sm text-gray-400 mt-1 flex items-center space-x-2">
                            <span className="flex items-center space-x-1"><Globe size={13} /><span>{scan?.target_url}</span></span>
                            <span className="text-gray-600">|</span>
                            <span>{screenshots.length} visual captures</span>
                        </p>
                    </div>
                </div>

                <div className="relative">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" size={16} />
                    <input
                        type="text"
                        placeholder="Filter URLs..."
                        value={searchTerm}
                        onChange={(e) => setSearchTerm(e.target.value)}
                        className="bg-gray-900 border border-gray-800 rounded-xl py-2 pl-10 pr-4 text-sm text-gray-300 focus:outline-none focus:border-purple-500/50 transition-all w-64"
                    />
                </div>
            </div>

            {screenshots.length === 0 ? (
                <div className="bg-gray-900 rounded-3xl border border-gray-800 p-20 text-center">
                    <Camera className="mx-auto mb-4 text-gray-700" size={64} />
                    <h2 className="text-xl font-bold text-white mb-2">No Screenshots Captured</h2>
                    <p className="text-gray-500 max-w-md mx-auto">
                        The visual survey was either skipped or no live pages were found for capturing.
                        Make sure the 'Visual Survey' option is enabled in the scan configuration.
                    </p>
                </div>
            ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                    {filtered.map((s, i) => (
                        <div key={i} className="group bg-gray-900 rounded-2xl border border-gray-800 overflow-hidden hover:border-purple-500/30 transition-all hover:shadow-2xl hover:shadow-purple-500/10">
                            <div className="relative aspect-video overflow-hidden bg-gray-950">
                                <img
                                    src={`http://localhost:5000/screenshots/${s.filename}`}
                                    alt={s.url}
                                    className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-500 opacity-90 group-hover:opacity-100"
                                    onClick={() => setSelectedImg(s)}
                                />
                                <div className="absolute inset-0 bg-black/40 opacity-0 group-hover:opacity-100 transition-opacity flex items-center justify-center pointer-events-none">
                                    <div className="flex space-x-2 pointer-events-auto">
                                        <button
                                            onClick={() => setSelectedImg(s)}
                                            className="p-2 bg-purple-600 rounded-lg text-white shadow-xl hover:bg-purple-500 transition-all">
                                            <Maximize2 size={16} />
                                        </button>
                                        <a
                                            href={s.url} target="_blank" rel="noopener noreferrer"
                                            className="p-2 bg-gray-800 rounded-lg text-white shadow-xl hover:bg-gray-700 transition-all">
                                            <ExternalLink size={16} />
                                        </a>
                                    </div>
                                </div>
                            </div>
                            <div className="p-4">
                                <p className="text-xs text-blue-400 font-mono truncate mb-1">{s.url}</p>
                                <div className="flex items-center justify-between">
                                    <span className="text-[10px] text-gray-500 flex items-center space-x-1">
                                        <Camera size={10} /><span>Visual Capture</span>
                                    </span>
                                </div>
                            </div>
                        </div>
                    ))}
                </div>
            )}

            {/* Lightbox / Modal */}
            {selectedImg && (
                <div className="fixed inset-0 z-50 flex items-center justify-center p-8 bg-black/95 animate-fade-in" onClick={() => setSelectedImg(null)}>
                    <div className="relative max-w-6xl w-full" onClick={e => e.stopPropagation()}>
                        <div className="bg-gray-900 rounded-t-2xl border-x border-t border-gray-800 p-4 flex items-center justify-between">
                            <div className="flex items-center space-x-3">
                                <div className="p-2 bg-purple-500/20 rounded-lg text-purple-400">
                                    <Camera size={18} />
                                </div>
                                <span className="text-sm font-semibold text-white font-mono truncate max-w-2xl">{selectedImg.url}</span>
                            </div>
                            <button onClick={() => setSelectedImg(null)} className="text-gray-400 hover:text-white transition-colors">
                                <Maximize2 size={20} className="rotate-45" />
                            </button>
                        </div>
                        <div className="bg-gray-950 border border-gray-800 rounded-b-2xl overflow-hidden shadow-2xl">
                            <img
                                src={`http://localhost:5000/screenshots/${selectedImg.filename}`}
                                alt={selectedImg.url}
                                className="w-full h-auto max-h-[80vh] object-contain"
                            />
                        </div>
                        <div className="mt-4 flex justify-center">
                            <a href={selectedImg.url} target="_blank" rel="noopener noreferrer"
                                className="flex items-center space-x-2 text-sm text-purple-400 hover:text-purple-300 font-semibold px-4 py-2 bg-purple-500/10 rounded-full border border-purple-500/20 transition-all">
                                <span>Open Live URL</span><ExternalLink size={14} />
                            </a>
                        </div>
                    </div>
                </div>
            )}
        </div>
    )
}

export default VisualSurface
