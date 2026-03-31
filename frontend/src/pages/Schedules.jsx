import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { Clock, Plus, Trash2, ToggleLeft, ToggleRight, Calendar, Globe, AlertCircle } from 'lucide-react'

const API = 'http://localhost:5000/api'

const FREQUENCY_OPTIONS = [
    { value: 'hourly', label: 'Every Hour', cron: '0 * * * *' },
    { value: 'daily', label: 'Daily (8am)', cron: '0 8 * * *' },
    { value: 'weekly', label: 'Weekly (Mon)', cron: '0 8 * * 1' },
    { value: 'monthly', label: 'Monthly (1st)', cron: '0 8 1 * *' },
    { value: 'custom', label: 'Custom cron…', cron: '' },
]

const Schedules = () => {
    const [schedules, setSchedules] = useState([])
    const [loading, setLoading] = useState(true)
    const [showForm, setShowForm] = useState(false)
    const [form, setForm] = useState({ name: '', target_url: '', frequency: 'daily', cron_expression: '', scan_type: 'full' })
    const [saving, setSaving] = useState(false)
    const [error, setError] = useState('')

    const fetchSchedules = async () => {
        try {
            const r = await fetch(`${API}/schedules`)
            if (r.ok) { const d = await r.json(); setSchedules(d.data || []) }
        } catch { setSchedules([]) } finally { setLoading(false) }
    }

    useEffect(() => { fetchSchedules() }, [])

    const handleCreate = async () => {
        if (!form.target_url.trim()) { setError('Target URL is required'); return }
        setSaving(true); setError('')
        const chosen = FREQUENCY_OPTIONS.find(f => f.value === form.frequency)
        try {
            const r = await fetch(`${API}/schedules`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    ...form,
                    cron_expression: form.frequency === 'custom' ? form.cron_expression : chosen?.cron,
                }),
            })
            if (!r.ok) { const d = await r.json(); throw new Error(d.error || 'Failed'); }
            await fetchSchedules()
            setShowForm(false)
            setForm({ name: '', target_url: '', frequency: 'daily', cron_expression: '', scan_type: 'full' })
        } catch (e) { setError(e.message) } finally { setSaving(false) }
    }

    const handleToggle = async (id) => {
        await fetch(`${API}/schedules/${id}/toggle`, { method: 'PATCH' })
        fetchSchedules()
    }

    const handleDelete = async (id) => {
        if (!confirm('Delete this schedule?')) return
        await fetch(`${API}/schedules/${id}`, { method: 'DELETE' })
        fetchSchedules()
    }

    return (
        <div className="max-w-5xl mx-auto px-4 pb-10">
            <div className="flex items-center justify-between mb-8">
                <div>
                    <h1 className="text-4xl font-bold text-gradient">Scheduled Scans</h1>
                    <p className="text-gray-400 mt-1">Automate recurring vulnerability assessments</p>
                </div>
                <button onClick={() => setShowForm(!showForm)}
                    className="flex items-center space-x-2 px-5 py-2.5 gradient-bg text-white font-semibold rounded-xl hover:shadow-lg hover:shadow-purple-500/25 transition-all text-sm">
                    <Plus size={16} /><span>New Schedule</span>
                </button>
            </div>

            {/* Create Form */}
            {showForm && (
                <div className="bg-gray-900 border border-purple-500/30 rounded-xl p-6 mb-6">
                    <h3 className="font-bold text-white mb-4">Create Recurring Scan</h3>
                    {error && (
                        <div className="flex items-center space-x-2 bg-red-900/30 border border-red-700/40 text-red-300 px-4 py-2 rounded-lg mb-4 text-sm">
                            <AlertCircle size={14} /><span>{error}</span>
                        </div>
                    )}
                    <div className="grid grid-cols-2 gap-4">
                        <div>
                            <label className="block text-xs text-gray-400 mb-1 uppercase tracking-wider">Schedule Name</label>
                            <input type="text" value={form.name} onChange={e => setForm({ ...form, name: e.target.value })}
                                placeholder="e.g. Daily prod scan"
                                className="w-full px-4 py-2.5 bg-gray-800 border border-gray-700 text-white rounded-lg text-sm focus:ring-1 focus:ring-purple-500 outline-none placeholder-gray-500" />
                        </div>
                        <div>
                            <label className="block text-xs text-gray-400 mb-1 uppercase tracking-wider">Target URL</label>
                            <input type="text" value={form.target_url} onChange={e => setForm({ ...form, target_url: e.target.value })}
                                placeholder="https://example.com"
                                className="w-full px-4 py-2.5 bg-gray-800 border border-gray-700 text-white rounded-lg text-sm focus:ring-1 focus:ring-purple-500 outline-none placeholder-gray-500" />
                        </div>
                        <div>
                            <label className="block text-xs text-gray-400 mb-1 uppercase tracking-wider">Frequency</label>
                            <select value={form.frequency} onChange={e => setForm({ ...form, frequency: e.target.value })}
                                className="w-full px-4 py-2.5 bg-gray-800 border border-gray-700 text-white rounded-lg text-sm focus:ring-1 focus:ring-purple-500 outline-none">
                                {FREQUENCY_OPTIONS.map(f => (<option key={f.value} value={f.value}>{f.label}</option>))}
                            </select>
                        </div>
                        <div>
                            <label className="block text-xs text-gray-400 mb-1 uppercase tracking-wider">Scan Template</label>
                            <select value={form.scan_type} onChange={e => setForm({ ...form, scan_type: e.target.value })}
                                className="w-full px-4 py-2.5 bg-gray-800 border border-gray-700 text-white rounded-lg text-sm focus:ring-1 focus:ring-purple-500 outline-none">
                                <option value="full">Full + CVE</option>
                                <option value="webapp">Web App</option>
                                <option value="basic">Basic Network</option>
                                <option value="quick">Quick</option>
                            </select>
                        </div>
                        {form.frequency === 'custom' && (
                            <div className="col-span-2">
                                <label className="block text-xs text-gray-400 mb-1 uppercase tracking-wider">Custom Cron Expression</label>
                                <input type="text" value={form.cron_expression} onChange={e => setForm({ ...form, cron_expression: e.target.value })}
                                    placeholder="e.g.  0 */6 * * *  (every 6 hours)"
                                    className="w-full px-4 py-2.5 bg-gray-800 border border-gray-700 text-white rounded-lg text-sm focus:ring-1 focus:ring-purple-500 outline-none font-mono placeholder-gray-500" />
                            </div>
                        )}
                    </div>
                    <div className="flex space-x-3 mt-4">
                        <button onClick={handleCreate} disabled={saving}
                            className="px-5 py-2 gradient-bg text-white font-semibold rounded-lg text-sm disabled:opacity-50">
                            {saving ? 'Creating…' : 'Create Schedule'}
                        </button>
                        <button onClick={() => setShowForm(false)} className="px-5 py-2 border border-gray-700 text-gray-400 rounded-lg text-sm hover:bg-gray-800">Cancel</button>
                    </div>
                </div>
            )}

            {/* Schedule List */}
            {loading ? (
                <div className="text-center text-gray-500 py-16">Loading schedules…</div>
            ) : schedules.length === 0 ? (
                <div className="bg-gray-900 border border-gray-800 rounded-xl p-16 text-center">
                    <Calendar size={48} className="mx-auto mb-4 text-gray-700" />
                    <p className="text-gray-400">No scheduled scans yet.</p>
                    <p className="text-gray-600 text-sm mt-1">Create one above to automate your security assessments.</p>
                </div>
            ) : (
                <div className="space-y-3">
                    {schedules.map(s => (
                        <div key={s.id} className={`bg-gray-900 rounded-xl border ${s.enabled ? 'border-gray-800 hover:border-gray-700' : 'border-gray-800/50 opacity-60'} p-5 transition-all`}>
                            <div className="flex items-center justify-between">
                                <div className="flex items-start space-x-4">
                                    <div className="w-10 h-10 rounded-xl bg-purple-500/10 border border-purple-500/20 flex items-center justify-center flex-shrink-0 mt-0.5">
                                        <Calendar size={18} className="text-purple-400" />
                                    </div>
                                    <div>
                                        <div className="flex items-center space-x-2">
                                            <h3 className="font-semibold text-white">{s.name}</h3>
                                            <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${s.enabled ? 'bg-green-900/40 text-green-400 border border-green-700/30' : 'bg-gray-800 text-gray-500'}`}>
                                                {s.enabled ? 'Active' : 'Paused'}
                                            </span>
                                        </div>
                                        <div className="flex items-center space-x-4 mt-1 text-xs text-gray-400">
                                            <span className="flex items-center space-x-1"><Globe size={11} /><span>{s.target_url}</span></span>
                                            <span className="flex items-center space-x-1"><Clock size={11} /><code className="font-mono">{s.cron_expression}</code></span>
                                            <span>{s.scan_type} scan</span>
                                            {s.run_count > 0 && <span>Ran {s.run_count} time{s.run_count !== 1 ? 's' : ''}</span>}
                                        </div>
                                    </div>
                                </div>
                                <div className="flex items-center space-x-2">
                                    {s.last_scan_id && (
                                        <Link to={`/results/${s.last_scan_id}`}
                                            className="text-xs text-purple-400 hover:text-purple-300 px-3 py-1.5 border border-gray-700 rounded-lg transition-colors">
                                            Last Report
                                        </Link>
                                    )}
                                    <button onClick={() => handleToggle(s.id)}
                                        className="p-2 hover:bg-gray-800 rounded-lg transition-colors"
                                        title={s.enabled ? 'Pause' : 'Resume'}>
                                        {s.enabled ? <ToggleRight size={20} className="text-green-400" /> : <ToggleLeft size={20} className="text-gray-500" />}
                                    </button>
                                    <button onClick={() => handleDelete(s.id)}
                                        className="p-2 hover:bg-red-900/30 rounded-lg transition-colors text-gray-500 hover:text-red-400">
                                        <Trash2 size={16} />
                                    </button>
                                </div>
                            </div>
                        </div>
                    ))}
                </div>
            )}
        </div>
    )
}

export default Schedules
