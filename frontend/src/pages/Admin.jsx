import { useState, useEffect } from 'react'
import { 
    Users, 
    UserPlus, 
    Shield, 
    ShieldCheck, 
    Trash2, 
    Search, 
    User, 
    Mail, 
    Lock, 
    MoreVertical, 
    AlertCircle,
    Loader2,
    X,
    Check
} from 'lucide-react'

const API = 'http://localhost:5000/api'

const Admin = () => {
    const [users, setUsers] = useState([])
    const [loading, setLoading] = useState(true)
    const [searchTerm, setSearchTerm] = useState('')
    const [isModalOpen, setIsModalOpen] = useState(false)
    const [error, setError] = useState('')
    const [success, setSuccess] = useState('')
    
    // New User State
    const [newUsername, setNewUsername] = useState('')
    const [newPassword, setNewPassword] = useState('')
    const [newRole, setNewRole] = useState('member')
    const [submitting, setSubmitting] = useState(false)

    useEffect(() => {
        fetchUsers()
    }, [])

    const fetchUsers = async () => {
        setLoading(true)
        try {
            const authData = JSON.parse(localStorage.getItem('user'))
            const token = authData?.token
            const res = await fetch(`${API}/users`, {
                headers: { 'Authorization': `Bearer ${token}` }
            })
            const data = await res.json()
            if (data.success) {
                setUsers(data.data)
            } else {
                setError(data.error)
            }
        } catch (err) {
            setError('Failed to load personnel data')
        } finally {
            setLoading(false)
        }
    }

    const handleCreateUser = async (e) => {
        e.preventDefault()
        setSubmitting(true)
        setError('')
        
        try {
            const authData = JSON.parse(localStorage.getItem('user'))
            const token = authData?.token
            const res = await fetch(`${API}/users`, {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}` 
                },
                body: JSON.stringify({
                    username: newUsername,
                    password: newPassword,
                    role: newRole
                })
            })
            const data = await res.json()
            
            if (data.success) {
                setSuccess(`User ${newUsername} authorized successfully`)
                setNewUsername('')
                setNewPassword('')
                setNewRole('member')
                setIsModalOpen(false)
                fetchUsers()
                setTimeout(() => setSuccess(''), 3000)
            } else {
                setError(data.error)
            }
        } catch (err) {
            setError('Failed to create user')
        } finally {
            setSubmitting(false)
        }
    }

    const handleDeleteUser = async (id, username) => {
        if (!window.confirm(`Are you sure you want to revoke access for ${username}?`)) return
        
        try {
            const authData = JSON.parse(localStorage.getItem('user'))
            const token = authData?.token
            const res = await fetch(`${API}/users/${id}`, {
                method: 'DELETE',
                headers: { 'Authorization': `Bearer ${token}` }
            })
            const data = await res.json()
            
            if (data.success) {
                setSuccess(`Access revoked for ${username}`)
                fetchUsers()
                setTimeout(() => setSuccess(''), 3000)
            } else {
                setError(data.error)
            }
        } catch (err) {
            setError('Failed to delete user')
        }
    }

    const handleToggleRole = async (user) => {
        const newRole = user.role === 'admin' ? 'member' : 'admin'
        try {
            const authData = JSON.parse(localStorage.getItem('user'))
            const token = authData?.token
            const res = await fetch(`${API}/users/${user.id}/role`, {
                method: 'PATCH',
                headers: { 
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}` 
                },
                body: JSON.stringify({ role: newRole })
            })
            const data = await res.json()
            if (data.success) {
                fetchUsers()
            }
        } catch (err) {
            setError('Failed to update role')
        }
    }

    const handleToggleStatus = async (user) => {
        // Pending users get approved → active. Active users get suspended and vice versa.
        const newStatus = user.status === 'pending' ? 'active' : user.status === 'active' ? 'suspended' : 'active'
        try {
            const authData = JSON.parse(localStorage.getItem('user'))
            const token = authData?.token
            const res = await fetch(`${API}/users/${user.id}/status`, {
                method: 'PATCH',
                headers: { 
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}` 
                },
                body: JSON.stringify({ status: newStatus })
            })
            const data = await res.json()
            if (data.success) {
                const actionLabel = newStatus === 'active' ? 'Approved & activated' : newStatus === 'suspended' ? 'Suspended' : 'Updated'
                setSuccess(`${actionLabel}: ${user.username}`)
                fetchUsers()
                setTimeout(() => setSuccess(''), 3000)
            } else {
                setError(data.error || 'Failed to update status')
            }
        } catch (err) {
            setError('Failed to update status')
        }
    }

    const filteredUsers = users.filter(u => 
        u.username.toLowerCase().includes(searchTerm.toLowerCase())
    )

    return (
        <div className="space-y-8 animate-in fade-in duration-700">
            {/* Header Section */}
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div>
                    <h1 className="text-4xl font-black text-white tracking-tight uppercase">
                        Personnel <span className="text-primary-500 underline decoration-primary-500/30 underline-offset-8">Management</span>
                    </h1>
                    <p className="text-dark-text-secondary mt-3 font-medium tracking-wide">Authorized security intelligence analysts</p>
                </div>
                <button 
                    onClick={() => setIsModalOpen(true)}
                    className="gradient-bg text-white px-6 py-4 rounded-2xl font-bold flex items-center justify-center space-x-3 shadow-xl shadow-primary-500/20 active:scale-95 transition-all"
                >
                    <UserPlus size={20} />
                    <span>Authorize Personnel</span>
                </button>
            </div>

            {/* Notification Area */}
            {(error || success) && (
                <div className={`p-4 rounded-2xl border flex items-center space-x-3 animate-in slide-in-from-top-4 duration-300 ${
                    error ? 'bg-red-500/10 border-red-500/20 text-red-400' : 'bg-green-500/10 border-green-500/20 text-green-400'
                }`}>
                    {error ? <AlertCircle size={20} /> : <Check size={20} />}
                    <span className="font-bold text-sm tracking-wide">{error || success}</span>
                </div>
            )}

            {/* Content Card */}
            <div className="glass-effect rounded-[2.5rem] border border-white/5 overflow-hidden shadow-2xl">
                {/* Control Bar */}
                <div className="p-8 border-b border-white/5 flex flex-col sm:flex-row justify-between items-center gap-4 bg-white/[0.02]">
                    <div className="relative w-full sm:w-96 group">
                        <Search className="absolute left-4 top-1/2 -translate-y-1/2 text-dark-text-secondary group-focus-within:text-primary-400 transition-colors" size={18} />
                        <input 
                            type="text"
                            placeholder="Search by username or ID..."
                            className="w-full bg-dark-background/50 border border-white/10 rounded-2xl py-3 pl-12 pr-4 focus:outline-none focus:ring-2 focus:ring-primary-500/50 transition-all font-medium text-white placeholder:text-gray-600"
                            value={searchTerm}
                            onChange={(e) => setSearchTerm(e.target.value)}
                        />
                    </div>
                    <div className="flex items-center space-x-2 text-dark-text-secondary bg-dark-background/50 px-4 py-2 rounded-xl border border-white/5">
                        <Users size={16} />
                        <span className="text-xs font-bold uppercase tracking-widest">{filteredUsers.length} Total Analysts</span>
                    </div>
                </div>

                {/* Table Section */}
                <div className="overflow-x-auto">
                    <table className="w-full text-left border-collapse">
                        <thead>
                            <tr className="bg-white/[0.01]">
                                <th className="px-8 py-5 text-[10px] font-black text-dark-text-secondary uppercase tracking-[0.2em] border-b border-white/5">User Entity</th>
                                <th className="px-8 py-5 text-[10px] font-black text-dark-text-secondary uppercase tracking-[0.2em] border-b border-white/5 text-center">Status</th>
                                <th className="px-8 py-5 text-[10px] font-black text-dark-text-secondary uppercase tracking-[0.2em] border-b border-white/5 text-center">Authorization</th>
                                <th className="px-8 py-5 text-[10px] font-black text-dark-text-secondary uppercase tracking-[0.2em] border-b border-white/5">Onboard Date</th>
                                <th className="px-8 py-5 text-[10px] font-black text-dark-text-secondary uppercase tracking-[0.2em] border-b border-white/5 text-right">Actions</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-white/5">
                            {loading ? (
                                <tr>
                                    <td colSpan="5" className="px-8 py-20 text-center">
                                        <Loader2 className="animate-spin text-primary-500 mx-auto mb-4" size={40} />
                                        <p className="text-dark-text-secondary font-bold uppercase tracking-widest text-xs">Decrypting personnel records...</p>
                                    </td>
                                </tr>
                            ) : filteredUsers.length === 0 ? (
                                <tr>
                                    <td colSpan="5" className="px-8 py-20 text-center">
                                        <User className="text-dark-text-secondary/20 mx-auto mb-4" size={48} />
                                        <p className="text-dark-text-secondary font-bold">No matching personnel records discovered</p>
                                    </td>
                                </tr>
                            ) : (
                                filteredUsers.map((u) => (
                                    <tr key={u.id} className="hover:bg-white/[0.02] transition-colors group">
                                        <td className="px-8 py-5">
                                            <div className="flex items-center space-x-4">
                                                <div className="w-12 h-12 rounded-2xl bg-gradient-to-br from-indigo-500/20 to-purple-500/20 border border-white/10 flex items-center justify-center text-primary-400 font-black text-xl group-hover:scale-110 transition-transform">
                                                    {u.username.charAt(0).toUpperCase()}
                                                </div>
                                                <div>
                                                    <p className="text-white font-bold tracking-tight text-lg leading-none">{u.username}</p>
                                                    <p className="text-[10px] text-dark-text-secondary font-mono mt-2 opacity-50 uppercase tracking-tighter">REF: {u.id.substring(0, 8)}...</p>
                                                </div>
                                            </div>
                                        </td>
                                        <td className="px-8 py-5 text-center">
                                            <button 
                                                onClick={() => handleToggleStatus(u)}
                                                className={`mx-auto flex items-center space-x-2 px-3 py-1.5 rounded-xl border text-[10px] font-black uppercase tracking-widest transition-all ${
                                                    u.status === 'active' 
                                                    ? 'bg-green-500/10 border-green-500/30 text-green-400 hover:bg-green-500/20' 
                                                    : u.status === 'suspended'
                                                    ? 'bg-red-500/10 border-red-500/30 text-red-400 hover:bg-red-500/20'
                                                    : 'bg-yellow-500/10 border-yellow-500/30 text-yellow-400 hover:bg-yellow-500/20 animate-pulse'
                                                }`}
                                                title={u.status === 'pending' ? 'Click to Approve' : u.status === 'active' ? 'Click to Suspend' : 'Click to Reactivate'}
                                            >
                                                <span>{u.status === 'pending' ? '⏳ APPROVE' : u.status === 'suspended' ? '🔴 SUSPENDED' : '✓ ACTIVE'}</span>
                                            </button>
                                        </td>
                                        <td className="px-8 py-5 text-center">
                                            <button 
                                                onClick={() => handleToggleRole(u)}
                                                className={`mx-auto flex items-center space-x-2 px-3 py-1.5 rounded-xl border text-[10px] font-black uppercase tracking-widest transition-all ${
                                                    u.role === 'admin' 
                                                    ? 'bg-primary-500/10 border-primary-500/30 text-primary-400' 
                                                    : 'bg-white/[0.03] border-white/10 text-dark-text-secondary hover:text-white'
                                                }`}
                                            >
                                                {u.role === 'admin' ? <ShieldCheck size={14} /> : <User size={14} />}
                                                <span>{u.role}</span>
                                            </button>
                                        </td>
                                        <td className="px-8 py-5">
                                            <p className="text-sm font-bold text-dark-text-secondary">{new Date(u.created_at).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })}</p>
                                            <p className="text-[10px] text-dark-text-secondary opacity-40 uppercase tracking-tighter">Authentication Active</p>
                                        </td>
                                        <td className="px-8 py-5 text-right">
                                            <div className="flex items-center justify-end space-x-3">
                                                <button 
                                                    onClick={() => handleDeleteUser(u.id, u.username)}
                                                    className="p-3 text-dark-text-secondary hover:text-red-400 hover:bg-red-500/10 rounded-2xl transition-all active:scale-90"
                                                    title="Revoke Access"
                                                >
                                                    <Trash2 size={20} />
                                                </button>
                                                <button className="p-3 text-dark-text-secondary hover:text-white hover:bg-white/5 rounded-2xl transition-all">
                                                    <MoreVertical size={20} />
                                                </button>
                                            </div>
                                        </td>
                                    </tr>
                                ))
                            )}
                        </tbody>
                    </table>
                </div>
            </div>

            {/* User Access Modal */}
            {isModalOpen && (
                <div className="fixed inset-0 z-[100] flex items-center justify-center p-6 bg-black/80 backdrop-blur-md animate-in fade-in duration-300">
                    <div className="w-full max-w-lg glass-effect rounded-[3rem] border border-white/10 overflow-hidden shadow-[0_0_100px_rgba(0,0,0,0.5)] animate-in zoom-in-95 duration-500">
                        {/* Modal Header */}
                        <div className="bg-gradient-to-r from-primary-600/20 to-transparent p-10 flex justify-between items-start">
                            <div>
                                <h3 className="text-3xl font-black text-white tracking-tighter uppercase leading-none mb-3">Authorize Personnel</h3>
                                <p className="text-dark-text-secondary text-sm font-medium">Grant new intelligence clearance access</p>
                            </div>
                            <button 
                                onClick={() => setIsModalOpen(false)}
                                className="p-3 hover:bg-white/5 rounded-2xl text-dark-text-secondary hover:text-white transition-all"
                            >
                                <X size={24} />
                            </button>
                        </div>

                        {/* Modal Form */}
                        <form onSubmit={handleCreateUser} className="p-10 space-y-8">
                            <div className="space-y-3">
                                <label className="text-[10px] font-black text-dark-text-secondary uppercase tracking-[0.2em] ml-2">Username Entity</label>
                                <div className="relative group">
                                    <User className="absolute left-5 top-1/2 -translate-y-1/2 text-dark-text-secondary group-focus-within:text-primary-500" size={20} />
                                    <input 
                                        type="text"
                                        required
                                        className="w-full bg-dark-background/50 border border-white/10 rounded-2xl py-4 pl-14 pr-6 focus:outline-none focus:ring-2 focus:ring-primary-500/50 transition-all font-bold text-white placeholder:text-gray-600"
                                        placeholder="e.g. security.operator_01"
                                        value={newUsername}
                                        onChange={(e) => setNewUsername(e.target.value)}
                                    />
                                </div>
                            </div>

                            <div className="space-y-3">
                                <label className="text-[10px] font-black text-dark-text-secondary uppercase tracking-[0.2em] ml-2">Access Key (Password)</label>
                                <div className="relative group">
                                    <Lock className="absolute left-5 top-1/2 -translate-y-1/2 text-dark-text-secondary group-focus-within:text-primary-500" size={20} />
                                    <input 
                                        type="password"
                                        required
                                        className="w-full bg-dark-background/50 border border-white/10 rounded-2xl py-4 pl-14 pr-6 focus:outline-none focus:ring-2 focus:ring-primary-500/50 transition-all font-bold text-white placeholder:text-gray-600"
                                        placeholder="••••••••••••"
                                        value={newPassword}
                                        onChange={(e) => setNewPassword(e.target.value)}
                                    />
                                </div>
                            </div>

                            <div className="space-y-3">
                                <label className="text-[10px] font-black text-dark-text-secondary uppercase tracking-[0.2em] ml-2">Clearance Level</label>
                                <div className="grid grid-cols-2 gap-4">
                                    <button 
                                        type="button"
                                        onClick={() => setNewRole('member')}
                                        className={`p-5 rounded-3xl border flex flex-col items-center gap-3 transition-all ${
                                            newRole === 'member' 
                                            ? 'bg-primary-500/10 border-primary-500/30 ring-1 ring-primary-500/50' 
                                            : 'bg-white/[0.02] border-white/5 hover:bg-white/[0.05]'
                                        }`}
                                    >
                                        <div className={`p-3 rounded-xl ${newRole === 'member' ? 'bg-primary-500/20 text-primary-400' : 'bg-white/5 text-gray-500'}`}>
                                            <User size={24} />
                                        </div>
                                        <span className={`text-[10px] font-black uppercase tracking-widest ${newRole === 'member' ? 'text-primary-400' : 'text-gray-500'}`}>Standard Member</span>
                                    </button>
                                    <button 
                                        type="button"
                                        onClick={() => setNewRole('admin')}
                                        className={`p-5 rounded-3xl border flex flex-col items-center gap-3 transition-all ${
                                            newRole === 'admin' 
                                            ? 'bg-primary-500/10 border-primary-500/30 ring-1 ring-primary-500/50' 
                                            : 'bg-white/[0.02] border-white/5 hover:bg-white/[0.05]'
                                        }`}
                                    >
                                        <div className={`p-3 rounded-xl ${newRole === 'admin' ? 'bg-primary-500/20 text-primary-400' : 'bg-white/5 text-gray-500'}`}>
                                            <ShieldCheck size={24} />
                                        </div>
                                        <span className={`text-[10px] font-black uppercase tracking-widest ${newRole === 'admin' ? 'text-primary-400' : 'text-gray-500'}`}>System Admin</span>
                                    </button>
                                </div>
                            </div>

                            <button 
                                type="submit"
                                disabled={submitting}
                                className="w-full gradient-bg text-white py-5 rounded-[2rem] font-bold text-lg uppercase tracking-[0.1em] shadow-xl shadow-primary-500/20 active:scale-[0.98] transition-all disabled:opacity-50 flex items-center justify-center gap-3"
                            >
                                {submitting ? <Loader2 className="animate-spin" size={24} /> : (
                                    <>
                                        <Check size={24} />
                                        <span>Confirm Authorization</span>
                                    </>
                                )}
                            </button>
                        </form>
                    </div>
                </div>
            )}
        </div>
    )
}

export default Admin
