import { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import { Shield, Lock, User, ArrowRight, AlertCircle, Loader2 } from 'lucide-react'

const Login = () => {
    const [username, setUsername] = useState('')
    const [password, setPassword] = useState('')
    const [error, setError] = useState('')
    const [loading, setLoading] = useState(false)
    const { login } = useAuth()
    const navigate = useNavigate()

    const handleSubmit = async (e) => {
        e.preventDefault()
        setError('')
        setLoading(true)

        try {
            await login(username, password)
            navigate('/dashboard')
        } catch (err) {
            setError(err.response?.data?.error || 'Login failed. Please check your credentials.')
            console.error('Login error:', err)
        } finally {
            setLoading(false)
        }
    }

    return (
        <div className="min-h-screen w-full flex items-center justify-center bg-[#050505] overflow-hidden relative">
            {/* Animated Background Elements */}
            <div className="absolute top-[-10%] left-[-10%] w-[40%] h-[40%] bg-purple-600/20 rounded-full blur-[120px] animate-pulse"></div>
            <div className="absolute bottom-[-10%] right-[-10%] w-[40%] h-[40%] bg-blue-600/20 rounded-full blur-[120px] animate-pulse" style={{ animationDelay: '2s' }}></div>
            
            <div className="z-10 w-full max-w-md px-6">
                {/* Logo Area */}
                <div className="flex flex-col items-center mb-10 transition-all duration-700 transform hover:scale-105">
                    <div className="w-20 h-20 bg-gradient-to-tr from-purple-600 to-blue-500 rounded-2xl flex items-center justify-center shadow-[0_0_50px_rgba(147,51,234,0.3)] mb-4">
                        <Shield className="text-white w-10 h-10" />
                    </div>
                    <h1 className="text-4xl font-black bg-clip-text text-transparent bg-gradient-to-r from-white to-gray-500 tracking-tighter">
                        SECURE<span className="text-purple-500">SCAN</span>
                    </h1>
                    <p className="text-gray-500 text-sm mt-2 font-medium uppercase tracking-[0.2em]">Vulnerability Command Center</p>
                </div>

                {/* Login Card (Glassmorphism) */}
                <div className="bg-white/[0.03] backdrop-blur-xl border border-white/[0.08] rounded-3xl p-8 shadow-2xl relative overflow-hidden group">
                    {/* Top Accent Line */}
                    <div className="absolute top-0 left-0 w-full h-[2px] bg-gradient-to-r from-transparent via-purple-500 to-transparent opacity-50"></div>
                    
                    <form onSubmit={handleSubmit} className="space-y-6">
                        {error && (
                            <div className="bg-red-500/10 border border-red-500/20 text-red-400 p-4 rounded-xl flex items-center gap-3 animate-in fade-in slide-in-from-top-4 duration-300">
                                <AlertCircle className="w-5 h-5 flex-shrink-0" />
                                <span className="text-sm font-medium">{error}</span>
                            </div>
                        )}

                        <div className="space-y-2">
                            <label className="text-xs font-bold text-gray-400 uppercase tracking-widest ml-1">Username</label>
                            <div className="relative group/input">
                                <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none transition-colors group-focus-within/input:text-purple-500 text-gray-500">
                                    <User className="w-5 h-5" />
                                </div>
                                <input
                                    type="text"
                                    value={username}
                                    onChange={(e) => setUsername(e.target.value)}
                                    className="w-full bg-white/[0.05] border border-white/[0.1] text-white rounded-2xl py-4 pl-12 pr-4 focus:outline-none focus:ring-2 focus:ring-purple-500/50 focus:border-purple-500 transition-all duration-300 placeholder:text-gray-600"
                                    placeholder="Enter your username"
                                    required
                                />
                            </div>
                        </div>

                        <div className="space-y-2">
                            <label className="text-xs font-bold text-gray-400 uppercase tracking-widest ml-1">Password</label>
                            <div className="relative group/input">
                                <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none transition-colors group-focus-within/input:text-blue-500 text-gray-500">
                                    <Lock className="w-5 h-5" />
                                </div>
                                <input
                                    type="password"
                                    value={password}
                                    onChange={(e) => setPassword(e.target.value)}
                                    className="w-full bg-white/[0.05] border border-white/[0.1] text-white rounded-2xl py-4 pl-12 pr-4 focus:outline-none focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500 transition-all duration-300 placeholder:text-gray-600"
                                    placeholder="••••••••"
                                    required
                                />
                            </div>
                        </div>

                        <button
                            type="submit"
                            disabled={loading}
                            className="w-full bg-gradient-to-r from-purple-600 to-blue-600 hover:from-purple-500 hover:to-blue-500 text-white font-bold py-4 rounded-2xl transition-all duration-300 transform active:scale-[0.98] flex items-center justify-center gap-2 group/btn shadow-[0_0_20px_rgba(147,51,234,0.2)] hover:shadow-[0_0_30px_rgba(147,51,234,0.4)] disabled:opacity-70 disabled:cursor-not-allowed"
                        >
                            {loading ? (
                                <Loader2 className="w-5 h-5 animate-spin" />
                            ) : (
                                <>
                                    <span>Access Terminal</span>
                                    <ArrowRight className="w-5 h-5 transition-transform group-hover/btn:translate-x-1" />
                                </>
                            )}
                        </button>
                    </form>

                    <div className="mt-8 flex justify-between items-center px-2">
                        <span className="text-gray-500 text-xs font-medium uppercase tracking-widest">
                            Authorized Personnel Only
                        </span>
                        <Link to="/register" className="text-purple-400 text-xs font-bold uppercase tracking-widest hover:text-purple-300 transition-colors">
                            Request Access
                        </Link>
                    </div>
                </div>

                {/* Footer Info */}
                <p className="mt-8 text-center text-gray-600 text-[10px] uppercase tracking-[0.3em] font-semibold">
                    System Version 2.4.0 • Node Cluster: EU-WEST-1
                </p>
            </div>

            {/* Scanning Laser Effect */}
            <div className="absolute top-0 left-0 w-full h-[2px] bg-gradient-to-r from-transparent via-blue-500 to-transparent opacity-10 animate-scan"></div>
            
            <style dangerouslySetInnerHTML={{ __html: `
                @keyframes scan {
                    0% { transform: translateY(-100vh); }
                    100% { transform: translateY(100vh); }
                }
                .animate-scan {
                    animation: scan 4s linear infinite;
                }
            `}} />
        </div>
    )
}

export default Login
