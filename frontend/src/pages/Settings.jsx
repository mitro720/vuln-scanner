import { useState } from 'react'
import { Settings as SettingsIcon, User, Bell, Shield, Zap } from 'lucide-react'
import AISettings from '../components/settings/AISettings'

const Settings = () => {
    const [activeTab, setActiveTab] = useState('general')

    const tabs = [
        { id: 'general', label: 'General', icon: SettingsIcon },
        { id: 'ai', label: 'AI Assistant', icon: Zap },
        { id: 'notifications', label: 'Notifications', icon: Bell },
        { id: 'security', label: 'Security', icon: Shield },
    ]

    return (
        <div className="max-w-7xl mx-auto px-4">
            <h1 className="text-4xl font-bold text-gradient mb-8">Settings</h1>

            <div className="grid grid-cols-4 gap-6">
                {/* Sidebar */}
                <div className="col-span-1">
                    <div className="bg-white rounded-xl shadow-lg p-4">
                        <nav className="space-y-2">
                            {tabs.map((tab) => {
                                const Icon = tab.icon
                                return (
                                    <button
                                        key={tab.id}
                                        onClick={() => setActiveTab(tab.id)}
                                        className={`w-full flex items-center space-x-3 px-4 py-3 rounded-lg transition-all ${activeTab === tab.id
                                                ? 'gradient-bg text-white shadow-lg'
                                                : 'text-gray-600 hover:bg-gray-100'
                                            }`}
                                    >
                                        <Icon size={18} />
                                        <span className="font-medium">{tab.label}</span>
                                    </button>
                                )
                            })}
                        </nav>
                    </div>
                </div>

                {/* Content */}
                <div className="col-span-3">
                    {activeTab === 'general' && (
                        <div className="bg-white rounded-xl shadow-lg p-8">
                            <h2 className="text-2xl font-bold text-gray-800 mb-6">General Settings</h2>
                            <div className="space-y-4">
                                <div>
                                    <label className="block text-sm font-medium text-gray-700 mb-2">
                                        Default Scan Type
                                    </label>
                                    <select className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent">
                                        <option value="quick">Quick Scan</option>
                                        <option value="full">Full Scan</option>
                                        <option value="custom">Custom</option>
                                    </select>
                                </div>
                                <div>
                                    <label className="block text-sm font-medium text-gray-700 mb-2">
                                        Concurrent Scans Limit
                                    </label>
                                    <input
                                        type="number"
                                        defaultValue={3}
                                        className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent"
                                    />
                                </div>
                            </div>
                        </div>
                    )}

                    {activeTab === 'ai' && <AISettings />}

                    {activeTab === 'notifications' && (
                        <div className="bg-white rounded-xl shadow-lg p-8">
                            <h2 className="text-2xl font-bold text-gray-800 mb-6">Notification Settings</h2>
                            <div className="space-y-4">
                                <label className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
                                    <span className="text-gray-700">Email on scan completion</span>
                                    <input type="checkbox" className="toggle" />
                                </label>
                                <label className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
                                    <span className="text-gray-700">Alert on critical findings</span>
                                    <input type="checkbox" className="toggle" />
                                </label>
                                <label className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
                                    <span className="text-gray-700">Weekly summary report</span>
                                    <input type="checkbox" className="toggle" />
                                </label>
                            </div>
                        </div>
                    )}

                    {activeTab === 'security' && (
                        <div className="bg-white rounded-xl shadow-lg p-8">
                            <h2 className="text-2xl font-bold text-gray-800 mb-6">Security Settings</h2>
                            <div className="space-y-4">
                                <div>
                                    <label className="block text-sm font-medium text-gray-700 mb-2">
                                        API Key
                                    </label>
                                    <input
                                        type="password"
                                        placeholder="••••••••••••••••"
                                        className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent"
                                    />
                                </div>
                                <div>
                                    <label className="block text-sm font-medium text-gray-700 mb-2">
                                        Two-Factor Authentication
                                    </label>
                                    <button className="px-4 py-2 gradient-bg text-white rounded-lg hover:shadow-lg transition-all">
                                        Enable 2FA
                                    </button>
                                </div>
                            </div>
                        </div>
                    )}
                </div>
            </div>
        </div>
    )
}

export default Settings
