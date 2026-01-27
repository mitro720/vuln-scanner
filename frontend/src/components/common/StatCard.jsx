const StatCard = ({ title, value, trend, icon: Icon, color = 'purple' }) => {
    const colorClasses = {
        purple: 'border-purple-500',
        red: 'border-red-500',
        orange: 'border-orange-500',
        green: 'border-green-500',
        blue: 'border-blue-500',
    }

    return (
        <div className={`bg-white rounded-xl shadow-lg p-6 border-l-4 ${colorClasses[color]} hover:shadow-xl transition-shadow`}>
            <div className="flex items-center justify-between">
                <div>
                    <div className="text-gray-500 text-sm font-medium">{title}</div>
                    <div className="text-3xl font-bold text-gray-800 mt-2">{value}</div>
                    {trend && (
                        <div className={`text-sm mt-2 ${trend.positive ? 'text-green-500' : 'text-red-500'}`}>
                            {trend.positive ? '↑' : '↓'} {trend.text}
                        </div>
                    )}
                </div>
                {Icon && (
                    <div className={`w-12 h-12 rounded-lg bg-${color}-100 flex items-center justify-center`}>
                        <Icon className={`text-${color}-600`} size={24} />
                    </div>
                )}
            </div>
        </div>
    )
}

export default StatCard
