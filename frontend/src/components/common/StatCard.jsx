const StatCard = ({ title, value, icon: Icon, color = 'primary', subtitle }) => {
    const colorMap = {
        primary: 'text-primary-400 bg-primary-500/10 border-primary-500/20 shadow-primary-500/10',
        red: 'text-rose-500 bg-rose-500/10 border-rose-500/20 shadow-rose-500/10',
        orange: 'text-orange-500 bg-orange-500/10 border-orange-500/20 shadow-orange-500/10',
        amber: 'text-amber-400 bg-amber-400/10 border-amber-400/20 shadow-amber-400/10',
        blue: 'text-sky-400 bg-sky-400/10 border-sky-400/20 shadow-sky-400/10',
        emerald: 'text-emerald-400 bg-emerald-400/10 border-emerald-400/20 shadow-emerald-400/10',
    }

    const colorClass = colorMap[color] || colorMap.primary

    return (
        <div className="group relative bg-slate-900/50 backdrop-blur-md border border-white/5 rounded-2xl p-5 hover:bg-slate-800/50 hover:border-white/10 transition-all duration-300 shadow-inner-glass">
            {/* Hover Glow */}
            <div className={`absolute inset-0 rounded-2xl opacity-0 group-hover:opacity-100 transition-opacity duration-300 pointer-events-none blur-xl -z-10 bg-gradient-to-br from-transparent to-${color}-500/5`} />
            
            <div className="flex items-start justify-between">
                <div className="space-y-3">
                    <p className="text-[10px] font-bold text-slate-500 uppercase tracking-[0.2em]">{title}</p>
                    <div className="flex items-baseline space-x-2">
                        <h3 className="text-3xl font-black text-slate-100 tracking-tight">{value}</h3>
                        {subtitle && <span className="text-xs text-slate-500 font-medium">{subtitle}</span>}
                    </div>
                </div>
                
                {Icon && (
                    <div className={`w-12 h-12 rounded-xl border flex items-center justify-center transition-transform group-hover:scale-110 duration-300 ${colorClass}`}>
                        <Icon size={24} strokeWidth={2.5} />
                    </div>
                )}
            </div>

            {/* Bottom accent bar */}
            <div className={`absolute bottom-0 left-4 right-4 h-[1px] bg-gradient-to-r from-transparent via-${color}-500/20 to-transparent opacity-0 group-hover:opacity-100 transition-opacity`} />
        </div>
    )
}

export default StatCard
